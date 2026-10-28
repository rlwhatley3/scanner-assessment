"""Trains the value classifier on synthetic data and writes it as ONNX for the engine.

    .venv/bin/python train.py

The model reads one row of token ids (see `encoding.py`) and returns three probabilities that sum
to 1, in this order: the value is a credential, a non-secret random string, or a placeholder.
That is the contract a rule's `valueClassifier` setting expects. The ONNX graph is written by
hand from the trained weights, so it uses only a few plain operators that tract runs.
"""

import hashlib
from pathlib import Path

import numpy as np
import onnx
import torch
from onnx import TensorProto, helper, numpy_helper
from torch import nn

from data import CLASSES, generate
from encoding import VOCAB_SIZE, encode_value

INPUT_LEN = 128
EMBED_DIM = 24
CHANNELS = 48
KERNEL = 5
DILATIONS = (1, 2, 4)
SEED = 7
OUTPUT = Path(__file__).resolve().parent.parent / "engine" / "models" / "value-classifier.onnx"


class ValueClassifier(nn.Module):
    """Byte embeddings, three dilated convolutions, a max over positions, and one output."""

    def __init__(self) -> None:
        super().__init__()
        self.embed = nn.Embedding(VOCAB_SIZE, EMBED_DIM)
        channels_in = [EMBED_DIM, CHANNELS, CHANNELS]
        self.convs = nn.ModuleList(
            nn.Conv1d(c, CHANNELS, KERNEL, dilation=d, padding=d * (KERNEL // 2))
            for c, d in zip(channels_in, DILATIONS)
        )
        self.out = nn.Linear(CHANNELS, len(CLASSES))

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        """Logits, one per class; the exported graph adds the softmax."""
        x = self.embed(ids).transpose(1, 2)
        for conv in self.convs:
            x = torch.relu(conv(x))
        return self.out(x.amax(dim=2))


def tensors(samples) -> tuple[torch.Tensor, torch.Tensor]:
    ids = [encode_value(s.text, s.start, s.end, INPUT_LEN) for s in samples]
    labels = [s.label for s in samples]
    return torch.tensor(ids, dtype=torch.int64), torch.tensor(labels, dtype=torch.int64)


def train(model: ValueClassifier, ids: torch.Tensor, labels: torch.Tensor) -> None:
    optimizer = torch.optim.Adam(model.parameters(), lr=3e-3)
    # Label smoothing keeps probabilities off 0 and 1, so a rule's minimum score stays meaningful.
    loss_fn = nn.CrossEntropyLoss(label_smoothing=0.1)
    generator = torch.Generator().manual_seed(SEED)
    for epoch in range(8):
        model.train()
        order = torch.randperm(len(ids), generator=generator)
        total = 0.0
        for batch in order.split(256):
            optimizer.zero_grad()
            loss = loss_fn(model(ids[batch]), labels[batch])
            loss.backward()
            optimizer.step()
            total += loss.item() * len(batch)
        print(f"epoch {epoch + 1}: loss {total / len(ids):.4f}")


def evaluate(model: ValueClassifier, ids: torch.Tensor, labels: torch.Tensor) -> None:
    model.eval()
    with torch.no_grad():
        predicted = model(ids).argmax(dim=1)
    print(f"held-out accuracy {(predicted == labels).float().mean():.3f}")
    for index, name in enumerate(CLASSES):
        rows = labels == index
        counts = [(predicted[rows] == other).sum().item() for other in range(len(CLASSES))]
        print(f"  {name:>11} rated as " + ", ".join(f"{CLASSES[o]} {c}" for o, c in enumerate(counts)))


def export(model: ValueClassifier, path: Path) -> bytes:
    """Writes the model as an ONNX graph: Gather, Transpose, Conv, Relu, ReduceMax, Gemm,
    Softmax, at opset 13."""
    weights = {name: p.detach().numpy() for name, p in model.state_dict().items()}
    initializers = [numpy_helper.from_array(array, name) for name, array in weights.items()]
    nodes = [
        helper.make_node("Gather", ["embed.weight", "ids"], ["embedded"]),
        helper.make_node("Transpose", ["embedded"], ["x0"], perm=[0, 2, 1]),
    ]
    for i, dilation in enumerate(DILATIONS):
        pad = dilation * (KERNEL // 2)
        nodes.append(
            helper.make_node(
                "Conv",
                [f"x{i}", f"convs.{i}.weight", f"convs.{i}.bias"],
                [f"conv{i}"],
                dilations=[dilation],
                pads=[pad, pad],
                kernel_shape=[KERNEL],
            )
        )
        nodes.append(helper.make_node("Relu", [f"conv{i}"], [f"x{i + 1}"]))
    last = f"x{len(DILATIONS)}"
    nodes += [
        helper.make_node("ReduceMax", [last], ["pooled"], axes=[2], keepdims=0),
        helper.make_node("Gemm", ["pooled", "out.weight", "out.bias"], ["logits"], transB=1),
        helper.make_node("Softmax", ["logits"], ["scores"], axis=1),
    ]
    graph = helper.make_graph(
        nodes,
        "value_classifier",
        [helper.make_tensor_value_info("ids", TensorProto.INT64, [1, INPUT_LEN])],
        [helper.make_tensor_value_info("scores", TensorProto.FLOAT, [1, len(CLASSES)])],
        initializers,
    )
    proto = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13)],
        producer_name="scanner-assessment/ml/train.py",
    )
    proto.ir_version = 7
    onnx.checker.check_model(proto)
    data = proto.SerializeToString()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def main() -> None:
    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    train_ids, train_labels = tensors(generate(40_000, seed=SEED))
    test_ids, test_labels = tensors(generate(4_000, seed=SEED + 1))

    model = ValueClassifier()
    train(model, train_ids, train_labels)
    evaluate(model, test_ids, test_labels)

    data = export(model, OUTPUT)
    print(f"wrote {OUTPUT} ({len(data):,} bytes)")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
