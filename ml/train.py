"""Trains the value classifier and writes it as ONNX for the engine.

    .venv/bin/python train.py --creddata /path/to/CredData

Training mixes synthetic data with CredData, a public set of labeled credentials from open-source
repos (see `value_creddata.py`), when a local checkout is given; without one it trains on
synthetic data alone. It reports results on held-out synthetic data and on held-out CredData
repos, next to the model it replaces.

The model reads one row of token ids (see `encoding.py`) and returns three probabilities that sum
to 1, in this order: the value is a credential, a non-secret random string, or a placeholder.
That is the contract a rule's `valueClassifier` setting expects. The ONNX graph is written by
hand from the trained weights, so it uses only a few plain operators that tract runs.
"""

import argparse
import hashlib
import os
from collections import Counter
from pathlib import Path

import numpy as np
import onnx
import torch
from onnx import TensorProto, helper, numpy_helper
from torch import nn

import onnx_eval
import value_creddata
from data import CLASSES, CREDENTIAL, generate
from encoding import VOCAB_SIZE, encode_value, line_bounds

INPUT_LEN = 128
EMBED_DIM = 24
CHANNELS = 48
KERNEL = 5
DILATIONS = (1, 2, 4)
SEED = 7
# The most samples of one class a single CredData repo contributes to training.
PER_REPO_LIMIT = 400
# Synthetic training samples. 20,000 was chosen over 10,000 and 40,000 on the CredData validation
# repos, never the test repos.
SYNTHETIC_SAMPLES = 20_000
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
    ids = []
    for s in samples:
        # The engine shows the classifier only the value's own line.
        line_start, line_end = line_bounds(s.text, s.start, s.end)
        line = s.text[line_start:line_end]
        ids.append(encode_value(line, s.start - line_start, s.end - line_start, INPUT_LEN))
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


def probabilities(model: ValueClassifier, ids: torch.Tensor) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        return torch.softmax(model(ids), dim=1).numpy()


def report(name: str, probs: np.ndarray, labels: np.ndarray) -> None:
    """Per-class precision and recall, and how often a credential would get lower confidence: a
    credential score under 50, the setting's usual minimum."""
    predicted = probs.argmax(axis=1)
    print(f"{name}: {len(labels)} values, accuracy {(predicted == labels).mean():.3f}")
    for index, name in enumerate(CLASSES):
        hits = ((predicted == index) & (labels == index)).sum()
        precision = hits / max((predicted == index).sum(), 1)
        recall = hits / max((labels == index).sum(), 1)
        print(f"  {name:>11}  precision {precision:.3f}  recall {recall:.3f}")
    credentials = labels == CREDENTIAL
    lowered = (np.round(probs[credentials, CREDENTIAL] * 100) < 50).mean()
    print(f"  credentials that would get lower confidence: {lowered:.3f}")


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
    parser = argparse.ArgumentParser()
    parser.add_argument("--creddata", default=os.environ.get("CREDDATA_DIR"),
                        help="A local CredData checkout with data/ built; omit for synthetic only")
    args = parser.parse_args()

    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    train_samples = generate(SYNTHETIC_SAMPLES, seed=SEED)
    tests = {"synthetic": tensors(generate(4_000, seed=SEED + 1))}
    if args.creddata:
        by_split = value_creddata.load(Path(args.creddata))
        creddata_train = value_creddata.cap_per_repo(by_split["train"], PER_REPO_LIMIT)
        train_samples += creddata_train
        repos = len({repo for repo, _ in by_split["train"]})
        print(f"CredData: {len(creddata_train)} training values from {repos} repos")
        test_rows = by_split["test"]
        largest = Counter(repo for repo, s in test_rows if s.label == CREDENTIAL).most_common(1)[0][0]
        tests["CredData validation repos"] = tensors([s for _, s in by_split["validation"]])
        tests["CredData test repos"] = tensors([s for _, s in test_rows])
        tests[f"CredData test repos without {largest}"] = tensors(
            [s for repo, s in test_rows if repo != largest]
        )

    if OUTPUT.exists():
        previous = onnx_eval.load(OUTPUT)
        print(f"Previous model ({hashlib.sha256(OUTPUT.read_bytes()).hexdigest()[:12]}):")
        for name, (ids, labels) in tests.items():
            report(f"  {name}", onnx_eval.predict(previous, ids.numpy()), labels.numpy())

    model = ValueClassifier()
    train_ids, train_labels = tensors(train_samples)
    train(model, train_ids, train_labels)
    print("New model:")
    for name, (ids, labels) in tests.items():
        report(f"  {name}", probabilities(model, ids), labels.numpy())

    data = export(model, OUTPUT)
    print(f"wrote {OUTPUT} ({len(data):,} bytes)")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
