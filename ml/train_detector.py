"""Trains the secret detector on synthetic documents and real labeled code, and writes it as ONNX
for the engine.

    .venv/bin/python train_detector.py --creddata /path/to/CredData

The model reads one window of text as token ids (see `encoding.py`, `encode_window`) and returns
one probability per byte: how likely that byte is part of a secret. That is the contract a
`model_detection` rule expects. The ONNX graph is written by hand from the trained weights, so it
uses only a few plain operators that tract runs.
"""

import argparse
import hashlib
from pathlib import Path

import numpy as np
import onnx
import torch
from onnx import TensorProto, helper, numpy_helper
from torch import nn

import creddata
from detector_data import Doc, generate
from encoding import PAD_ID, VOCAB_SIZE, encode_window

INPUT_LEN = 256
STRIDE = INPUT_LEN // 2
EMBED_DIM = 32
CHANNELS = 40
KERNEL = 3
DILATIONS = (1, 2, 4, 8, 16, 32)
SEED = 11
EPOCHS = 12
TRAIN_DOCS = 32_000
TEST_DOCS = 2_000
# A fixed thread count, so training gives the same file each time on the same machine.
THREADS = 4
# Evaluation doesn't change the model, so it can use every core.
EVAL_THREADS = 8
# The engine's own rules: a byte counts at a score of THRESHOLD or more, and shorter runs drop.
THRESHOLD = 50
MIN_RUN = 8
OUTPUT = Path(__file__).resolve().parent.parent / "engine" / "models" / "secret-detector.onnx"


class SecretDetector(nn.Module):
    """Byte embeddings, a stack of dilated residual convolutions that each byte sees about 64
    bytes either side through, a summary of the whole window added back to every byte, and one
    score per byte."""

    def __init__(self) -> None:
        super().__init__()
        self.embed = nn.Embedding(VOCAB_SIZE, EMBED_DIM)
        self.stem = nn.Conv1d(EMBED_DIM, CHANNELS, 1)
        self.blocks = nn.ModuleList(
            nn.Conv1d(CHANNELS, CHANNELS, KERNEL, dilation=d, padding=d * (KERNEL // 2))
            for d in DILATIONS
        )
        self.summary = nn.Conv1d(CHANNELS, CHANNELS, 1)
        self.mix = nn.Conv1d(CHANNELS, CHANNELS, 1)
        self.out = nn.Conv1d(CHANNELS, 1, 1)

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        """Logits, one per byte; the exported graph adds the sigmoid."""
        x = self.stem(self.embed(ids).transpose(1, 2))
        for block in self.blocks:
            x = x + torch.relu(block(x))
        x = torch.relu(self.mix(x) + self.summary(x.amax(dim=2, keepdim=True)))
        return self.out(x).squeeze(1)


def crops(docs: list[Doc], rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """One window from each document, placed the way the engine places them: at the start, on a
    stride boundary, or anywhere, sometimes running off the end into padding. Returns the ids, the
    per-byte labels, and a mask of the bytes that are text rather than padding."""
    ids = np.full((len(docs), INPUT_LEN), PAD_ID, dtype=np.int64)
    labels = np.zeros((len(docs), INPUT_LEN), dtype=np.float32)
    mask = np.zeros((len(docs), INPUT_LEN), dtype=np.float32)
    for row, doc in enumerate(docs):
        n = len(doc.text)
        last = max(n - INPUT_LEN // 4, 0)
        roll = rng.random()
        if roll < 0.2 or last == 0:
            start = 0
        elif roll < 0.5:
            start = STRIDE * int(rng.integers(0, last // STRIDE + 1))
        else:
            start = int(rng.integers(0, last + 1))
        window = doc.text[start : start + INPUT_LEN]
        ids[row] = encode_window(window, INPUT_LEN)
        labels[row, : len(window)] = doc.labels[start : start + len(window)]
        mask[row, : len(window)] = 1.0 if doc.mask is None else doc.mask[start : start + len(window)]
    return ids, labels, mask


def train(model: SecretDetector, docs: list[Doc], epochs: int) -> None:
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-3, weight_decay=1e-4)
    schedule = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=3e-3, total_steps=epochs * ((len(docs) + 127) // 128)
    )
    rng = np.random.default_rng(SEED)
    for epoch in range(epochs):
        model.train()
        order = rng.permutation(len(docs))
        total = 0.0
        for begin in range(0, len(docs), 128):
            batch = [docs[i] for i in order[begin : begin + 128]]
            ids, labels, mask = (torch.from_numpy(a) for a in crops(batch, rng))
            # Label smoothing keeps scores off 0 and 1, so a rule's threshold stays meaningful.
            target = labels * 0.9 + 0.05
            loss = nn.functional.binary_cross_entropy_with_logits(model(ids), target, reduction="none")
            loss = (loss * mask).sum() / mask.sum()
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            schedule.step()
            total += loss.item() * len(batch)
        print(f"epoch {epoch + 1}: loss {total / len(docs):.4f}", flush=True)


def scores(model: SecretDetector, text: bytes) -> np.ndarray:
    """Per-byte 0–100 scores for a whole text, windowed and combined the way the engine does it."""
    out = np.zeros(len(text), dtype=np.int64)
    starts = [0]
    while starts[-1] + INPUT_LEN < len(text):
        starts.append(starts[-1] + STRIDE)
    probs = []
    with torch.no_grad():
        for begin in range(0, len(starts), 1024):
            ids = torch.tensor([encode_window(text[s : s + INPUT_LEN], INPUT_LEN) for s in starts[begin : begin + 1024]])
            probs.extend(torch.sigmoid(model(ids)).numpy())
    for s, row in zip(starts, probs):
        end = min(s + INPUT_LEN, len(text))
        window = np.round(np.clip(row[: end - s], 0, 1) * 100).astype(np.int64)
        out[s:end] = np.maximum(out[s:end], window)
    return out


def runs(flags: np.ndarray) -> list[tuple[int, int]]:
    """The [start, end) ranges where `flags` is set."""
    padded = np.concatenate([[0], flags.astype(np.int8), [0]])
    edges = np.flatnonzero(np.diff(padded))
    return list(zip(edges[::2].tolist(), edges[1::2].tolist()))


def findings(byte_scores: np.ndarray, threshold: int = THRESHOLD) -> list[tuple[int, int]]:
    return [(s, e) for s, e in runs(byte_scores >= threshold) if e - s >= MIN_RUN]


def evaluate(model: SecretDetector, docs: list[Doc], name: str, kind_of=lambda kind: kind) -> None:
    """Span-level precision and recall, using the engine's windows, threshold and minimum run: a
    secret counts as found when a finding overlaps it, and a finding counts as right when it
    overlaps a secret. Also reports recall for each kind of secret and false positives for each
    kind of planted or labeled non-secret; `kind_of` groups kinds for the report."""
    model.eval()
    print(f"{name}: {len(docs):,} documents, {sum(len(d.text) for d in docs) / 1e6:.1f} MB", flush=True)
    all_scores = [scores(model, doc.text) for doc in docs]
    for threshold in (30, 50, 70):
        found = secrets = right = flagged = 0
        missed_by_kind: dict[str, list[int]] = {}
        false_by_kind: dict[str, int] = {}
        for doc, byte_scores in zip(docs, all_scores):
            spans = findings(byte_scores, threshold)
            flagged += len(spans)
            for s, e in spans:
                if any(ks < e and s < ke for ks, ke, _ in doc.secrets):
                    right += 1
                else:
                    kinds = {kind_of(k) for ks, ke, k in doc.decoys if ks < e and s < ke} or {"other text"}
                    for kind in kinds:
                        false_by_kind[kind] = false_by_kind.get(kind, 0) + 1
            for ks, ke, kind in doc.secrets:
                secrets += 1
                hit = any(s < ke and ks < e for s, e in spans)
                found += hit
                tally = missed_by_kind.setdefault(kind_of(kind), [0, 0])
                tally[0] += hit
                tally[1] += 1
        precision = right / max(flagged, 1)
        recall = found / max(secrets, 1)
        print(f"  threshold {threshold}: precision {precision:.3f} ({right}/{flagged}), "
              f"recall {recall:.3f} ({found}/{secrets})")
        if threshold == THRESHOLD:
            print("    recall by kind: " + ", ".join(
                f"{k} {h}/{n}" for k, (h, n) in sorted(missed_by_kind.items(), key=lambda kv: -kv[1][1])))
            print("    false positives by what they overlapped: " + ", ".join(
                f"{k} {n}" for k, n in sorted(false_by_kind.items(), key=lambda kv: -kv[1])))
            decoys = sum(len(doc.decoys) for doc in docs)
            print(f"    non-secrets planted or labeled: {decoys}", flush=True)


def credata_kind(kind: str) -> str:
    """CredData's categories, grouped for the report: `F:` and `X:` lines by their label, and
    credentials by the first part of their category."""
    return kind[:2] + "line" if kind[:2] in ("F:", "X:") else kind.split(":")[0]


def load_onnx_weights(model: SecretDetector, path: Path) -> None:
    """Loads a written model's weights back, to evaluate it; the graph names its weights after
    the PyTorch parameters."""
    weights = {t.name: torch.from_numpy(numpy_helper.to_array(t).copy()) for t in onnx.load(path).graph.initializer}
    model.load_state_dict(weights)


def export(model: SecretDetector, path: Path) -> bytes:
    """Writes the model as an ONNX graph: Gather, Transpose, Conv, Relu, Add, ReduceMax, Sigmoid,
    Flatten, at opset 13."""
    weights = {name: p.detach().numpy() for name, p in model.state_dict().items()}
    initializers = [numpy_helper.from_array(array, name) for name, array in weights.items()]

    def conv(x: str, name: str, out: str, dilation: int = 1, kernel: int = 1) -> onnx.NodeProto:
        pad = dilation * (kernel // 2)
        return helper.make_node(
            "Conv", [x, f"{name}.weight", f"{name}.bias"], [out],
            dilations=[dilation], pads=[pad, pad], kernel_shape=[kernel],
        )

    nodes = [
        helper.make_node("Gather", ["embed.weight", "ids"], ["embedded"]),
        helper.make_node("Transpose", ["embedded"], ["channels"], perm=[0, 2, 1]),
        conv("channels", "stem", "x0"),
    ]
    for i, dilation in enumerate(DILATIONS):
        nodes += [
            conv(f"x{i}", f"blocks.{i}", f"block{i}", dilation, KERNEL),
            helper.make_node("Relu", [f"block{i}"], [f"relu{i}"]),
            helper.make_node("Add", [f"x{i}", f"relu{i}"], [f"x{i + 1}"]),
        ]
    last = f"x{len(DILATIONS)}"
    nodes += [
        helper.make_node("ReduceMax", [last], ["pooled"], axes=[2], keepdims=1),
        conv("pooled", "summary", "summarised"),
        conv(last, "mix", "mixed"),
        helper.make_node("Add", ["mixed", "summarised"], ["combined"]),
        helper.make_node("Relu", ["combined"], ["features"]),
        conv("features", "out", "logits"),
        helper.make_node("Sigmoid", ["logits"], ["probabilities"]),
        helper.make_node("Flatten", ["probabilities"], ["scores"], axis=1),
    ]
    graph = helper.make_graph(
        nodes,
        "secret_detector",
        [helper.make_tensor_value_info("ids", TensorProto.INT64, [1, INPUT_LEN])],
        [helper.make_tensor_value_info("scores", TensorProto.FLOAT, [1, INPUT_LEN])],
        initializers,
    )
    proto = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 13)],
        producer_name="scanner-assessment/ml/train_detector.py",
    )
    proto.ir_version = 7
    onnx.checker.check_model(proto)
    data = proto.SerializeToString()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def check_export(model: SecretDetector, data: bytes, docs: list[Doc]) -> None:
    """Runs the written graph with ONNX's reference runtime and checks it matches PyTorch."""
    from onnx.reference import ReferenceEvaluator

    runtime = ReferenceEvaluator(onnx.load_from_string(data))
    worst = 0.0
    for doc in docs:
        ids = np.array([encode_window(doc.text[:INPUT_LEN], INPUT_LEN)], dtype=np.int64)
        (onnx_out,) = runtime.run(None, {"ids": ids})
        with torch.no_grad():
            torch_out = torch.sigmoid(model(torch.from_numpy(ids))).numpy()
        worst = max(worst, float(np.abs(onnx_out - torch_out).max()))
    print(f"ONNX graph matches PyTorch to within {worst:.2e}")
    assert worst < 1e-4


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=OUTPUT, help="where to write the ONNX file")
    parser.add_argument("--docs", type=int, default=TRAIN_DOCS, help="synthetic training documents")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--creddata", type=Path, help="a local CredData checkout to train and evaluate on")
    parser.add_argument("--evaluate", type=Path, help="evaluate this ONNX model instead of training")
    parser.add_argument("--untrained", action="store_true", help="write the untrained network, to time it")
    args = parser.parse_args()

    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(THREADS)
    model = SecretDetector()
    print(f"{sum(p.numel() for p in model.parameters()):,} parameters")
    if args.untrained:
        data = export(model, args.out)
        print(f"wrote an untrained model to {args.out} ({len(data):,} bytes)")
        return

    test_docs = generate(TEST_DOCS, seed=SEED + 1)
    real_test = creddata.load(args.creddata, "test") if args.creddata else []
    if args.evaluate:
        torch.set_num_threads(EVAL_THREADS)
        load_onnx_weights(model, args.evaluate)
    else:
        train_docs = generate(args.docs, seed=SEED)
        if args.creddata:
            pieces = creddata.training_pieces(creddata.load(args.creddata, "train"), seed=SEED)
            print(f"CredData training pieces: {len(pieces):,}")
            train_docs += pieces
        train(model, train_docs, args.epochs)
    evaluate(model, test_docs, "held-out synthetic documents")
    if real_test:
        torch.set_num_threads(EVAL_THREADS)
        evaluate(model, real_test, "held-out CredData repositories", credata_kind)
        # One repository can hold most of the labels; report the rest on their own too.
        counts: dict[str, int] = {}
        for doc in real_test:
            counts[doc.source] = counts.get(doc.source, 0) + len(doc.secrets)
        largest = max(counts, key=counts.get)
        if counts[largest] > sum(counts.values()) / 2:
            rest = [doc for doc in real_test if doc.source != largest]
            evaluate(model, rest, f"held-out CredData repositories other than {largest}", credata_kind)
    if args.evaluate:
        return

    data = export(model, args.out)
    check_export(model, data, test_docs[:20])
    print(f"wrote {args.out} ({len(data):,} bytes)")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
