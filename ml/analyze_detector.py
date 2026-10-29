"""Looks at what a trained detector gets wrong on held-out CredData repositories.

    .venv/bin/python analyze_detector.py MODEL.onnx --creddata /path/to/CredData [--split test|validation]

Prints the model's false positives sorted into rough groups, its missed credentials by category,
and precision and recall at every threshold from 30 to 90. Examples are shown by shape only:
letters become `a` or `A`, digits `9`, so no value is printed.
"""

import argparse
import re
from pathlib import Path

import numpy as np
import torch

import creddata
from train_detector import EVAL_THREADS, SecretDetector, findings, load_onnx_weights, scores

UUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX = re.compile(rb"^(0x|sha\d*[:-]|md5[:-])?[0-9a-fA-F]{16,}$")
BASE64 = re.compile(rb"^[A-Za-z0-9+/_-]{16,}={0,2}$")
IDENTIFIER = re.compile(rb"^[A-Za-z_$][A-Za-z0-9_$.\-]*$")
PLACEHOLDER = re.compile(rb"example|sample|dummy|test|fake|xxxx|placeholder|your|changeme|foo|bar|lorem|secret|password|token", re.I)
HASH_CONTEXT = re.compile(rb"sha|hash|digest|checksum|integrity|md5|crc|fingerprint|etag|commit", re.I)


def shape(value: bytes, limit: int = 40) -> str:
    """A value with its letters and digits masked, so only its shape shows."""
    out = []
    for byte in value[:limit]:
        char = chr(byte)
        out.append("A" if char.isupper() else "a" if char.isalpha() else "9" if char.isdigit() else char if 32 <= byte < 127 else "?")
    return "".join(out) + ("…" if len(value) > limit else "") + f" ({len(value)})"


def token_around(text: bytes, start: int, end: int) -> bytes:
    """The flagged span widened to the whitespace- or quote-delimited token it sits in."""
    stops = b" \t\n\"'`<>(),;[]{}="
    while start > 0 and text[start - 1] not in stops:
        start -= 1
    while end < len(text) and text[end] not in stops:
        end += 1
    return text[start:end]


def group(text: bytes, start: int, end: int, labeled: str | None) -> str:
    token = token_around(text, start, end)
    context = text[max(start - 60, 0):start]
    if labeled == "X":
        return "example or placeholder value"
    if UUID.search(token) or re.search(rb"(^|[_.\-])id\W*$", context.split(b"\n")[-1], re.I):
        return "UUID or ID"
    if HEX.match(token) or (BASE64.match(token) and HASH_CONTEXT.search(context)):
        return "hash or digest"
    if b"://" in token or token.count(b"/") >= 2 or token.startswith((b"./", b"/", b"~/")):
        return "URL or path"
    if PLACEHOLDER.search(token):
        return "example or placeholder value"
    if IDENTIFIER.match(token) and sum(c in b"0123456789" for c in token) <= len(token) // 4:
        return "variable or identifier"
    if BASE64.match(token):
        return "base64 or encoded data"
    return "other"


def repo_counts(docs, all_scores, threshold: int) -> dict[str, np.ndarray]:
    """Per repository: right findings, all findings, credentials found, all credentials."""
    counts: dict[str, np.ndarray] = {}
    for doc, byte_scores in zip(docs, all_scores):
        spans = findings(byte_scores, threshold)
        row = counts.setdefault(doc.source, np.zeros(4))
        row[0] += sum(any(ks < e and s < ke for ks, ke, _ in doc.secrets) for s, e in spans)
        row[1] += len(spans)
        row[2] += sum(any(s < ke and ks < e for s, e in spans) for ks, ke, _ in doc.secrets)
        row[3] += len(doc.secrets)
    return counts


def bootstrap(docs, models: dict[str, list[np.ndarray]], threshold: int, rounds: int = 2000) -> None:
    """95% intervals for precision, recall and F1, resampling whole repositories with
    replacement, since errors cluster by repository. The same resamples are used for every
    model, so the interval for the difference is paired."""
    counts = {name: repo_counts(docs, s, threshold) for name, s in models.items()}
    repos = sorted(next(iter(counts.values())))
    tables = {name: np.array([c[r] for r in repos]) for name, c in counts.items()}
    rng = np.random.default_rng(0)
    picks = rng.integers(0, len(repos), size=(rounds, len(repos)))

    def metrics(table: np.ndarray) -> np.ndarray:
        sums = table[picks].sum(axis=1)
        precision = sums[:, 0] / np.maximum(sums[:, 1], 1)
        recall = sums[:, 2] / np.maximum(sums[:, 3], 1)
        f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-9)
        return np.stack([precision, recall, f1], axis=1)

    results = {name: metrics(t) for name, t in tables.items()}
    print(f"\nbootstrap over {len(repos)} repositories, {rounds} rounds, threshold {threshold} (95% intervals)")
    for name, table in tables.items():
        whole = table.sum(axis=0)
        point = [whole[0] / max(whole[1], 1), whole[2] / max(whole[3], 1)]
        point.append(2 * point[0] * point[1] / max(point[0] + point[1], 1e-9))
        low, high = np.percentile(results[name], [2.5, 97.5], axis=0)
        print(f"  {name}: " + ", ".join(f"{m} {p:.3f} [{lo:.3f}, {hi:.3f}]" for m, p, lo, hi in zip(("precision", "recall", "F1"), point, low, high)))
    if len(results) == 2:
        a, b = results.values()
        difference = a - b
        low, high = np.percentile(difference, [2.5, 97.5], axis=0)
        better = (difference > 0).mean(axis=0)
        print("  model minus baseline: " + ", ".join(
            f"{m} [{lo:+.3f}, {hi:+.3f}] (better in {p:.0%} of rounds)" for m, lo, hi, p in zip(("precision", "recall", "F1"), low, high, better)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("model", type=Path)
    parser.add_argument("--creddata", type=Path, required=True)
    parser.add_argument("--split", default="test", choices=["test", "validation"])
    parser.add_argument("--threshold", type=int, default=50)
    parser.add_argument("--keep-largest", action="store_true", help="keep the repository that holds most labels")
    parser.add_argument("--baseline", type=Path, help="another model to compare with, by bootstrapping repositories")
    args = parser.parse_args()

    torch.set_num_threads(EVAL_THREADS)
    model = SecretDetector()
    load_onnx_weights(model, args.model)
    model.eval()
    docs = creddata.load(args.creddata, args.split)
    if not args.keep_largest:
        counts: dict[str, int] = {}
        for doc in docs:
            counts[doc.source] = counts.get(doc.source, 0) + len(doc.secrets)
        largest = max(counts, key=counts.get)
        if counts[largest] > sum(counts.values()) / 2:
            docs = [doc for doc in docs if doc.source != largest]
            print(f"leaving out {largest}, which holds {counts[largest]} of {sum(counts.values())} credentials")
    print(f"{args.split}: {len({d.source for d in docs})} repositories, {len(docs)} documents")
    def cached_scores(path: Path) -> list[np.ndarray]:
        cache = path.with_suffix(f".{args.split}{'.all' if args.keep_largest else ''}.scores.npz")
        if cache.exists():
            return list(np.load(cache).values())
        load_onnx_weights(model, path)
        result = [scores(model, doc.text) for doc in docs]
        np.savez_compressed(cache, *result)
        return result

    all_scores = cached_scores(args.model)
    if args.baseline:
        bootstrap(docs, {"model": all_scores, "baseline": cached_scores(args.baseline)}, args.threshold)

    print("\nthreshold  precision  recall  findings")
    for threshold in range(30, 95, 5):
        right = flagged = found = total = 0
        for doc, byte_scores in zip(docs, all_scores):
            spans = findings(byte_scores, threshold)
            flagged += len(spans)
            right += sum(any(ks < e and s < ke for ks, ke, _ in doc.secrets) for s, e in spans)
            total += len(doc.secrets)
            found += sum(any(s < ke and ks < e for s, e in spans) for ks, ke, _ in doc.secrets)
        print(f"{threshold:9}  {right / max(flagged, 1):9.3f}  {found / max(total, 1):6.3f}  {flagged:8}")

    groups: dict[str, list[str]] = {}
    labeled_negative = {"F": 0, "X": 0, "unlabeled": 0}
    missed: dict[str, list[str]] = {}
    missed_lengths: dict[str, list[int]] = {}
    for doc, byte_scores in zip(docs, all_scores):
        spans = findings(byte_scores, args.threshold)
        for s, e in spans:
            if any(ks < e and s < ke for ks, ke, _ in doc.secrets):
                continue
            labels = [k[0] for ks, ke, k in doc.decoys if ks < e and s < ke]
            labeled = "X" if "X" in labels else "F" if "F" in labels else None
            labeled_negative[labeled or "unlabeled"] += 1
            name = group(doc.text, s, e, labeled)
            groups.setdefault(name, []).append(shape(token_around(doc.text, s, e)))
        for ks, ke, kind in doc.secrets:
            if not any(s < ke and ks < e for s, e in spans):
                line_start = doc.text.rfind(b"\n", 0, ks) + 1
                context = doc.text[max(line_start, ks - 30):ks].decode(errors="replace").strip()
                missed_lengths.setdefault(kind.split(":")[0], []).append(ke - ks)
                missed.setdefault(kind.split(":")[0], []).append(f"{context[-30:]!r} → {shape(doc.text[ks:ke])}")

    total_false = sum(len(v) for v in groups.values())
    print(f"\nfalse positives at threshold {args.threshold}: {total_false} "
          f"(on F lines {labeled_negative['F']}, on X lines {labeled_negative['X']}, unlabeled {labeled_negative['unlabeled']})")
    rng = np.random.default_rng(0)
    for name, examples in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        picks = rng.choice(len(examples), size=min(4, len(examples)), replace=False)
        print(f"  {name}: {len(examples)}")
        for i in picks:
            print(f"      {examples[i]}")
    total_missed = sum(len(v) for v in missed.values())
    print(f"\nmissed credentials at threshold {args.threshold}: {total_missed}")
    buckets = {"under 8 bytes (shorter than the engine's minimum finding)": 0, "8-11 bytes": 0, "12 bytes or more": 0}
    for lengths in missed_lengths.values():
        for n in lengths:
            buckets["under 8 bytes (shorter than the engine's minimum finding)" if n < 8 else "8-11 bytes" if n < 12 else "12 bytes or more"] += 1
    print("  by length: " + ", ".join(f"{k} {v}" for k, v in buckets.items()))
    pw = missed_lengths.get("Password", [])
    print(f"  passwords: {sum(n < 8 for n in pw)} of {len(pw)} missed are under 8 bytes")
    all_pw = [ke - ks for doc in docs for ks, ke, k in doc.secrets if k.split(":")[0] == "Password"]
    print(f"  all held-out passwords: {sum(n < 8 for n in all_pw)} of {len(all_pw)} are under 8 bytes")
    long_false = sum(1 for v in groups.values() for x in v if int(x.rsplit("(", 1)[1][:-1]) > 200)
    print(f"  false positives inside tokens over 200 bytes (embedded blobs): {long_false}")
    for name, examples in sorted(missed.items(), key=lambda kv: -len(kv[1])):
        picks = rng.choice(len(examples), size=min(4 if name == "Password" else 2, len(examples)), replace=False)
        print(f"  {name}: {len(examples)}")
        for i in picks:
            print(f"      {examples[i]}")


if __name__ == "__main__":
    main()
