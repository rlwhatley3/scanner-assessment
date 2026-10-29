"""CredData rows for the value classifier.

Reads a local checkout of Samsung's CredData (https://github.com/Samsung/CredData), built with its
`download_data.py`. Nothing from it is committed here: each file keeps its source project's
license. Each single-line row that marks its value becomes a sample with the same shape as the
synthetic ones: the value's line, the value's byte range in it, and a class.

- `T` (a credential, including ones in test folders) is a credential.
- `F` (a false positive: a hash, ID, variable, or ordinary value) is a non-secret.
- `X` (a test value, example, or placeholder) is a placeholder.

Repos are split by a hash of their ID with the secret detector's rule, so one repo's lines never
land in both training and test, and both models hold out the same test repos.
"""

import csv
import hashlib
from collections import defaultdict
from pathlib import Path

from data import CREDENTIAL, NON_SECRET, PLACEHOLDER, Sample

LABELS = {"T": CREDENTIAL, "F": NON_SECRET, "X": PLACEHOLDER}


def split_of(repo: str) -> str:
    """Which split a repo belongs to, by the same rule as the secret detector's
    `creddata.split_of`, so both models hold out the same test repos: one in five is `test`, one
    in eight of the rest is `validation` (for choosing settings), and the rest is `train`."""
    digest = int(hashlib.sha256(repo.encode()).hexdigest(), 16)
    if digest % 5 == 0:
        return "test"
    return "validation" if (digest // 5) % 8 == 0 else "train"


def load(root: Path) -> dict[str, list[tuple[str, Sample]]]:
    """Samples by split, each with the repo it came from."""
    lines_cache: dict[Path, list[str]] = {}
    by_split: dict[str, list[tuple[str, Sample]]] = defaultdict(list)
    for meta in sorted((root / "meta").glob("*.csv")):
        repo = meta.stem
        with meta.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                sample = _sample(root, row, lines_cache)
                if sample is not None:
                    by_split[split_of(repo)].append((repo, sample))
    return by_split


def cap_per_repo(rows: list[tuple[str, Sample]], limit: int) -> list[Sample]:
    """At most `limit` samples of each class from each repo, so no single repo dominates."""
    kept: dict[tuple[str, int], int] = defaultdict(int)
    out = []
    for repo, sample in rows:
        key = (repo, sample.label)
        if kept[key] < limit:
            kept[key] += 1
            out.append(sample)
    return out


def _sample(root: Path, row: dict, cache: dict[Path, list[str]]) -> Sample | None:
    label = LABELS.get(row["GroundTruth"])
    if label is None or row["LineStart"] != row["LineEnd"]:
        return None
    try:
        value_start = int(row["ValueStart"])
    except ValueError:
        return None
    if value_start < 0:
        return None
    path = root / row["FilePath"]
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            return None
    lines = cache[path]
    number = int(row["LineStart"])
    if not 1 <= number <= len(lines):
        return None
    line = lines[number - 1].rstrip("\r")
    try:
        value_end = int(row["ValueEnd"])
    except ValueError:
        value_end = len(line)
    if value_end < 0 or value_end > len(line):
        value_end = len(line)
    if value_start >= value_end:
        return None
    # Offsets are in characters; the model reads bytes.
    start = len(line[:value_start].encode())
    end = len(line[:value_end].encode())
    return Sample(line.encode(), start, end, label)
