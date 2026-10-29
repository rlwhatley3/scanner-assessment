"""Real labeled text for the secret detector, from Samsung's CredData.

CredData (https://github.com/Samsung/CredData) is source code from public repositories in which
the lines a set of scanners flagged were labeled by hand: `T` a credential, `F` not one, `X` a
test value, example or placeholder. Real credentials were replaced with random values of the same
character set and length. Each file keeps its source project's license, so nothing from it is
committed here; point `--creddata` at a local checkout built with its `download_data.py`.

A file becomes a `Doc` the way the generator's documents are, with a label for every byte:

- A `T` row's value is labeled 1. A private key over several lines is labeled from its start to
  the end of its second line, the same rule the generator uses for keys, and the rest of it is
  left out of training. Other values over several lines (two keys and the code between them)
  are left out of training.
- A `T` row with no value position is left out of training entirely, since which bytes are the
  secret is unknown.
- `F` and `X` rows, and all unlabeled text, are labeled 0.

Repositories are split, not files, so no repository is in both training and evaluation.
"""

import csv
import hashlib
import random
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from detector_data import Doc

# Files larger than the engine accepts in one scan are cut down to the text around their labels.
MAX_SCAN_BYTES = 1_000_000
AROUND_LABELS = 8_192
# The most training pieces one repository contributes.
REPO_CAP = 500


@dataclass
class Row:
    line_start: int
    line_end: int
    truth: str
    value_start: int
    value_end: int
    category: str


def split_of(repo_id: str) -> str:
    """Which split a repository belongs to, chosen by a hash of its id: one in five is held out
    as the test set, and one in eight of the rest is a validation set for choosing settings such
    as the threshold. The rest is training data."""
    digest = int(hashlib.sha256(repo_id.encode()).hexdigest(), 16)
    if digest % 5 == 0:
        return "test"
    return "validation" if (digest // 5) % 8 == 0 else "train"


def is_eval_repo(repo_id: str) -> bool:
    """Whether a repository is in the held-out test set."""
    return split_of(repo_id) == "test"


def load_meta(root: Path) -> dict[str, list[Row]]:
    """Every labeled row, grouped by file."""
    rows: dict[str, list[Row]] = {}
    for meta in sorted((root / "meta").glob("*.csv")):
        with open(meta, newline="") as handle:
            for row in csv.DictReader(handle):
                rows.setdefault(row["FilePath"], []).append(Row(
                    int(row["LineStart"]), int(row["LineEnd"]), row["GroundTruth"],
                    int(row["ValueStart"]) if row["ValueStart"] not in ("", "-1") else -1,
                    int(row["ValueEnd"]) if row["ValueEnd"] not in ("", "-1") else -1,
                    row["Category"],
                ))
    return rows


def load_file(root: Path, path: str, rows: list[Row]) -> Doc:
    """One file as a `Doc`. Line endings are normalized to `\\n` first, since that is the text
    CredData's offsets count in. `doc.secrets` holds the `T` values (or lines, when a value has
    no position) and `doc.decoys` the `F` and `X` lines, each tagged with its category."""
    raw = (root / path).read_bytes()
    text = raw.decode("utf-8", "surrogateescape").replace("\r\n", "\n").replace("\r", "\n")
    data = text.encode("utf-8", "surrogateescape")
    ascii_only = len(data) == len(text)
    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)

    def line_end(line: int) -> int:
        """Character index of the end of 1-based `line`, before its line break."""
        return line_starts[line] - 1 if line < len(line_starts) else len(text)

    def to_byte(char_index: int) -> int:
        return char_index if ascii_only else len(text[:char_index].encode("utf-8", "surrogateescape"))

    labels = np.zeros(len(data), np.uint8)
    mask = np.ones(len(data), np.uint8)
    secrets, decoys = [], []
    for row in rows:
        if row.line_start > len(line_starts):
            continue
        first = line_starts[row.line_start - 1]
        last_line = min(row.line_end, len(line_starts))
        lines = (to_byte(first), to_byte(line_end(last_line)))
        if row.truth != "T":
            decoys.append((*lines, f"{row.truth}:{row.category}"))
            continue
        if row.value_start < 0:
            mask[lines[0]:lines[1]] = 0
            secrets.append((*lines, row.category))
            continue
        start = first + row.value_start
        end_line_start = line_starts[last_line - 1]
        end = line_end(last_line) if row.value_end < 0 else end_line_start + row.value_end
        start, end = to_byte(start), to_byte(min(end, line_end(last_line)))
        if end <= start:
            continue
        secrets.append((start, end, row.category))
        if row.line_end > row.line_start and "PEM" not in row.category and "Private Key" not in row.category:
            # A value over several lines that isn't a key block, such as two keys and the code
            # between them, has no clean span to learn from.
            mask[start:end] = 0
        elif row.line_end > row.line_start:
            head_end = to_byte(line_end(min(row.line_start + 1, last_line)))
            labels[start:min(head_end, end)] = 1
            mask[min(head_end, end):end] = 0
        else:
            labels[start:end] = 1
    secrets.sort()
    decoys.sort()
    return Doc(data, labels, secrets, decoys, mask, Path(path).parts[1])


def cut(doc: Doc, start: int, end: int) -> Doc:
    """The part of a document between two byte offsets, with the spans inside it."""
    def inside(spans):
        return [(max(s, start) - start, min(e, end) - start, k) for s, e, k in spans if s < end and start < e]

    mask = doc.mask[start:end] if doc.mask is not None else None
    return Doc(doc.text[start:end], doc.labels[start:end], inside(doc.secrets), inside(doc.decoys), mask, doc.source)


def scan_sized(doc: Doc) -> list[Doc]:
    """A file as the engine would scan it: whole if it fits in one scan, otherwise the text
    around its labels, merged where it overlaps."""
    if len(doc.text) <= MAX_SCAN_BYTES:
        return [doc]
    regions: list[list[int]] = []
    for s, e, _ in sorted(doc.secrets + doc.decoys):
        s, e = max(s - AROUND_LABELS, 0), min(e + AROUND_LABELS, len(doc.text))
        if regions and s <= regions[-1][1]:
            regions[-1][1] = max(regions[-1][1], e)
        else:
            regions.append([s, e])
    return [cut(doc, s, e) for s, e in regions]


def load(root: Path, split: str) -> list[Doc]:
    """The files of the `train`, `validation` or `test` repositories, cut to what a scan would
    read."""
    docs = []
    for path, rows in sorted(load_meta(root).items()):
        if split_of(Path(path).parts[1]) == split:
            docs.extend(scan_sized(load_file(root, path, rows)))
    return docs


def training_pieces(docs: list[Doc], seed: int, size: int = 768) -> list[Doc]:
    """Short pieces of the training files for `train_detector.crops` to take windows from, each
    around a labeled line at a random offset:

    - one around every `T`, `F` and `X` line, and two more around each password of 8 bytes or
      more (passwords are the hardest kind; shorter ones are below the engine's minimum finding);
    - one random piece for every four files, so the model also sees unlabeled code;
    - at most `REPO_CAP` pieces per repository, keeping credentials first, then `X` and `F`
      lines, then random pieces, so no repository dominates.
    """
    r = random.Random(seed)
    by_repo: dict[str, dict[str, list[Doc]]] = {}
    for doc in docs:
        groups = by_repo.setdefault(doc.source, {"T": [], "X": [], "F": [], "random": []})
        spans = [(s, e, k, "T") for s, e, k in doc.secrets] + [(s, e, k, k[0]) for s, e, k in doc.decoys]
        for s, e, kind, label in spans:
            copies = 3 if label == "T" and "Password" in kind and e - s >= 8 else 1
            for _ in range(copies):
                room = max(size - (e - s), 0)
                start = max(min(s - r.randint(0, room), len(doc.text) - size), 0)
                groups[label].append(cut(doc, start, min(start + max(size, e - s), len(doc.text))))
        if r.random() < 0.25 and len(doc.text) > 0:
            start = r.randint(0, max(len(doc.text) - size, 0))
            groups["random"].append(cut(doc, start, start + size))
    pieces = []
    for repo in sorted(by_repo):
        groups = by_repo[repo]
        for group in groups.values():
            r.shuffle(group)
        half = REPO_CAP // 2
        ordered = groups["T"][:half] + groups["X"] + groups["F"] + groups["T"][half:] + groups["random"]
        pieces.extend(ordered[:REPO_CAP])
    return pieces


def license_tally(root: Path) -> dict[str, int]:
    """How many repositories carry each license, read from the license files at each
    repository's root."""
    kinds = [
        ("Apache-2.0", ["apache license", "version 2.0"]), ("MIT", ["permission is hereby granted, free of charge"]),
        ("BSD-3-Clause", ["neither the name"]), ("BSD-2-Clause", ["redistributions in binary form"]),
        ("LGPL", ["lesser general public license"]), ("AGPL", ["affero general public license"]),
        ("GPL", ["gnu general public license"]), ("MPL-2.0", ["mozilla public license"]),
        ("ISC", ["permission to use, copy, modify, and/or distribute"]), ("Unlicense", ["unlicense", "public domain"]),
        ("EPL", ["eclipse public license"]), ("CC0", ["cc0"]),
    ]
    tally: dict[str, int] = {}
    for repo in sorted(p for p in (root / "data").iterdir() if p.is_dir()):
        text = " ".join(f.read_text(errors="replace").lower() for f in repo.iterdir()
                        if f.is_file() and any(w in f.name.lower() for w in ("license", "copying")))
        text = " ".join(text.split())
        found = next((name for name, needles in kinds if all(n in text for n in needles)), None)
        name = found or ("no license file" if not text else "other")
        tally[name] = tally.get(name, 0) + 1
    return dict(sorted(tally.items(), key=lambda kv: -kv[1]))
