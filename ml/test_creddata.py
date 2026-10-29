"""Checks that CredData's labels land on the right bytes, using a tiny made-up checkout."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from creddata import is_eval_repo, load_file, load_meta

HEADER = "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,ValueStart,ValueEnd,CryptographyKey,PredefinedPattern,Category\n"


class LoadFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / "data" / "r1" / "src").mkdir(parents=True)
        (self.root / "meta").mkdir()
        # CRLF line endings, a non-ASCII character before the value, and a key over three lines.
        text = "a = 1\r\nnote = \"café\" pw = Hunter22x\r\nhash = abcdef0123456789\r\n-----BEGIN KEY-----\nAAAA\nBBBB\n"
        (self.root / "data/r1/src/f.py").write_bytes(text.encode())
        rows = [
            "1,f,GitHub,r1,data/r1/src/f.py,2,2,T,19,28,,,Password",
            "2,f,GitHub,r1,data/r1/src/f.py,3,3,F,7,23,,,Key",
            "3,f,GitHub,r1,data/r1/src/f.py,1,1,T,,,,,Secret",
            "4,f,GitHub,r1,data/r1/src/f.py,4,6,T,0,4,,,PEM Private Key",
        ]
        (self.root / "meta/r1.csv").write_text(HEADER + "\n".join(rows) + "\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_labels_land_on_the_value_bytes(self):
        path, rows = next(iter(load_meta(self.root).items()))
        doc = load_file(self.root, path, rows)
        text = doc.text.decode()
        labeled = "".join(c for c, label in zip(doc.text.decode("latin-1"), doc.labels) if label)
        # The password, then the key from its start to the end of its second line.
        self.assertEqual(labeled, "Hunter22x" + "-----BEGIN KEY-----\nAAAA")
        self.assertNotIn("\r", text)
        # The F line is a decoy, labeled 0.
        self.assertEqual([kind for *_, kind in doc.decoys], ["F:Key"])
        # A T row with no value position is left out of training; so is the rest of the key.
        first_line = text.index("\n")
        self.assertTrue((doc.mask[:first_line] == 0).all())
        masked = np.frombuffer(doc.text, np.uint8)[doc.mask == 0].tobytes().decode()
        self.assertEqual(masked, "a = 1" + "\nBBBB")

    def test_the_split_is_by_repository_and_stable(self):
        self.assertEqual(is_eval_repo("r1"), is_eval_repo("r1"))
        held_out = [repo for repo in (f"repo{i}" for i in range(1000)) if is_eval_repo(repo)]
        self.assertTrue(150 < len(held_out) < 250)


if __name__ == "__main__":
    unittest.main()
