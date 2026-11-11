"""Source archives cannot escape the revision directory."""

from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy import PolicyError
from tarsafe import extract_source


class TarSafeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "src.tar"
        self.destination = self.root / "out"

    def _tar(self, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        with tarfile.open(self.archive, "w") as handle:
            for info, payload in members:
                handle.addfile(info, io.BytesIO(payload) if payload is not None else None)

    def test_regular_file_extracts(self) -> None:
        payload = b"import SwiftUI\n"
        info = tarfile.TarInfo("App/main.swift")
        info.size = len(payload)
        self._tar([(info, payload)])
        extract_source(self.archive, self.destination, 1024)
        self.assertEqual((self.destination / "App/main.swift").read_bytes(), payload)

    def test_parent_path_is_rejected(self) -> None:
        info = tarfile.TarInfo("../escaped.txt")
        info.size = 1
        self._tar([(info, b"x")])
        with self.assertRaises(PolicyError):
            extract_source(self.archive, self.destination, 1024)
        self.assertFalse((self.root / "escaped.txt").exists())

    def test_absolute_path_is_rejected(self) -> None:
        outside = self.root / "outside.txt"
        info = tarfile.TarInfo(str(outside))
        info.size = 1
        self._tar([(info, b"x")])
        with self.assertRaises(PolicyError):
            extract_source(self.archive, self.destination, 1024)
        self.assertFalse(outside.exists())

    def test_symlink_is_rejected(self) -> None:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/Users/leolurch"
        self._tar([(info, None)])
        with self.assertRaises(PolicyError):
            extract_source(self.archive, self.destination, 1024)
        self.assertFalse((self.destination / "link").exists())

    def test_hardlink_is_rejected(self) -> None:
        info = tarfile.TarInfo("hard")
        info.type = tarfile.LNKTYPE
        info.linkname = "App/main.swift"
        self._tar([(info, None)])
        with self.assertRaises(PolicyError):
            extract_source(self.archive, self.destination, 1024)
        self.assertFalse((self.destination / "hard").exists())


if __name__ == "__main__":
    unittest.main()
