"""The client reads a token file and refuses a world-readable one."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cli


class CliTest(unittest.TestCase):
    def test_token_file_must_be_owner_only(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "token"
        path.write_text("a" * 32)
        path.chmod(0o644)
        with self.assertRaises(SystemExit):
            cli.read_secret(path)
        path.chmod(0o600)
        self.assertEqual(cli.read_secret(path), "a" * 32)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_token_file_must_not_be_a_symlink(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        real = Path(tmp.name) / "real"
        real.write_text("b" * 32)
        real.chmod(0o600)
        link = Path(tmp.name) / "link"
        link.symlink_to(real)
        with self.assertRaises(SystemExit):
            cli.read_secret(link)
        os.close(os.open(real, os.O_RDONLY | os.O_NOFOLLOW))


if __name__ == "__main__":
    unittest.main()
