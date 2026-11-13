"""The client reads a token file and refuses a world-readable one."""

from __future__ import annotations

import os
import base64
import stat
import sys
import tempfile
import unittest
import io
import json
from unittest.mock import patch
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


    def test_wait_returns_when_operator_approval_is_needed(self):
        raw = json.dumps({"jobId": "job1", "status": "waiting_for_approval"}).encode()
        with patch("cli.call", return_value=(200, raw)), patch("sys.stdout", new=io.StringIO()):
            result = cli.wait_job("http://example.test", "test-token", "job1")
        self.assertEqual(result["status"], "waiting_for_approval")

    def test_release_build_and_preparation_options(self):
        parser = cli.build_parser()
        args = parser.parse_args(["build", "--revision", "rev1", "--lease", "lease1", "--configuration", "Release", "--build-only", "--no-boot"])
        self.assertTrue(args.build_only)
        self.assertTrue(args.no_boot)
        args = parser.parse_args(["prepare", "--revision", "rev1", "--lease", "lease1", "--recipe", "expo-ios"])
        self.assertEqual(args.recipe, "expo-ios")


    def test_bearer_client_refuses_redirects(self):
        self.assertIsNone(cli.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_preview_writes_image_and_reports_frame_id_without_dumping_bytes(self):
        raw = b"\xff\xd8\xfffixture\xff\xd9"
        frame = {"id": "frame", "changed": True, "jpegBase64": base64.b64encode(raw).decode()}
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new=io.StringIO()) as output:
            path = Path(directory) / "preview.jpg"
            self.assertEqual(cli.save_preview({"status": "succeeded", "simulatorPreview": frame}, path), 0)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(json.loads(output.getvalue()), {"frameId": "frame", "changed": True})


if __name__ == "__main__":
    unittest.main()
