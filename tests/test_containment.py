"""Launch command, import path, and storage caps."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import load_worker_config
from containment import (
    DISK_BUDGET,
    MEMORY_LIMIT,
    SUDO_ARGV,
    Tail,
    directory_size,
    launch_path_problems,
    pin_sys_path,
    worker_child_env,
)
from policy import PolicyError
from runner import SudoRunner


WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"


class ContainmentTest(unittest.TestCase):
    def test_sudo_argv_is_exact_and_isolated(self) -> None:
        self.assertEqual(
            SUDO_ARGV,
            [
                "/usr/bin/sudo",
                "-n",
                "-u",
                "root",
                "/Library/ios-worker/worker_cap",
            ],
        )
        SudoRunner({WORKER}, set())

    def test_import_path_drops_the_working_directory(self) -> None:
        pinned = pin_sys_path(["", "/tmp/evil", "/Library/ios-worker", "/usr/lib"], "/Library/ios-worker", "/tmp/evil")
        self.assertEqual(pinned[0], "/Library/ios-worker")
        self.assertNotIn("/tmp/evil", pinned)
        self.assertNotIn("", pinned)
        self.assertIn("/usr/lib", pinned)

    def test_sparse_files_count_allocated_bytes_once(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "work"
        root.mkdir()
        sparse = root / "v8.data"
        fd = os.open(sparse, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.ftruncate(fd, 32 * 1024 * 1024 * 1024)
        finally:
            os.close(fd)
        info = sparse.stat()
        if info.st_blocks * 512 > 1024 * 1024:
            sparse.unlink()
            self.skipTest("this filesystem allocated the sparse file")
        os.link(sparse, root / "v8-link.data")
        outside = Path(tmp.name) / "outside.bin"
        outside.write_bytes(b"canary-not-counted")
        (root / "escape").symlink_to(outside)
        self.assertGreater(info.st_size, DISK_BUDGET)
        self.assertLess(directory_size([root]), 1024 * 1024)

    def test_command_output_keeps_the_tail(self) -> None:
        tail = Tail(8)
        tail.extend(b"abcdefghij")
        tail.extend(b"KL")
        self.assertEqual(bytes(tail), b"efghijKL")

    def test_child_env_does_not_forward_pythonpath(self) -> None:
        env = worker_child_env("/Applications/Xcode.app/Contents/Developer")
        self.assertEqual(env["HOME"], "/Users/iosagent")
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("PYTHONHOME", env)
        self.assertEqual(env["DEVELOPER_DIR"], "/Applications/Xcode.app/Contents/Developer")
        self.assertEqual(env["TMPDIR"], "/Library/ios-worker/data/tmp")

    def test_disk_and_memory_caps_cannot_be_raised(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "worker.json"
        path.write_text(
            json.dumps(
                {
                    "workspace_root": "/Library/ios-worker/data/work",
                    "spool_root": "/Library/ios-worker/data/spool",
                    "artifact_root": "/Library/ios-worker/data/artifacts",
                    "device_allowlist": [WORKER],
                    "disk_budget_bytes": DISK_BUDGET * 4,
                    "memory_limit_bytes": MEMORY_LIMIT * 4,
                    "max_upload_bytes": 1024 * 1024 * 1024,
                }
            )
        )
        loaded = load_worker_config(path)
        self.assertEqual(loaded.disk_budget, DISK_BUDGET)
        self.assertEqual(loaded.memory_limit, MEMORY_LIMIT)
        self.assertEqual(loaded.max_upload_bytes, 64 * 1024 * 1024)

    def test_untrusted_code_directory_is_rejected(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        problems = launch_path_problems(root)
        self.assertTrue(any("not owned by root" in item for item in problems))

    def test_rlimit_refusal_does_not_abort(self) -> None:
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            ["/usr/bin/python3", "-c", "import containment; containment.apply_rlimits(); print('ok')"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ok", completed.stdout)

    def test_runner_refuses_a_different_command(self) -> None:
        with self.assertRaises(PolicyError):
            SudoRunner({WORKER}, set(), argv=["/bin/sh"])


if __name__ == "__main__":
    unittest.main()
