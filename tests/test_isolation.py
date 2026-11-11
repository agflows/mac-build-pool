"""The host must never silently fall back to native execution."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from guest_guard import require_macos_guest
from isolated_runner import IsolatedRunner, EXECUTOR
from policy import PolicyError
from scheduler import Job

WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"


class IsolationTest(unittest.TestCase):
    def test_missing_adapter_fails_without_starting_any_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = IsolatedRunner({WORKER}, set())
            with patch("isolated_runner.EXECUTOR", Path(temporary) / "missing"), patch("isolated_runner.subprocess.Popen") as start:
                self.assertFalse(runner.installed())
                with self.assertRaises(PolicyError) as caught:
                    runner.run(Job(id="job1", kind="build", revision_id="rev1"))
                self.assertEqual(caught.exception.code, "isolation_required")
                start.assert_not_called()

    def test_writable_adapter_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "executor"
            path.write_text("not executed")
            path.chmod(0o777)
            with patch("isolated_runner.EXECUTOR", path):
                self.assertFalse(IsolatedRunner({WORKER}, set()).installed())

    def test_controller_gets_fixed_argv_without_sudo_or_credentials(self):
        runner = IsolatedRunner({WORKER}, set())
        process = Mock(returncode=0)
        with patch.object(runner, "_require_controller"), patch("isolated_runner.subprocess.Popen", return_value=process) as start, patch("isolated_runner._read_capped", return_value=(b'{"ok": true}', b"")):
            runner.run(Job(id="job1", kind="prepare", revision_id="rev1", recipe="swift-ios", lease_id="lease1"))
        self.assertEqual(start.call_args.args[0], [str(EXECUTOR)])
        self.assertNotIn("shell", start.call_args.kwargs)
        env = start.call_args.kwargs["env"]
        self.assertNotIn("TOKEN", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertEqual(env["USER"], "iosbroker")

    def test_personal_mac_is_refused_even_in_dev_mode(self):
        with patch.dict(os.environ, {"IOS_WORKER_DEV": "1"}), patch("guest_guard.subprocess.check_output", side_effect=["MacBookPro17,1\n", "apfs"]):
            with self.assertRaises(PolicyError) as caught:
                require_macos_guest()
        self.assertEqual(caught.exception.code, "isolation_required")

    def test_known_guest_identity_is_accepted_but_is_not_network_proof(self):
        with patch("guest_guard.subprocess.check_output", side_effect=["VirtualMac2,1\n", "/dev/disk1 on / (apfs, local)"]):
            require_macos_guest()

    def test_guest_shared_mounts_are_refused(self):
        with patch("guest_guard.subprocess.check_output", side_effect=["VirtualMac2,1\n", "share on /Volumes/host (virtiofs)"]):
            with self.assertRaises(PolicyError) as caught:
                require_macos_guest()
        self.assertEqual(caught.exception.code, "host_sharing_forbidden")


if __name__ == "__main__":
    unittest.main()
