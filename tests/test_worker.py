"""Worker operations reject the personal simulator, shell requests, and an untested sandbox."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import DEVELOPER_DIR, WorkerConfig, load_worker_config
from memory import PRESSURE_WARNING, MemorySample
from policy import PolicyError, simulator_input
from worker_exec import build, ensure_booted, perform, send_simulator_input, shutdown, screenshot

WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"
PERSONAL = "4D015300-4BAE-4E6D-89C9-BC4D454E4216"


class FakeCommands:
    def __init__(self) -> None:
        self.calls = []
        self.state = "Shutdown"
        self.xcodebuild = "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild"
        self.xcrun = "/Applications/Xcode.app/Contents/Developer/usr/bin/xcrun"

    def run(self, argv, timeout):
        self.calls.append(list(argv))
        if len(argv) > 2 and argv[2] == "boot":
            self.state = "Booted"
        if "list" in argv and "-j" in argv:
            body = json.dumps({"devices": {"iOS": [{"udid": WORKER, "state": self.state}]}}).encode()
            return subprocess.CompletedProcess(argv, 0, body, b"")
        if "-list" in argv:
            body = json.dumps({"project": {"schemes": ["HeadlessSmoke"]}}).encode()
            return subprocess.CompletedProcess(argv, 0, body, b"")
        return subprocess.CompletedProcess(argv, 0, b"ok", b"")


def warning():
    return MemorySample(PRESSURE_WARNING, 0, 0)


class WorkerGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.cfg = WorkerConfig(
            workspace_root=root / "work",
            spool_root=root / "spool",
            artifact_root=root / "artifacts",
            developer_dir=DEVELOPER_DIR,
            device_allowlist={WORKER},
            device_denylist=set(),
            sandbox_builds=False,
        )
        self.cfg.workspace_root.mkdir()
        self.commands = FakeCommands()

    def test_accessibility_typing_uses_stdin_and_does_not_return_field_values(self):
        email = "simulator+test@example.test"
        self.commands = Mock()
        self.commands.run.return_value = subprocess.CompletedProcess([], 0, json.dumps({
            "schema": "axe.output.agent-result", "schemaVersion": "2", "didError": False,
            "data": {"action": {"outcome": "completed"}, "capture": {"rows": [email]}},
        }).encode(), email.encode())
        action = {"action": "typeInto", "snapshotId": WORKER, "ref": "e12", "focus": True, "text": email}
        with patch("worker_exec.is_booted", return_value=True), patch("pathlib.Path.is_file", return_value=True), \
                patch("execution_policy.require_protected_file"):
            result = send_simulator_input({"device_id": WORKER, "input_action": action}, self.cfg, self.commands)
        argv, = self.commands.run.call_args.args
        self.assertEqual(argv[1:], ["--output", "json", "type", "--agent", "--stdin", "--snapshot-id", WORKER,
                                   "--ref", "e12", "--focus", "--udid", WORKER])
        self.assertEqual(self.commands.run.call_args.kwargs["input_bytes"], email.encode())
        self.assertEqual(result["simulatorUI"]["action"]["outcome"], "completed")
        self.assertNotIn(email, str(result))

    def test_simulator_actions_reject_unknown_targets_and_options(self):
        for action in (
            {"action": "tapElement", "snapshotId": WORKER, "ref": "--help"},
            {"action": "tapElement", "snapshotId": WORKER, "ref": "e12", "udid": PERSONAL},
            {"action": "snapshot", "offset": 1},
            {"action": "tapMatching", "identifier": "field", "label": "Email"},
            {"action": "waitFor", "condition": "settled", "timeout": 21},
            {"action": "keyCombo", "modifiers": [227, 227], "code": 25},
            {"action": "clipboardCopy", "text": "\x00"},
        ):
            with self.subTest(action=action), self.assertRaises(PolicyError):
                simulator_input(action)
        simulator_input({"action": "clipboardCopy", "text": "Grüße"})
        self.assertEqual(simulator_input({"action": "tapMatching", "label": "--udid"}),
                         ["tap", "--agent", "--label=--udid"])

    def test_wait_observes_keyboard_without_sending_input(self):
        def response(capture):
            return subprocess.CompletedProcess([], 0, json.dumps({
                "schema": "axe.output.agent-result", "schemaVersion": "2", "didError": False,
                "data": {"capture": capture},
            }).encode(), b"")

        self.commands = Mock()
        self.commands.run.side_effect = [response({"screenHash": "first"}),
                                         response({"screenHash": "next", "keyboard": "likelyVisible"})]
        request = {"device_id": WORKER, "input_action": {"action": "waitFor", "condition": "keyboardVisible"}}
        with patch("worker_exec.is_booted", return_value=True), patch("pathlib.Path.is_file", return_value=True), \
                patch("execution_policy.require_protected_file"), patch("worker_exec.time.sleep"):
            result = send_simulator_input(request, self.cfg, self.commands)
        self.assertEqual(result["simulatorUI"]["capture"]["screenHash"], "next")
        self.assertEqual(self.commands.run.call_count, 2)
        self.assertTrue(all(call.args[0][3] == "describe-ui" for call in self.commands.run.call_args_list))

    def test_clipboard_copy_targets_simulator_with_utf8_stdin(self):
        self.commands = Mock()
        self.commands.run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
        request = {"device_id": WORKER, "input_action": {"action": "clipboardCopy", "text": "Grüße"}}
        with patch("worker_exec.is_booted", return_value=True):
            result = send_simulator_input(request, self.cfg, self.commands)
        self.commands.run.assert_called_once_with(
            [self.commands.xcrun, "simctl", "pbcopy", WORKER], timeout=25, input_bytes="Grüße".encode())
        self.assertEqual(result["log"], "")

    def test_shutdown_of_personal_simulator_never_reaches_simctl(self) -> None:
        with self.assertRaises(PolicyError) as caught:
            shutdown({"device_id": PERSONAL}, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "personal_simulator")
        self.assertEqual(self.commands.calls, [])

    def test_shell_operation_is_absent(self) -> None:
        with self.assertRaises(PolicyError) as caught:
            perform({"op": "shell", "command": "id"}, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "unknown_op")
        self.assertEqual(self.commands.calls, [])

    def test_scheme_cannot_carry_a_shell_command(self) -> None:
        revision = self.cfg.workspace_root / "rev0001"
        (revision / "App.xcodeproj").mkdir(parents=True)
        with self.assertRaises(PolicyError):
            build(
                {
                    "revision_id": "rev0001",
                    "device_id": WORKER,
                    "scheme": "HeadlessSmoke;touch /tmp/owned",
                },
                self.cfg,
                self.commands,
            )
        self.assertEqual(self.commands.calls, [])

    def test_build_command_is_xcodebuild_without_sandbox_exec(self) -> None:
        revision = self.cfg.workspace_root / "rev0001"
        (revision / "App.xcodeproj").mkdir(parents=True)
        build(
            {"revision_id": "rev0001", "device_id": WORKER, "scheme": "HeadlessSmoke"},
            self.cfg,
            self.commands,
        )
        flat = [" ".join(argv) for argv in self.commands.calls]
        self.assertTrue(any("build-for-testing" in item and WORKER in item for item in flat))
        build_argv = next(argv for argv in self.commands.calls if "build-for-testing" in argv)
        self.assertEqual(build_argv[build_argv.index("-jobs") + 1], "4")
        self.assertTrue(any("CODE_SIGNING_ALLOWED=NO" in item for item in flat))
        self.assertFalse(any(PERSONAL in item or "sandbox-exec" in item for item in flat))

    def test_sandbox_flag_refuses_to_wrap_xcodebuild(self) -> None:
        self.cfg.sandbox_builds = True
        with self.assertRaises(PolicyError) as caught:
            build({"revision_id": "rev0001", "device_id": WORKER}, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "sandbox_untested")
        self.assertEqual(self.commands.calls, [])

    def test_warning_does_not_boot_until_approved(self) -> None:
        with self.assertRaises(PolicyError) as caught:
            ensure_booted(WORKER, False, self.cfg, self.commands, warning)
        self.assertEqual(caught.exception.code, "approval_required")
        self.assertFalse(any(argv[1:3] == ["simctl", "boot"] for argv in self.commands.calls))

    def test_already_booted_screenshot_path_does_not_boot_again(self) -> None:
        self.commands.state = "Booted"
        ensure_booted(WORKER, False, self.cfg, self.commands, warning)
        self.assertFalse(any(argv[1:3] == ["simctl", "boot"] for argv in self.commands.calls))

    def test_approval_allows_boot_under_warning(self) -> None:
        ensure_booted(WORKER, True, self.cfg, self.commands, warning)
        self.assertTrue(any(argv[1:3] == ["simctl", "boot"] for argv in self.commands.calls))
        self.assertEqual(sum(argv[1:3] == ["simctl", "list"] for argv in self.commands.calls), 1)

    def test_worker_config_rejects_a_token(self) -> None:
        path = Path(self.tmp.name) / "worker.json"
        path.write_text(
            json.dumps(
                {
                    "token": "secret",
                    "workspace_root": "/Users/Shared/ios-worker/work",
                    "spool_root": "/Users/Shared/ios-worker/spool",
                    "artifact_root": "/Users/Shared/ios-worker/artifacts",
                    "device_allowlist": [WORKER],
                }
            )
        )
        with self.assertRaises(PolicyError) as caught:
            load_worker_config(path)
        self.assertEqual(caught.exception.code, "bad_config")


    def test_screenshot_is_readable_by_broker_group_inside_private_directory(self):
        import stat
        self.cfg.artifact_root.mkdir()
        self.commands.state = "Booted"
        original = self.commands.run

        def run(argv, timeout):
            if "screenshot" in argv:
                path = Path(argv[-1])
                path.write_bytes(b"test-image")
                path.chmod(0o600)
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return original(argv, timeout)

        self.commands.run = run
        result = screenshot({"device_id": WORKER, "artifact_id": "shot1"}, self.cfg, self.commands, warning)
        path = Path(result["artifact_path"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
