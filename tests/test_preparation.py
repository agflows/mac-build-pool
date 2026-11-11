"""Recipe tests use fake commands: no npm installation, Xcode or Mac access."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import DEVELOPER_DIR, WorkerConfig, load_worker_config
from policy import PolicyError, require_public_env
from tarsafe import extract_source
from worker_exec import Commands, CommandFailed, _find_project, _find_app, build, prepare
from workspace import toolchain_paths, workspace_env, copy_flutter_sdk

WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"


class FakeCommands:
    xcodebuild = DEVELOPER_DIR + "/usr/bin/xcodebuild"
    xcrun = "/usr/bin/xcrun"

    def __init__(self, revision):
        self.revision = revision
        self.calls = []
        self.fail_step = None
        self.env = {}
        self.cwd = Path("/tmp")

    def run(self, argv, timeout):
        self.calls.append((list(argv), timeout, dict(self.env), self.cwd))
        if self.fail_step and self.fail_step in " ".join(argv):
            return subprocess.CompletedProcess(argv, 17, b"dependency output", b"dependency error")
        if "install" in argv:
            (self.revision / "ios/CoupleJoy.xcworkspace").mkdir(parents=True, exist_ok=True)
        if "--config-only" in argv:
            (self.revision / "ios/Runner.xcworkspace").mkdir(parents=True, exist_ok=True)
        if "-list" in argv:
            section = "workspace" if "-workspace" in argv else "project"
            return subprocess.CompletedProcess(argv, 0, json.dumps({section: {"schemes": ["CoupleJoy"]}}).encode(), b"")
        if "simctl" in argv and "list" in argv:
            return subprocess.CompletedProcess(argv, 0, b'{"devices": {}}', b"")
        return subprocess.CompletedProcess(argv, 0, b"ok", b"")


class PreparationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cfg = WorkerConfig(self.root / "work", self.root / "spool", self.root / "artifacts",
                                DEVELOPER_DIR, {WORKER}, set(), allow_dependency_install=True)
        self.revision = self.cfg.workspace_root / "rev1"
        self.revision.mkdir(parents=True)
        (self.revision / "package.json").write_text(json.dumps({"dependencies": {"expo": "~58.0.23"}}))
        (self.revision / "package-lock.json").write_text('{}')
        self.tools = {"node": Path("/approved/node/bin/node"), "npm_cli": Path("/approved/npm/npm-cli.js"),
                      "pod": Path("/approved/ruby/bin/pod"), "ruby_bin": Path("/approved/ruby/bin")}
        self.commands = FakeCommands(self.revision)
        self.request = {"recipe": "expo-ios", "revision_id": "rev1", "public_env": {"EXPO_PUBLIC_API_URL": "https://example.test"}}

    def prepare(self):
        with patch("worker_exec.toolchain_paths", return_value=self.tools):
            return prepare(self.request, self.cfg, self.commands)

    def test_recipe_runs_locked_install_prebuild_and_pods_in_order(self):
        result = self.prepare()
        calls = self.commands.calls
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][0][0:3], [str(self.tools["node"]), str(self.tools["npm_cli"]), "ci"])
        self.assertIn("--no-install", calls[1][0])
        self.assertIn("--clean", calls[1][0])
        self.assertEqual(calls[2][0], [str(self.tools["pod"]), "install", "--project-directory=" + str(self.revision / "ios")])
        for argv, timeout, env, cwd in calls:
            self.assertEqual(cwd, self.revision)
            self.assertNotIn("sudo", " ".join(argv))
            self.assertGreater(timeout, 0)
            self.assertLess(timeout, 2700)
            self.assertTrue(env["HOME"].startswith(str(self.revision)))
            self.assertTrue(env["TMPDIR"].startswith(str(self.revision)))
            self.assertEqual(env["EXPO_NO_DOTENV"], "1")
            self.assertEqual(env["EXPO_PUBLIC_API_URL"], "https://example.test")
            self.assertNotIn("GITHUB_TOKEN", env)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(json.loads((self.revision / ".worker/prepared.json").read_text())["recipe"], "expo-ios")

    def test_dependency_installs_require_owner_opt_in(self):
        self.cfg.allow_dependency_install = False
        with self.assertRaises(PolicyError) as caught:
            prepare(self.request, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "preparation_disabled")
        self.assertFalse(self.commands.calls)

    def test_sandbox_flag_fails_closed(self):
        self.cfg.sandbox_builds = True
        with self.assertRaises(PolicyError) as caught:
            prepare(self.request, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "sandbox_untested")
        self.assertFalse(self.commands.calls)

    def test_unknown_recipe_does_not_execute(self):
        self.request["recipe"] = "shell"
        with self.assertRaises(PolicyError):
            prepare(self.request, self.cfg, self.commands)
        self.assertFalse(self.commands.calls)

    def test_lockfile_required(self):
        (self.revision / "package-lock.json").unlink()
        with self.assertRaises(PolicyError):
            self.prepare()
        self.assertFalse(self.commands.calls)

    def test_failure_keeps_diagnostics_and_invalidates_receipt(self):
        self.prepare()
        self.commands.fail_step = "npm-cli.js"
        with self.assertRaises(CommandFailed) as caught:
            self.prepare()
        self.assertEqual(caught.exception.exit_code, 17)
        self.assertIn("npm ci", str(caught.exception))
        self.assertIn("dependency error", str(caught.exception))
        self.assertFalse((self.revision / ".worker/prepared.json").exists())

    def test_writable_toolchain_is_rejected(self):
        self.cfg.toolchain = {k: str(self.root / k) for k in self.tools}
        for key, path in self.cfg.toolchain.items():
            if key == "ruby_bin":
                Path(path).mkdir()
            else:
                Path(path).write_text("tool")
        with self.assertRaises(PolicyError) as caught:
            toolchain_paths(self.cfg)
        self.assertEqual(caught.exception.code, "toolchain_writable")

    def test_toolchain_with_no_worker_write_access_is_accepted(self):
        self.cfg.toolchain = {k: str(self.root / k) for k in self.tools}
        for key, path in self.cfg.toolchain.items():
            Path(path).mkdir() if key == "ruby_bin" else Path(path).write_text("tool")
        with patch("workspace.os.access", side_effect=lambda p, mode: mode != os.W_OK):
            paths = toolchain_paths(self.cfg)
        self.assertEqual(set(paths), set(self.tools))

    def test_runtime_directory_symlink_is_rejected(self):
        (self.revision / ".worker").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PolicyError):
            workspace_env(self.revision, self.cfg, tools=self.tools)

    def test_only_public_variables_are_accepted(self):
        for env in ({"HOME": "evil"}, {"NODE_OPTIONS": "--require evil"}, {"EXPO_PUBLIC_A": "\x00"}, {"EXPO_PUBLIC_A": 1}, {"TOKEN": "secret"}):
            with self.assertRaises(PolicyError):
                require_public_env(env)
        self.assertEqual(require_public_env({"EXPO_PUBLIC_A": "value"}), {"EXPO_PUBLIC_A": "value"})

    def test_source_cannot_upload_preparation_state(self):
        archive = self.root / "source.tar"
        data = b'{}'
        with tarfile.open(archive, "w") as handle:
            member = tarfile.TarInfo(".worker/prepared.json")
            member.size = len(data)
            handle.addfile(member, io.BytesIO(data))
        with self.assertRaises(PolicyError):
            extract_source(archive, self.root / "extracted", 1024)

    def test_workspace_preferred_and_release_build_does_not_require_test_target(self):
        self.prepare()
        (self.revision / "ios/CoupleJoy.xcodeproj").mkdir()
        with patch("workspace.toolchain_paths", return_value=self.tools):
            result = build({"revision_id": "rev1", "scheme": "CoupleJoy", "device_id": WORKER,
                            "configuration": "Release", "for_testing": False}, self.cfg, self.commands)
        argv, _, env, cwd = self.commands.calls[-1]
        self.assertEqual(argv[1], "build")
        self.assertIn("-workspace", argv)
        self.assertIn("Release", argv)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", argv)
        self.assertEqual(env["HOME"], "/Users/iosagent")
        self.assertNotIn("CFFIXED_USER_HOME", env)
        self.assertTrue(env["npm_config_cache"].startswith(str(self.revision)))
        self.assertEqual(result["exitCode"], 0)

    def test_expo_build_requires_preparation(self):
        with patch("workspace.toolchain_paths", return_value=self.tools):
            with self.assertRaises(PolicyError) as caught:
                build({"revision_id": "rev1", "device_id": WORKER}, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "preparation_required")
        self.assertFalse(any("build" == arg for call in self.commands.calls for arg in call[0]))

    def test_project_symlink_outside_revision_is_rejected(self):
        outside = self.root / "Outside.xcworkspace"
        outside.mkdir()
        (self.revision / "Outside.xcworkspace").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PolicyError):
            _find_project(self.revision)

    def test_app_selection_is_configuration_specific(self):
        derived = self.revision / "DerivedData"
        for configuration in ("Debug", "Release"):
            (derived / "Build/Products" / (configuration + "-iphonesimulator") / "CoupleJoy.app").mkdir(parents=True)
        self.assertIn("Release-iphonesimulator", str(_find_app(derived, "Release")))
        self.assertIn("Debug-iphonesimulator", str(_find_app(derived, "Debug")))

    def test_native_project_in_one_subdirectory_still_works(self):
        nested = self.revision / "Native/App.xcodeproj"
        nested.mkdir(parents=True)
        (nested / "project.xcworkspace").mkdir()
        self.assertEqual(_find_project(self.revision), nested)

    def test_commands_pass_job_environment_and_cwd_without_shell(self):
        commands = Commands(DEVELOPER_DIR)
        commands.cwd = self.revision
        commands.env = {"HOME": str(self.revision)}
        with patch("worker_exec.run_contained", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
            commands.run(["/approved/node", "script.js"], 5)
        self.assertEqual(run.call_args.kwargs["cwd"], self.revision)
        self.assertEqual(run.call_args.kwargs["env"], commands.env)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_owner_config_requires_boolean_opt_in(self):
        path = self.root / "worker.json"
        path.write_text(json.dumps({"device_allowlist": [WORKER], "allow_dependency_install": "yes"}))
        with self.assertRaises(PolicyError):
            load_worker_config(path)


    def test_swift_recipe_needs_no_node_ruby_or_flutter(self):
        (self.revision / "package.json").unlink()
        (self.revision / "Simple.xcodeproj").mkdir()
        result = prepare({"recipe": "swift-ios", "revision_id": "rev1"}, self.cfg, self.commands)
        self.assertEqual(result["recipe"], "swift-ios")
        argv = self.commands.calls[-1][0]
        self.assertIn("-resolvePackageDependencies", argv)
        self.assertIn("-onlyUsePackageVersionsFromResolvedFile", argv)
        self.assertNotIn("NODE_BINARY", self.commands.calls[-1][2])

    def test_flutter_uses_private_sdk_and_locked_pub_get(self):
        (self.revision / "pubspec.yaml").write_text("name: app\\n")
        (self.revision / "pubspec.lock").write_text("packages: {}\\n")
        (self.revision / "ios").mkdir()
        sdk = self.root / "sdk"
        (sdk / "bin").mkdir(parents=True)
        (sdk / "bin/flutter").write_text("approved SDK fixture")
        (sdk / "bin/flutter").chmod(0o755)
        tools = {"flutter_sdk": sdk, "pod": Path("/approved/pod"), "ruby_bin": Path("/approved/ruby/bin")}
        with patch("worker_exec.toolchain_paths", return_value=tools):
            result = prepare({"recipe": "flutter-ios", "revision_id": "rev1"}, self.cfg, self.commands)
        self.assertEqual(result["recipe"], "flutter-ios")
        first = self.commands.calls[0][0]
        self.assertEqual(first[1:], ["pub", "get", "--enforce-lockfile"])
        self.assertTrue(first[0].startswith(str(self.revision / ".worker/flutter")))
        self.assertIn("--no-codesign", self.commands.calls[1][0])
        self.assertEqual((sdk / "bin/flutter").read_text(), "approved SDK fixture")

    def test_flutter_simulator_rejects_release_mode(self):
        (self.revision / "pubspec.yaml").write_text("name: app")
        with self.assertRaises(PolicyError) as caught:
            build({"revision_id": "rev1", "device_id": WORKER, "configuration": "Release"}, self.cfg, self.commands)
        self.assertEqual(caught.exception.code, "invalid_configuration")

    def test_flutter_runner_app_is_not_mistaken_for_xctest_runner(self):
        derived = self.revision / "DerivedData"
        target = derived / "Build/Products/Debug-iphonesimulator/Runner.app"
        target.mkdir(parents=True)
        (target.parent / "RunnerUITests-Runner.app").mkdir()
        self.assertEqual(_find_app(derived), target)

    def test_flutter_sdk_links_cannot_escape_approved_tree(self):
        sdk = self.root / "sdk"
        sdk.mkdir()
        (sdk / "escape").symlink_to(self.root / "outside")
        with self.assertRaises(PolicyError):
            copy_flutter_sdk(self.revision, sdk)


if __name__ == "__main__":
    unittest.main()
