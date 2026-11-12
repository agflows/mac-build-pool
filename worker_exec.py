"""Operations the iosagent account is allowed to perform.

Build scripts and UI tests from a submitted project run as iosagent. Any
credential that account can read is exposed to that code. This process does
not receive the API token, and it has no host-shell operation.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CODE_ROOT = str(Path(__file__).resolve().parent)
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)

import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import time

from config import DEVELOPER_DIR, LIBRARY_ROOT, load_worker_config
from containment import BUILD_TIMEOUT, PREPARE_TIMEOUT, LOG_CAP, TEMP_ROOT, directory_size, install_import_path, run_contained, worker_child_env
from memory import boot_needs_approval, sample_system
from policy import PolicyError, check_device, require_id, require_scheme, require_under, require_bool, require_configuration, require_recipe, require_public_env
from tarsafe import extract_source
from workspace import is_expo_project, is_flutter_project, copy_flutter_sdk, toolchain_paths, workspace_env, preparation_receipt, load_prepared_env

install_import_path()
CONFIG_PATH = LIBRARY_ROOT / "worker.json"


class CommandFailed(RuntimeError):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")


class Commands:
    def __init__(self, developer_dir: str, disk_roots: list | None = None, disk_budget: int = 0) -> None:
        self.developer_dir = developer_dir
        self.disk_roots = list(disk_roots or [])
        self.disk_budget = disk_budget
        self.xcodebuild = str(Path(developer_dir) / "usr/bin/xcodebuild")
        # xcrun is the system shim. This Xcode does not ship one under Developer/usr/bin.
        self.xcrun = "/usr/bin/xcrun"
        self.env = worker_child_env(developer_dir)
        self.cwd = Path("/tmp")

    def run(self, argv: list, timeout: int) -> subprocess.CompletedProcess:
        if not argv or any(not isinstance(part, str) or "\x00" in part for part in argv):
            raise PolicyError("bad_argv", "Command arguments must be strings.")
        if not str(argv[0]).startswith("/"):
            raise PolicyError("bad_argv", "Commands use absolute paths.")
        try:
            return run_contained(
                list(argv),
                timeout=timeout,
                env=self.env,
                cwd=self.cwd,
                disk_roots=self.disk_roots,
                disk_budget=self.disk_budget,
            )
        except RuntimeError as exc:
            if str(exc) == "storage_limit":
                raise PolicyError("storage_limit", "Worker storage is over the 20 GB budget.") from exc
            raise


def perform(request: dict, cfg, commands: Commands, memory=sample_system) -> dict:
    op = request.get("op")
    if op == "ingest":
        return ingest(request, cfg)
    if op == "prepare":
        return prepare(request, cfg, commands)
    if op == "build":
        return build(request, cfg, commands)
    if op == "launch":
        return launch(request, cfg, commands, memory)
    if op == "screenshot":
        return screenshot(request, cfg, commands, memory)
    if op == "uitest":
        return uitest(request, cfg, commands, memory)
    if op == "logs":
        return logs(request, cfg, commands)
    if op == "reset":
        return reset(request, cfg, commands)
    if op == "boot":
        device = _device(request, cfg)
        ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
        return {"ok": True, "log": "booted", "booted": True}
    if op == "shutdown":
        return shutdown(request, cfg, commands)
    if op == "booted":
        return {"ok": True, "booted": is_booted(request, cfg, commands)}
    raise PolicyError("unknown_op", "That operation is not available.")


def ingest(request: dict, cfg) -> dict:
    _require_disk(cfg)
    revision_id = require_id(request.get("revision_id"), "revision")
    archive = require_under(Path(str(request.get("archive", ""))), cfg.spool_root)
    destination = require_under(cfg.workspace_root / revision_id, cfg.workspace_root)
    if destination.exists():
        shutil.rmtree(destination)
    extract_source(archive, destination, cfg.max_upload_bytes)
    _require_disk(cfg)
    return {"ok": True, "log": "extracted"}


def prepare(request: dict, cfg, commands: Commands) -> dict:
    recipe = require_recipe(request.get("recipe"))
    tools = toolchain_paths(cfg, recipe)  # Guest owner opt-in and read-only base toolchains.
    revision = _revision(request, cfg)
    public_env = require_public_env(request.get("public_env", {}))
    if recipe != "expo-ios" and public_env:
        raise PolicyError("invalid_environment", "EXPO_PUBLIC_ configuration is only supported by expo-ios.")
    if recipe == "expo-ios":
        lockfiles = [name for name in ("package-lock.json", "bun.lock", "bun.lockb") if (revision / name).is_file()]
        if not is_expo_project(revision) or len(lockfiles) != 1:
            raise PolicyError("project", "expo-ios requires exactly one supported npm/Bun lockfile at the snapshot root.")
        require_under(revision / lockfiles[0], revision)
        if lockfiles[0].startswith("bun"):
            if "bun" not in tools:
                raise PolicyError("toolchain_missing", "Configure an owner-approved Bun executable for this project.")
            install_step = ("bun install", [str(tools["bun"]), "install", "--frozen-lockfile"])
        else:
            if "npm_cli" not in tools:
                raise PolicyError("toolchain_missing", "Configure the owner-approved npm CLI for this project.")
            install_step = ("npm ci", [str(tools["node"]), str(tools["npm_cli"]), "ci", "--no-audit", "--no-fund"])
    elif recipe == "flutter-ios":
        if not is_flutter_project(revision) or not (revision / "pubspec.lock").is_file() or not (revision / "ios").is_dir():
            raise PolicyError("project", "flutter-ios requires a Flutter app with pubspec.yaml, pubspec.lock and ios/.")
        require_under(revision / "pubspec.lock", revision)
        if directory_size([tools["flutter_sdk"]]) + directory_size([revision]) > cfg.disk_budget:
            raise PolicyError("storage_limit", "Private Flutter SDK copy exceeds the workspace disk budget.")
        copy_flutter_sdk(revision, tools["flutter_sdk"])
    commands.cwd = revision
    commands.env = workspace_env(revision, cfg, public_env, tools=tools)
    receipt = preparation_receipt(revision)
    receipt.unlink(missing_ok=True)  # Never reuse a receipt after failed preparation.
    if recipe == "expo-ios":
        steps = [
            install_step,
            ("expo prebuild", [str(tools["node"]), str(revision / "node_modules/expo/bin/cli"), "prebuild", "--platform", "ios", "--no-install", "--clean", "--skip-dependency-update", "react,react-native"]),
            ("pod install", [str(tools["pod"]), "install", "--project-directory=" + str(revision / "ios")]),
        ]
    elif recipe == "flutter-ios":
        flutter = str(revision / ".worker/flutter/bin/flutter")
        steps = [
            ("flutter pub get", [flutter, "pub", "get", "--enforce-lockfile"]),
            ("flutter iOS configuration", [flutter, "build", "ios", "--simulator", "--debug", "--config-only", "--no-pub", "--no-codesign"]),
        ]
        # Flutter's config-only build processes plugins/Pods (or SwiftPM) itself.
    else:
        project = _find_project(revision)
        package_args = _swift_package_args(revision)
        scheme = _scheme(request, project, commands, package_args)
        steps = [("resolve Swift packages", [commands.xcodebuild, _project_flag(project), str(project),
                  "-scheme", scheme, "-resolvePackageDependencies", *package_args])]

    deadline = time.monotonic() + PREPARE_TIMEOUT - 30
    log = ""
    for label, argv in steps:
        _require_disk(cfg)
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise CommandFailed((log + "\nPreparation deadline exceeded")[-LOG_CAP:], 124)
        log = (log + "\n== " + label + " ==\n")[-LOG_CAP:]
        try:
            completed = commands.run(argv, timeout=remaining)
        except (TimeoutError,subprocess.TimeoutExpired) as exc:
            raise CommandFailed((log+str(exc))[-LOG_CAP:],124) from exc
        except Exception as exc:
            raise CommandFailed((log + str(exc))[-LOG_CAP:], 1) from exc
        log = (log + _tail(completed))[-LOG_CAP:]
        if completed.returncode != 0:
            raise CommandFailed(log, completed.returncode)
    project = _find_project(revision)
    if recipe == "expo-ios" and project.suffix != ".xcworkspace":
        raise PolicyError("preparation_failed", "CocoaPods did not produce an Xcode workspace.")
    _require_disk(cfg)
    receipt.write_text(json.dumps({"recipe": recipe, "publicEnv": public_env}) + "\n")
    return {"ok": True, "recipe": recipe, "log": log, "exitCode": 0}


def build(request: dict, cfg, commands: Commands) -> dict:
    if cfg.sandbox_builds:
        raise PolicyError(
            "sandbox_untested",
            "The xcodebuild sandbox profile has not been validated. Builds stay unsandboxed.",
        )
    device = _device(request, cfg)
    if request.get("scheme"):
        require_scheme(request.get("scheme"))
    shutdown({"op": "shutdown", "device_id": device}, cfg, commands)
    revision = _revision(request, cfg)
    configuration = require_configuration(request.get("configuration", "Debug"))
    if is_flutter_project(revision) and configuration != "Debug":
        raise PolicyError("invalid_configuration", "Flutter iOS simulator builds use Debug mode.")
    for_testing = require_bool(request.get("for_testing", True), "forTesting")
    package_args = _configure_project_commands(revision, cfg, commands)
    project = _find_project(revision)
    scheme = _scheme(request, project, commands, package_args)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    argv = [
        commands.xcodebuild,
        "build-for-testing" if for_testing else "build",
        _project_flag(project),
        str(project),
        "-configuration",
        configuration,
        "-scheme",
        scheme,
        "-destination",
        _destination(request, cfg),
        "-derivedDataPath",
        str(derived),
        *package_args,
        "-jobs",
        "1",
        "ONLY_ACTIVE_ARCH=YES",
        "COMPILER_INDEX_STORE_ENABLE=NO",
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
        "CODE_SIGN_IDENTITY=-",
    ]
    completed = commands.run(argv, timeout=BUILD_TIMEOUT - 60)
    tail = _check(completed, "build failed")
    return {"ok": True, "log": tail, "exitCode": 0}


def launch(request: dict, cfg, commands: Commands, memory) -> dict:
    revision = _revision(request, cfg)
    device = _device(request, cfg)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    app = _find_app(derived, require_configuration(request.get("configuration", "Debug")))
    bundle = _bundle_id(app)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    install = commands.run([commands.xcrun, "simctl", "install", device, str(app)], timeout=180)
    _check(install, "install failed")
    launched = commands.run([commands.xcrun, "simctl", "launch", device, bundle], timeout=60)
    return {"ok": True, "log": _check(launched, "launch failed"), "bundle_id": bundle, "exitCode": 0}


def screenshot(request: dict, cfg, commands: Commands, memory) -> dict:
    device = _device(request, cfg)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    artifact_id = require_id(request.get("artifact_id") or _fallback_id(request), "artifact")
    path = require_under(cfg.artifact_root / f"{artifact_id}.png", cfg.artifact_root)
    completed = commands.run([commands.xcrun, "simctl", "io", device, "screenshot", str(path)], timeout=60)
    _check(completed, "screenshot failed")
    if path.is_symlink() or not path.is_file():
        raise CommandFailed("screenshot failed", completed.returncode or 1)
    # Both service accounts use staff, but the artifact directory is 700 with
    # access only for iosbroker/iosagent. Allow the broker to read this output
    # even when simctl honored our private 077 umask; never chmod through a link.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PolicyError("path_escape", "Screenshot must be a regular, unlinked output file.")
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
    return {"ok": True, "log": "screenshot", "artifact_id": artifact_id, "artifact_path": str(path)}


def uitest(request: dict, cfg, commands: Commands, memory) -> dict:
    if cfg.sandbox_builds:
        raise PolicyError("sandbox_untested", "Test sandboxing has not been validated.")
    device = _device(request, cfg)
    revision = _revision(request, cfg)
    configuration = require_configuration(request.get("configuration", "Debug"))
    project = _find_project(revision)
    package_args = _configure_project_commands(revision, cfg, commands)
    scheme = _scheme(request, project, commands, package_args)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    argv = [
        commands.xcodebuild,
        "test-without-building",
        _project_flag(project),
        str(project),
        "-configuration",
        configuration,
        "-parallel-testing-enabled",
        "NO",
        "-scheme",
        scheme,
        "-destination",
        f"platform=iOS Simulator,id={device},arch=arm64",
        "-derivedDataPath",
        str(derived),
        *package_args,
        "-jobs",
        "1",
    ]
    completed = commands.run(argv, timeout=900)
    return {"ok": True, "log": _check(completed, "ui test failed"), "exitCode": 0}


def logs(request: dict, cfg, commands: Commands) -> dict:
    device = _device(request, cfg)
    completed = commands.run(
        [commands.xcrun, "simctl", "spawn", device, "log", "show", "--style", "compact", "--last", "2m"],
        timeout=60,
    )
    return {"ok": True, "log": _check(completed, "log collection failed"), "exitCode": 0}


def reset(request: dict, cfg, commands: Commands) -> dict:
    device = _device(request, cfg)
    shutdown({"op": "shutdown", "device_id": device}, cfg, commands)
    erased = commands.run([commands.xcrun, "simctl", "erase", device], timeout=180)
    _check(erased, "erase failed")
    revision_id = request.get("revision_id")
    if revision_id:
        revision = require_under(cfg.workspace_root / require_id(revision_id, "revision"), cfg.workspace_root)
        if revision.exists():
            shutil.rmtree(revision)
    return {"ok": True, "log": "reset"}


def shutdown(request: dict, cfg, commands: Commands) -> dict:
    device = _device(request, cfg)
    if is_booted(request, cfg, commands):
        completed = commands.run([commands.xcrun, "simctl", "shutdown", device], timeout=60)
        _check(completed, "shutdown failed")
    return {"ok": True, "log": "shutdown"}


def is_booted(request: dict, cfg, commands: Commands) -> bool:
    device = _device(request, cfg)
    completed = commands.run([commands.xcrun, "simctl", "list", "devices", "-j"], timeout=30)
    _check(completed, "simctl list failed")
    listing = json.loads(completed.stdout.decode("utf-8"))
    for devices in listing.get("devices", {}).values():
        for item in devices:
            if str(item.get("udid", "")).upper() == device and item.get("state") == "Booted":
                return True
    return False


def ensure_booted(device: str, approved: bool, cfg, commands: Commands, memory) -> None:
    probe = {"device_id": device}
    if is_booted(probe, cfg, commands):
        return
    sample = memory()
    if boot_needs_approval(None, sample, approved):
        raise PolicyError("approval_required", "Simulator boot is waiting for approval.")
    _check(commands.run([commands.xcrun, "simctl", "boot", device], timeout=180), "boot failed")
    status = commands.run([commands.xcrun, "simctl", "bootstatus", device, "-b"], timeout=180)
    if not is_booted(probe, cfg, commands):
        raise CommandFailed(_tail(status) or "boot failed", int(status.returncode or 1))
    if getattr(cfg,'package_proxy',False):
        from execution_policy import require_protected_file
        certificate=Path('/Library/ios-worker/proxy-ca.pem')
        require_protected_file(certificate)
        _check(commands.run([commands.xcrun,'simctl','keychain',device,'add-root-cert',str(certificate)],
                            timeout=30),'guest simulator relay trust setup failed')


def _device(request: dict, cfg) -> str:
    return check_device(str(request.get("device_id", "")), cfg.device_allowlist, cfg.device_denylist)


def _revision(request: dict, cfg) -> Path:
    revision_id = require_id(request.get("revision_id"), "revision")
    return require_under(cfg.workspace_root / revision_id, cfg.workspace_root)


def _destination(request: dict, cfg) -> str:
    return f"platform=iOS Simulator,id={_device(request, cfg)},arch=arm64"


def _swift_package_args(revision: Path) -> tuple[str, ...]:
    return ("-onlyUsePackageVersionsFromResolvedFile", "-skipPackageUpdates",
            "-clonedSourcePackagesDirPath", str(revision / ".worker/cache/swift-packages"))


def _configure_project_commands(revision: Path, cfg, commands: Commands) -> tuple[str, ...]:
    generated = is_expo_project(revision) or is_flutter_project(revision)
    prepared = (revision / ".worker/prepared.json").exists()
    if generated or prepared:
        commands.env = load_prepared_env(revision, cfg)
        # CoreSimulator/Xcode need the actual account home to find its devices.
        # Package caches remain job-local; only installers use the synthetic HOME.
        commands.env["HOME"] = "/Users/iosagent"
        commands.env.pop("CFFIXED_USER_HOME", None)
        commands.cwd = revision
    return _swift_package_args(revision) if prepared and not generated else ()


def _project_flag(project: Path) -> str:
    return "-workspace" if project.suffix == ".xcworkspace" else "-project"


def _find_project(revision: Path) -> Path:
    # Prefer a CocoaPods workspace. Do not select .xcodeproj/project.xcworkspace
    # or dependency projects beneath node_modules/Pods.
    bases = [revision] + [p for p in revision.iterdir() if p.is_dir()
                          and p.name not in {"node_modules", "Pods", "DerivedData", ".worker"}
                          and p.suffix not in {".xcodeproj", ".xcworkspace"}]
    for suffix in ("xcworkspace", "xcodeproj"):
        matches = [p for base in bases for p in base.glob("*." + suffix) if p.is_dir()]
        if len(matches) > 1:
            raise PolicyError("project", "Snapshot has multiple Xcode containers; provide a single app at root or one directory below.")
        if matches:
            return require_under(matches[0], revision)
    raise PolicyError("project", "Expected an Xcode project/workspace at root or one directory below. Expo projects must be prepared first.")


def _scheme(request: dict, project: Path, commands: Commands, package_args: tuple[str, ...] = ()) -> str:
    requested = request.get("scheme")
    if requested:
        requested = require_scheme(requested)
    completed = commands.run([commands.xcodebuild, _project_flag(project), str(project), "-list", "-json",
                              *package_args], timeout=60)
    _check(completed, "xcodebuild -list failed")
    listing = json.loads(completed.stdout.decode("utf-8"))
    section = "workspace" if project.suffix == ".xcworkspace" else "project"
    schemes = list(listing.get(section, {}).get("schemes", []))
    if requested:
        if requested not in schemes:
            raise PolicyError("invalid_scheme", "Scheme is not in this project.")
        return requested
    if len(schemes) != 1:
        raise PolicyError("invalid_scheme", "Name a scheme. This project has more than one.")
    return schemes[0]


def _find_app(derived: Path, configuration: str = "Debug") -> Path:
    products = derived / "Build" / "Products"
    apps = [
        path
        for path in products.glob(require_configuration(configuration) + "-iphonesimulator/*.app")
        if path.is_dir() and "UITests" not in path.name and not path.name.endswith("-Runner.app")
    ]
    if len(apps) != 1:
        raise PolicyError("product", "Expected one built app in DerivedData.")
    return apps[0]


def _bundle_id(app: Path) -> str:
    with (app / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    bundle = str(info.get("CFBundleIdentifier", ""))
    if not BUNDLE_RE.fullmatch(bundle):
        raise PolicyError("bundle", "Built app has an unexpected bundle id.")
    return bundle


def _fallback_id(request: dict) -> str:
    job_id = request.get("job_id")
    if isinstance(job_id, str):
        return require_id(job_id, "job")
    raise PolicyError("invalid_id", "artifact id is missing")


def _check(completed: subprocess.CompletedProcess, label: str) -> str:
    tail = _tail(completed)
    if completed.returncode != 0:
        raise CommandFailed(tail or label, int(completed.returncode or 1))
    return tail


def _failure(message: str, error: str, exit_code: int) -> None:
    payload = {"ok": False, "error": error, "message": message[-LOG_CAP:], "exitCode": exit_code}
    sys.stderr.write(json.dumps(payload))


def _tail(completed: subprocess.CompletedProcess) -> str:
    text = (completed.stdout or b"").decode("utf-8", "replace")
    err = (completed.stderr or b"").decode("utf-8", "replace")
    combined = (text + "\n" + err).strip()
    return combined[-64_000:]


def _uid(name: str) -> int:
    import pwd

    return pwd.getpwnam(name).pw_uid


def _require_disk(cfg) -> None:
    used = directory_size([cfg.workspace_root, cfg.spool_root, cfg.artifact_root, TEMP_ROOT])
    if used > cfg.disk_budget:
        raise PolicyError("storage_limit", "Worker storage is over the 20 GB budget.")


def main() -> int:
    os.umask(0o077)
    try:
        from execution_policy import require_worker_execution, require_protected_file, require_native_config, NATIVE
        mode = require_worker_execution()
        require_protected_file(CONFIG_PATH)
        from containment import apply_rlimits

        apply_rlimits()
        request = json.load(sys.stdin)
        cfg = load_worker_config(CONFIG_PATH)
        if mode == NATIVE:
            require_native_config(cfg)
        if cfg.developer_dir != DEVELOPER_DIR:
            raise PolicyError("bad_config", "developer_dir is fixed.")
        result = perform(
            request,
            cfg,
            Commands(
                cfg.developer_dir,
                disk_roots=[cfg.workspace_root, cfg.spool_root, cfg.artifact_root, TEMP_ROOT],
                disk_budget=cfg.disk_budget,
            ),
        )
    except PolicyError as exc:
        _failure(exc.message, exc.code, 2)
        return 2
    except CommandFailed as exc:
        _failure(str(exc) or "command failed", "command_failed", exc.exit_code)
        return 1
    except FileNotFoundError as exc:
        _failure("FileNotFoundError " + str(exc.filename or ""), "FileNotFoundError", 1)
        return 1
    except Exception as exc:
        _failure(str(exc) or exc.__class__.__name__, exc.__class__.__name__, 1)
        return 1
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
