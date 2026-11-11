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
import subprocess

from config import DEVELOPER_DIR, LIBRARY_ROOT, load_worker_config
from containment import TEMP_ROOT, directory_size, install_import_path, run_contained, worker_child_env
from memory import boot_needs_approval, sample_system
from policy import PolicyError, check_device, require_id, require_scheme, require_under
from tarsafe import extract_source

install_import_path()
CONFIG_PATH = LIBRARY_ROOT / "worker.json"
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")


class Commands:
    def __init__(self, developer_dir: str, disk_roots: list | None = None, disk_budget: int = 0) -> None:
        self.developer_dir = developer_dir
        self.disk_roots = list(disk_roots or [])
        self.disk_budget = disk_budget
        self.xcodebuild = str(Path(developer_dir) / "usr/bin/xcodebuild")
        # xcrun is the system shim. This Xcode does not ship one under Developer/usr/bin.
        self.xcrun = "/usr/bin/xcrun"

    def run(self, argv: list, timeout: int) -> subprocess.CompletedProcess:
        if not argv or any(not isinstance(part, str) or "\x00" in part for part in argv):
            raise PolicyError("bad_argv", "Command arguments must be strings.")
        if not str(argv[0]).startswith("/"):
            raise PolicyError("bad_argv", "Commands use absolute paths.")
        try:
            return run_contained(
                list(argv),
                timeout=timeout,
                env=worker_child_env(self.developer_dir),
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
    project = _find_project(revision)
    scheme = _scheme(request, project, commands)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    argv = [
        commands.xcodebuild,
        "build-for-testing",
        "-project",
        str(project),
        "-scheme",
        scheme,
        "-destination",
        _destination(request, cfg),
        "-derivedDataPath",
        str(derived),
        "-jobs",
        "1",
        "ONLY_ACTIVE_ARCH=YES",
        "COMPILER_INDEX_STORE_ENABLE=NO",
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
        "CODE_SIGN_IDENTITY=-",
    ]
    completed = commands.run(argv, timeout=900)
    tail = _tail(completed)
    if completed.returncode != 0:
        raise RuntimeError(tail or "build failed")
    return {"ok": True, "log": tail}


def launch(request: dict, cfg, commands: Commands, memory) -> dict:
    revision = _revision(request, cfg)
    device = _device(request, cfg)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    app = _find_app(derived)
    bundle = _bundle_id(app)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    install = commands.run([commands.xcrun, "simctl", "install", device, str(app)], timeout=180)
    if install.returncode != 0:
        raise RuntimeError(_tail(install) or "install failed")
    launched = commands.run([commands.xcrun, "simctl", "launch", device, bundle], timeout=60)
    if launched.returncode != 0:
        raise RuntimeError(_tail(launched) or "launch failed")
    return {"ok": True, "log": _tail(launched), "bundle_id": bundle}


def screenshot(request: dict, cfg, commands: Commands, memory) -> dict:
    device = _device(request, cfg)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    artifact_id = require_id(request.get("artifact_id") or _fallback_id(request), "artifact")
    path = require_under(cfg.artifact_root / f"{artifact_id}.png", cfg.artifact_root)
    completed = commands.run([commands.xcrun, "simctl", "io", device, "screenshot", str(path)], timeout=60)
    if completed.returncode != 0 or not path.is_file():
        raise RuntimeError(_tail(completed) or "screenshot failed")
    return {"ok": True, "log": "screenshot", "artifact_id": artifact_id, "artifact_path": str(path)}


def uitest(request: dict, cfg, commands: Commands, memory) -> dict:
    device = _device(request, cfg)
    revision = _revision(request, cfg)
    project = _find_project(revision)
    scheme = _scheme(request, project, commands)
    ensure_booted(device, bool(request.get("approved")), cfg, commands, memory)
    derived = require_under(revision / "DerivedData", cfg.workspace_root)
    argv = [
        commands.xcodebuild,
        "test-without-building",
        "-project",
        str(project),
        "-scheme",
        scheme,
        "-destination",
        f"platform=iOS Simulator,id={device},arch=arm64",
        "-derivedDataPath",
        str(derived),
        "-jobs",
        "1",
    ]
    completed = commands.run(argv, timeout=900)
    tail = _tail(completed)
    if completed.returncode != 0:
        raise RuntimeError(tail or "ui test failed")
    return {"ok": True, "log": tail}


def logs(request: dict, cfg, commands: Commands) -> dict:
    device = _device(request, cfg)
    completed = commands.run(
        [commands.xcrun, "simctl", "spawn", device, "log", "show", "--style", "compact", "--last", "2m"],
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(_tail(completed) or "log collection failed")
    return {"ok": True, "log": _tail(completed)}


def reset(request: dict, cfg, commands: Commands) -> dict:
    device = _device(request, cfg)
    shutdown({"op": "shutdown", "device_id": device}, cfg, commands)
    erased = commands.run([commands.xcrun, "simctl", "erase", device], timeout=180)
    if erased.returncode != 0:
        raise RuntimeError(_tail(erased) or "erase failed")
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
        if completed.returncode != 0:
            raise RuntimeError(_tail(completed) or "shutdown failed")
    return {"ok": True, "log": "shutdown"}


def is_booted(request: dict, cfg, commands: Commands) -> bool:
    device = _device(request, cfg)
    completed = commands.run([commands.xcrun, "simctl", "list", "devices", "-j"], timeout=30)
    if completed.returncode != 0:
        raise RuntimeError("simctl list failed")
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
    commands.run([commands.xcrun, "simctl", "boot", device], timeout=180)
    status = commands.run([commands.xcrun, "simctl", "bootstatus", device, "-b"], timeout=180)
    if not is_booted(probe, cfg, commands):
        raise RuntimeError(_tail(status) or "boot failed")


def _device(request: dict, cfg) -> str:
    return check_device(str(request.get("device_id", "")), cfg.device_allowlist, cfg.device_denylist)


def _revision(request: dict, cfg) -> Path:
    revision_id = require_id(request.get("revision_id"), "revision")
    return require_under(cfg.workspace_root / revision_id, cfg.workspace_root)


def _destination(request: dict, cfg) -> str:
    return f"platform=iOS Simulator,id={_device(request, cfg)},arch=arm64"


def _find_project(revision: Path) -> Path:
    matches = list(revision.glob("*.xcodeproj")) + list(revision.glob("*/*.xcodeproj"))
    matches = [item for item in matches if item.is_dir()]
    if len(matches) != 1:
        raise PolicyError("project", "The snapshot must contain exactly one Xcode project.")
    return matches[0]


def _scheme(request: dict, project: Path, commands: Commands) -> str:
    requested = request.get("scheme")
    if requested:
        requested = require_scheme(requested)
    completed = commands.run([commands.xcodebuild, "-project", str(project), "-list", "-json"], timeout=60)
    if completed.returncode != 0:
        raise RuntimeError("xcodebuild -list failed")
    listing = json.loads(completed.stdout.decode("utf-8"))
    schemes = list(listing.get("project", {}).get("schemes", []))
    if requested:
        if requested not in schemes:
            raise PolicyError("invalid_scheme", "Scheme is not in this project.")
        return requested
    if len(schemes) != 1:
        raise PolicyError("invalid_scheme", "Name a scheme. This project has more than one.")
    return schemes[0]


def _find_app(derived: Path) -> Path:
    products = derived / "Build" / "Products"
    apps = [
        path
        for path in products.glob("*-iphonesimulator/*.app")
        if path.is_dir() and "UITests" not in path.name and not path.name.endswith("Runner.app")
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
    try:
        if os.environ.get("IOS_WORKER_DEV") != "1" and os.geteuid() != _uid("iosagent"):
            sys.stderr.write("worker must run as iosagent\n")
            return 2
        from containment import apply_rlimits

        apply_rlimits()
        request = json.load(sys.stdin)
        cfg = load_worker_config(CONFIG_PATH)
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
        sys.stderr.write(exc.message + "\n")
        return 2
    except FileNotFoundError as exc:
        sys.stderr.write("FileNotFoundError " + str(exc.filename or "") + "\n")
        return 1
    except Exception as exc:
        sys.stderr.write(exc.__class__.__name__ + "\n")
        return 1
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
