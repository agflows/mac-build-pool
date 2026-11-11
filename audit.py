"""Report the privileges iosagent actually has, and probe the sandbox.

This does not change group membership. A passing echo-and-deny probe is not a
validated sandbox for xcodebuild: builds stay outside sandbox-exec.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

PROBE = Path(__file__).with_name("probe.sb")
HOME_FILE = Path("/Users/leolurch/Documents/runner/data/arduino-tests/Untitled/ios-worker/probe.sb")
XCODEBUILD = "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild"


def collect() -> dict:
    report = {
        "account": _text(["/usr/bin/id", "iosagent"]),
        "developer_group": _text(["/usr/bin/dscl", ".", "-read", "/Groups/_developer", "GroupMembership", "PrimaryGroupID"]),
        "member_developer": _text(["/usr/bin/dsmemberutil", "checkmembership", "-U", "iosagent", "-G", "_developer"]),
        "member_admin": _text(["/usr/bin/dsmemberutil", "checkmembership", "-U", "iosagent", "-G", "admin"]),
        "member_wheel": _text(["/usr/bin/dsmemberutil", "checkmembership", "-U", "iosagent", "-G", "wheel"]),
        "devtools_security": _text(["/usr/sbin/DevToolsSecurity", "-status"]),
        "amfi_developer_mode": _text(["/usr/sbin/sysctl", "-n", "security.mac.amfi.developer_mode_status"]),
        "developer_tree": _developer_tree(),
        "sandbox_probe": _sandbox_probe(),
        "credential_risk": (
            "Submitted build scripts and UI tests run as iosagent. "
            "Any credential that account can read is exposed to that code. "
            "The API token stays in the broker account's token file and is not passed to the worker."
        ),
    }
    return report


def _developer_tree() -> dict:
    root = Path("/Library/Developer")
    owned: list[str] = []
    writable: list[str] = []
    try:
        group = _group_id("_developer")
    except Exception as exc:
        return {"error": exc.__class__.__name__}
    for current, dirs, files in os.walk(root):
        depth = Path(current).relative_to(root).parts
        if len(depth) >= 2:
            dirs.clear()
            continue
        for name in list(dirs) + list(files):
            path = Path(current) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            mode = stat.S_IMODE(info.st_mode)
            record = f"{mode:o} gid={info.st_gid} {path}"
            if info.st_gid == group:
                owned.append(record)
            if mode & stat.S_IWGRP:
                writable.append(record)
            if len(owned) + len(writable) >= 40:
                break
    root_stat = root.lstat() if root.exists() else None
    top = []
    if root.exists():
        top.append(f"{stat.S_IMODE(root_stat.st_mode):o} {root_stat.st_uid}:{root_stat.st_gid} {root}")
        for child in sorted(root.iterdir()):
            info = child.lstat()
            top.append(f"{stat.S_IMODE(info.st_mode):o} {info.st_uid}:{info.st_gid} {child.name}")
    return {
        "group_id": group,
        "top": top,
        "owned_by_developer_group": owned,
        "group_writable": writable,
    }


def _sandbox_probe() -> dict:
    echo = _run(["/usr/bin/sandbox-exec", "-f", str(PROBE), "/bin/echo", "sandbox-ok"])
    denied = _run(["/usr/bin/sandbox-exec", "-f", str(PROBE), "/bin/cat", str(HOME_FILE)])
    version = _run(["/usr/bin/sandbox-exec", "-f", str(PROBE), XCODEBUILD, "-version"])
    leaked = "deny default" in denied["stdout"]
    return {
        "profile": str(PROBE),
        "echo_ok": echo["code"] == 0 and echo["stdout"].strip() == "sandbox-ok",
        "home_read_denied": denied["code"] != 0 and not leaked,
        "home_read_code": denied["code"],
        "xcodebuild_version_code": version["code"],
        "xcodebuild_version_stderr": version["stderr"][-400:],
        "xcodebuild_builds_sandboxed": False,
        "note": (
            "The profile denies reading the personal home for a trivial process. "
            "xcodebuild -version under that profile is recorded above and is not a tested compile sandbox. "
            "worker builds keep sandbox_builds off and refuse to prefix sandbox-exec."
        ),
    }


def _group_id(name: str) -> int:
    text = _text(["/usr/bin/dscl", ".", "-read", f"/Groups/{name}", "PrimaryGroupID"])
    for line in text.splitlines():
        if "PrimaryGroupID" in line:
            return int(line.split()[-1])
    raise RuntimeError("missing PrimaryGroupID")


def _text(argv: list) -> str:
    result = _run(argv)
    output = (result["stdout"] + "\n" + result["stderr"]).strip()
    return output[:2000]


def _run(argv: list) -> dict:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"},
        )
    except Exception as exc:
        return {"code": -1, "stdout": "", "stderr": exc.__class__.__name__}
    return {
        "code": completed.returncode,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
    }


def main() -> int:
    json.dump(collect(), __import__("sys").stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
