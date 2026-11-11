"""Install the broker as iosbroker and the worker code as root-owned files.

Run this as root from outside ~/Documents. It does not print the API token
or the generated account password.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

LIBRARY = Path("/Library/ios-worker")
DATA = LIBRARY / "data"
BROKER_HOME = Path("/Users/iosbroker")
BROKER_DIR = BROKER_HOME / ".ios-worker"
PLIST_DST = Path("/Library/LaunchDaemons/com.iosworker.broker.plist")
SUDOERS_DST = Path("/etc/sudoers.d/ios-worker")
WORKER_DEVICE = "3C8BB98E-6383-446B-AF87-1E1282762A13"
PERSONAL_DEVICE = "4D015300-4BAE-4E6D-89C9-BC4D454E4216"
CODE = (
    "policy.py",
    "config.py",
    "memory.py",
    "tarsafe.py",
    "containment.py",
    "worker_exec.py",
    "runner.py",
    "scheduler.py",
    "api.py",
    "broker.py",
    "audit.py",
)
ACL_READ = "iosagent allow read,execute,file_inherit,directory_inherit"
ACL_WRITE = "iosagent allow read,write,execute,delete,add_file,add_subdirectory,file_inherit,directory_inherit"
ACL_TRAVERSE = "iosagent allow search"


def main() -> int:
    os.chdir("/tmp")
    if os.geteuid() != 0:
        sys.stderr.write("install_system.py must run as root\n")
        return 1
    source = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
    scratch = _private_dir()
    try:
        return _install(source, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _install(source: Path, scratch: Path) -> int:
    _ensure_user()
    _install_code(source)
    _install_helper(source)
    _probe_jetsam(scratch)
    _install_data()
    _install_sudoers(source, scratch)
    _probe_launch()
    _install_daemon(source)
    _remove_shared_copy()
    _free_port()
    subprocess.run(["/bin/launchctl", "bootout", "system/com.iosworker.broker"], check=False)
    subprocess.run(["/bin/launchctl", "bootstrap", "system", str(PLIST_DST)], check=True)
    subprocess.run(["/bin/launchctl", "enable", "system/com.iosworker.broker"], check=False)
    subprocess.run(["/bin/launchctl", "kickstart", "-k", "system/com.iosworker.broker"], check=True)
    import time

    time.sleep(2)
    log = BROKER_DIR / "broker.log"
    text = ""
    if log.exists():
        text = log.read_text(errors="replace")[-1500:]
        import re

        text = re.sub(r"[0-9a-fA-F]{32,}", "[redacted]", text)
    status = subprocess.run(
        ["/bin/launchctl", "print", "system/com.iosworker.broker"],
        capture_output=True,
        text=True,
    )
    if "listening on" not in text or "state = running" not in status.stdout:
        print(text)
        print("\n".join(status.stdout.splitlines()[:25]))
        return 1
    sys.path.insert(0, str(LIBRARY))
    from containment import launch_path_problems

    problems = launch_path_problems(LIBRARY)
    if problems:
        for item in problems:
            sys.stderr.write(item + "\n")
        return 1
    print("installed /Library/ios-worker as root")
    print("broker account: iosbroker (not admin, home mode 700)")
    print(f"token file: {BROKER_DIR / 'token'} (mode 600, value not printed)")
    print(f"operator token file: {BROKER_DIR / 'operator-token'} (mode 600, value not printed)")
    print("launchd: system/com.iosworker.broker UserName=iosbroker")
    return 0


def _private_dir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="ios-worker-"))
    os.chown(path, 0, 0)
    path.chmod(0o700)
    return path


def _ensure_user() -> None:
    if not _user_exists("iosbroker"):
        password = secrets.token_hex(24)
        try:
            completed = subprocess.run(
                [
                    "/usr/sbin/sysadminctl",
                    "-addUser",
                    "iosbroker",
                    "-fullName",
                    "iOS Broker",
                    "-shell",
                    "/usr/bin/false",
                    "-password",
                    password,
                    "-home",
                    str(BROKER_HOME),
                ],
                capture_output=True,
                text=True,
            )
            detail = (completed.stdout + completed.stderr).replace(password, "[redacted]")
            if not _user_exists("iosbroker"):
                _create_with_dscl(password)
            elif completed.returncode != 0 and "error" in detail.lower():
                sys.stderr.write(detail[-400:] + "\n")
        finally:
            del password
    if not BROKER_HOME.exists():
        subprocess.run(["/usr/sbin/createhomedir", "-c", "-u", "iosbroker"], check=True)
    subprocess.run(["/usr/sbin/dseditgroup", "-o", "edit", "-d", "iosbroker", "-t", "user", "admin"], check=False)
    subprocess.run(["/usr/bin/dscl", ".", "-create", "/Users/iosbroker", "IsHidden", "1"], check=False)
    subprocess.run(["/usr/sbin/dseditgroup", "-o", "edit", "-d", "iosbroker", "-t", "user", "_developer"], check=False)
    os.chown(BROKER_HOME, _uid("iosbroker"), 20)
    BROKER_HOME.chmod(0o700)
    BROKER_DIR.mkdir(exist_ok=True)
    os.chown(BROKER_DIR, _uid("iosbroker"), 20)
    BROKER_DIR.chmod(0o700)
    if _member("iosbroker", "admin"):
        raise SystemExit("iosbroker is still an admin")


def _create_with_dscl(password: str) -> None:
    uid = _next_uid()
    commands = [
        ["create", "/Users/iosbroker"],
        ["create", "/Users/iosbroker", "UserShell", "/usr/bin/false"],
        ["create", "/Users/iosbroker", "RealName", "iOS Broker"],
        ["create", "/Users/iosbroker", "UniqueID", str(uid)],
        ["create", "/Users/iosbroker", "PrimaryGroupID", "20"],
        ["create", "/Users/iosbroker", "NFSHomeDirectory", str(BROKER_HOME)],
    ]
    for command in commands:
        subprocess.run(["/usr/bin/dscl", ".", *command], check=True)
    completed = subprocess.run(
        ["/usr/bin/dscl", ".", "-passwd", "/Users/iosbroker", password],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr).replace(password, "[redacted]")
        raise SystemExit(detail[-400:] or "could not set the broker account password")
    subprocess.run(["/usr/sbin/createhomedir", "-c", "-u", "iosbroker"], check=False)


def _install_code(source: Path) -> None:
    LIBRARY.mkdir(exist_ok=True)
    os.chown(LIBRARY, 0, 0)
    LIBRARY.chmod(0o755)
    subprocess.run(["/bin/chmod", "-N", str(LIBRARY)], check=False)
    for name in CODE:
        target = LIBRARY / name
        shutil.copyfile(source / name, target)
        os.chown(target, 0, 0)
        target.chmod(0o644)
        subprocess.run(["/bin/chmod", "-N", str(target)], check=False)
    worker = {
        "workspace_root": str(DATA / "work"),
        "spool_root": str(DATA / "spool"),
        "artifact_root": str(DATA / "artifacts"),
        "developer_dir": "/Applications/Xcode.app/Contents/Developer",
        "device_allowlist": [WORKER_DEVICE],
        "device_denylist": [PERSONAL_DEVICE],
        "sandbox_builds": False,
        "max_upload_bytes": 64 * 1024 * 1024,
        "disk_budget_bytes": 20 * 1024 * 1024 * 1024,
        "memory_limit_bytes": 6 * 1024 * 1024 * 1024,
    }
    import json

    path = LIBRARY / "worker.json"
    path.write_text(json.dumps(worker, indent=2) + "\n")
    os.chown(path, 0, 0)
    path.chmod(0o644)


def _install_helper(source: Path) -> None:
    binary = LIBRARY / "worker_cap"
    compilers = ["/usr/bin/clang", "/usr/bin/cc"]
    last = "compiler missing"
    for compiler in compilers:
        if not Path(compiler).exists():
            continue
        completed = subprocess.run(
            [compiler, "-O2", "-Wall", "-Werror", "-o", str(binary), str(source / "worker_cap.c")],
            capture_output=True,
            text=True,
        )
        last = (completed.stderr or completed.stdout)[-400:]
        if completed.returncode == 0:
            os.chown(binary, 0, 0)
            binary.chmod(0o755)
            subprocess.run(["/bin/chmod", "-N", str(binary)], check=False)
            return
    raise SystemExit(last or "worker_cap compile failed")


def _probe_jetsam(scratch: Path) -> None:
    """Report which limits a root process can set and whether a child inherits them."""
    probe = scratch / "jetsam-probe.py"
    probe.write_text(
        "import ctypes, os, resource\n"
        "print('euid', os.geteuid(), flush=True)\n"
        "for name in ('RLIMIT_AS', 'RLIMIT_DATA', 'RLIMIT_RSS', 'RLIMIT_NPROC'):\n"
        "    limit = getattr(resource, name)\n"
        "    value = 512 if name == 'RLIMIT_NPROC' else 6442450944\n"
        "    try:\n"
        "        resource.setrlimit(limit, (value, value))\n"
        "        print(name, 'set', resource.getrlimit(limit), flush=True)\n"
        "    except Exception as exc:\n"
        "        print(name, type(exc).__name__, exc, flush=True)\n"
        "read_fd, write_fd = os.pipe()\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.close(read_fd)\n"
        "    text = 'child_as=%s child_nproc=%s\\n' % (resource.getrlimit(resource.RLIMIT_AS), resource.getrlimit(resource.RLIMIT_NPROC))\n"
        "    os.write(write_fd, text.encode())\n"
        "    os.close(write_fd)\n"
        "    os._exit(0)\n"
        "os.close(write_fd)\n"
        "print(os.read(read_fd, 300).decode(), end='', flush=True)\n"
        "os.close(read_fd)\n"
        "os.waitpid(pid, 0)\n"
        "class P(ctypes.Structure):\n"
        "    _fields_ = [('a', ctypes.c_int32), ('aa', ctypes.c_uint32), ('i', ctypes.c_int32), ('ia', ctypes.c_uint32)]\n"
        "libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)\n"
        "props = P(6144, 1, 6144, 1)\n"
        "rc = libc.memorystatus_control(7, os.getpid(), 0, ctypes.byref(props), ctypes.sizeof(props))\n"
        "got = P()\n"
        "libc.memorystatus_control(8, os.getpid(), 0, ctypes.byref(got), ctypes.sizeof(got))\n"
        "read_fd, write_fd = os.pipe()\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.close(read_fd)\n"
        "    child = P()\n"
        "    libc.memorystatus_control(8, os.getpid(), 0, ctypes.byref(child), ctypes.sizeof(child))\n"
        "    os.write(write_fd, ('jetsam set=%s self=%s child=%s\\n' % (rc, got.a, child.a)).encode())\n"
        "    os.close(write_fd)\n"
        "    os._exit(0)\n"
        "os.close(write_fd)\n"
        "print(os.read(read_fd, 200).decode(), end='', flush=True)\n"
        "os.waitpid(pid, 0)\n"
    )
    completed = subprocess.run(["/usr/bin/python3", str(probe)], capture_output=True, text=True)
    print(completed.stdout.strip() or completed.stderr.strip() or "limit probe produced no output")
    probe.unlink(missing_ok=True)


def _probe_launch() -> None:
    payload = '{"op":"booted","device_id":"3C8BB98E-6383-446B-AF87-1E1282762A13"}'
    completed = subprocess.run(
        [
            "/usr/bin/sudo",
            "-n",
            "-u",
            "iosbroker",
            "/usr/bin/sudo",
            "-n",
            "-u",
            "root",
            "/Library/ios-worker/worker_cap",
        ],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    stdout = completed.stdout.strip().replace("\n", "")[:240]
    stderr = completed.stderr.strip().replace("\n", " ")[-240:]
    line = f"worker_cap rc={completed.returncode} out={stdout} err={stderr}"
    print(line)
    if completed.returncode != 0 or '"booted"' not in completed.stdout:
        raise SystemExit("worker launch path failed")


def _install_data() -> None:
    uid = _uid("iosbroker")
    DATA.mkdir(exist_ok=True)
    os.chown(DATA, uid, 20)
    DATA.chmod(0o700)
    _acl(DATA, ACL_TRAVERSE)
    for name, acl in (("work", ACL_WRITE), ("artifacts", ACL_WRITE), ("spool", ACL_READ), ("tmp", ACL_WRITE)):
        path = DATA / name
        path.mkdir(exist_ok=True)
        os.chown(path, uid, 20)
        path.chmod(0o700)
        _acl(path, acl)
    export = DATA / "export"
    export.mkdir(exist_ok=True)
    os.chown(export, uid, 20)
    export.chmod(0o700)
    subprocess.run(["/bin/chmod", "-N", str(export)], check=False)
    token = _secret_file(BROKER_DIR / "token", uid)
    operator = _secret_file(BROKER_DIR / "operator-token", uid)
    if _read_secret(operator) == _read_secret(token):
        operator.unlink()
        operator = _secret_file(operator, uid)
    import json

    broker = {
        "worker_config": str(LIBRARY / "worker.json"),
        "listen_host": "tailscale",
        "listen_port": 8741,
        "token_file": str(token),
        "operator_token_file": str(operator),
        "simulator_idle_seconds": 600,
        "max_running_jobs": 1,
        "max_build_jobs": 2,
        "allow_loopback": False,
    }
    config = BROKER_DIR / "broker.json"
    config.write_text(json.dumps(broker, indent=2) + "\n")
    os.chown(config, uid, 20)
    config.chmod(0o600)
    log = BROKER_DIR / "broker.log"
    log.write_text("")
    os.chown(log, uid, 20)
    log.chmod(0o600)


def _secret_file(path: Path, uid: int) -> Path:
    if path.is_symlink():
        path.unlink()
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (secrets.token_hex(32) + "\n").encode())
        finally:
            os.close(fd)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit("secret file must be a regular file")
    os.chown(path, uid, 20)
    path.chmod(0o600)
    return path


def _read_secret(path: Path) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit("secret file must be a regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(fd)
        if current.st_ino != info.st_ino or current.st_dev != info.st_dev:
            raise SystemExit("secret file must be a regular file")
        return os.read(fd, 256).decode("utf-8")
    finally:
        os.close(fd)


def _install_sudoers(source: Path, scratch: Path) -> None:
    text = (source / "sudoers.fragment").read_text().splitlines()
    rules = [line for line in text if line and not line.startswith("#")]
    body = "\n".join(rules) + "\n"
    temporary = scratch / "sudoers"
    temporary.write_text(body)
    temporary.chmod(0o440)
    check = subprocess.run(["/usr/sbin/visudo", "-cf", str(temporary)], capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit(check.stderr[-400:] or "sudoers check failed")
    shutil.copyfile(temporary, SUDOERS_DST)
    os.chown(SUDOERS_DST, 0, 0)
    SUDOERS_DST.chmod(0o440)
    temporary.unlink(missing_ok=True)


def _install_daemon(source: Path) -> None:
    shutil.copyfile(source / "com.iosworker.broker.plist", PLIST_DST)
    os.chown(PLIST_DST, 0, 0)
    PLIST_DST.chmod(0o644)
    check = subprocess.run(["/usr/bin/plutil", "-lint", str(PLIST_DST)], capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit(check.stderr[-400:] or "plist lint failed")


def _remove_shared_copy() -> None:
    shared = Path("/Users/Shared/ios-worker")
    if shared.exists():
        shutil.rmtree(shared)


def _free_port() -> None:
    completed = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP:8741", "-sTCP:LISTEN", "-t"], capture_output=True, text=True)
    for line in completed.stdout.split():
        if line.isdigit():
            subprocess.run(["/bin/kill", line], check=False)


def _acl(path: Path, entry: str) -> None:
    subprocess.run(["/bin/chmod", "-N", str(path)], check=False)
    completed = subprocess.run(["/bin/chmod", "+a", entry, str(path)], capture_output=True, text=True)
    if completed.returncode != 0:
        raise SystemExit(f"ACL failed for {path}: {completed.stderr.strip()}")


def _user_exists(name: str) -> bool:
    return subprocess.run(["/usr/bin/id", name], capture_output=True).returncode == 0


def _uid(name: str) -> int:
    return int(subprocess.check_output(["/usr/bin/id", "-u", name], text=True).strip())


def _member(user: str, group: str) -> bool:
    completed = subprocess.run(
        ["/usr/bin/dsmemberutil", "checkmembership", "-U", user, "-G", group],
        capture_output=True,
        text=True,
    )
    return "is a member" in completed.stdout


def _next_uid() -> int:
    used = set()
    text = subprocess.check_output(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"], text=True)
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[-1].isdigit():
            used.add(int(parts[-1]))
    uid = 510
    while uid in used:
        uid += 1
    return uid


if __name__ == "__main__":
    sys.exit(main())
