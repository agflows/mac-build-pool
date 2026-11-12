"""Install the broker as iosbroker and the worker code as root-owned files.

Run this as root from outside ~/Documents. It does not print the API token
or the generated account password.
"""

from __future__ import annotations

import os
import argparse
import json
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
    "tart_lease.py",
    "egress_policy.py",
    "http_policy.py",
    "host_egress.py",
    "vm_transport.py",
    "vm_service.py",
    "vm_runner.py",
    "vm_launch.py",
    "policy.py",
    "config.py",
    "memory.py",
    "tarsafe.py",
    "containment.py",
    "worker_exec.py",
    "workspace.py",
    "guest_guard.py",
    "cli.py",
    "runner.py",
    "isolated_runner.py",
    "execution_policy.py",
    "native_runner.py",
    "scheduler.py",
    "api.py",
    "broker.py",
    "audit.py",
)


def main() -> int:
    os.chdir("/tmp")
    if os.geteuid() != 0:
        sys.stderr.write("install_system.py must run as root\n")
        return 1
    args = parse_args(sys.argv[1:])
    source = Path(args.source).resolve()
    scratch = _private_dir()
    try:
        return _install(source, scratch, native=args.execution_mode == "native-user")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', default=str(Path(__file__).resolve().parent))
    parser.add_argument('--execution-mode', choices=['isolated-only', 'native-user'], default='isolated-only')
    parser.add_argument('--accept-native-risk', action='store_true',
                        help='Accept account separation without VM or network isolation; simulator APIs only')
    args = parser.parse_args(argv)
    if (args.execution_mode == 'native-user') != args.accept_native_risk:
        parser.error('native-user requires --accept-native-risk; it is not valid with isolated-only')
    return args


def _install(source: Path, scratch: Path, native: bool = False) -> int:
    if native:
        _validate_native_account()
        _prepare_native_helper(source, scratch)
    # Upgrade only the named service; never kill arbitrary processes using a port.
    subprocess.run(["/bin/launchctl", "bootout", "system/com.iosworker.broker"], check=False)
    _ensure_user()
    _install_code(source)
    _install_data()
    if native:
        _install_native_helper(scratch)
        _install_native_data_access()
    else:
        _retire_native_host_launcher()
    _write_execution_policy(native)
    _install_daemon(source)
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
    print("Native-user mode: account separation only, no VM or network isolation. Signing and USB APIs are disabled."
          if native else "Host native execution is disabled. A reviewed isolation-executor must be installed separately.")
    return 0


def _validate_native_account() -> None:
    import pwd
    try:
        account = pwd.getpwnam('iosagent')
    except KeyError as exc:
        raise SystemExit('Provision a dedicated non-admin iosagent account before native installation') from exc
    home = Path('/Users/iosagent')
    if account.pw_uid == 0 or account.pw_dir != str(home) or _member('iosagent', 'admin'):
        raise SystemExit('iosagent must be a dedicated non-admin account with its own home')
    info = home.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_mode & 0o077:
        raise SystemExit('The dedicated iosagent home must be owned by iosagent with mode 700')


def _prepare_native_helper(source: Path, scratch: Path) -> None:
    # Compile only this reviewed, fixed launcher, never uploaded project source.
    subprocess.run(['/usr/bin/clang', '-O2', '-Wall', '-Werror', '-o', str(scratch / 'worker_cap'),
                    str(source / 'worker_cap.c')], check=True)
    fragment = scratch / 'ios-worker.sudoers'
    fragment.write_text('iosbroker ALL=(root) NOPASSWD: /Library/ios-worker/worker_cap ""\nDefaults:iosbroker !requiretty\n')
    fragment.chmod(0o440)
    subprocess.run(['/usr/sbin/visudo', '-cf', str(fragment)], check=True)


def _install_native_helper(scratch: Path) -> None:
    for source, target, mode in [(scratch / 'worker_cap', LIBRARY / 'worker_cap', 0o755),
                                 (scratch / 'ios-worker.sudoers', SUDOERS_DST, 0o440)]:
        if target.is_symlink():
            raise SystemExit('Refusing an unexpected native launcher symlink')
        shutil.copyfile(source, target)
        os.chown(target, 0, 0)
        target.chmod(mode)
        subprocess.run(['/bin/chmod', '-N', str(target)], check=True)


def _install_native_data_access() -> None:
    # Traversal only at the parent. Broker exports and credentials remain private.
    subprocess.run(['/bin/chmod', '+a', 'iosagent allow search', str(DATA)], check=True)
    for name in ('work', 'artifacts', 'tmp'):
        path = DATA / name
        subprocess.run(['/bin/chmod', '+a',
                        'iosagent allow read,write,execute,delete,add_file,add_subdirectory,file_inherit,directory_inherit', str(path)], check=True)
        subprocess.run(['/bin/chmod', '+a',
                        'iosbroker allow read,execute,file_inherit,directory_inherit', str(path)], check=True)
    subprocess.run(['/bin/chmod', '+a', 'iosagent allow read,execute,file_inherit,directory_inherit',
                    str(DATA / 'spool')], check=True)


def _write_execution_policy(native: bool) -> None:
    from execution_policy import NATIVE_ACK
    data = {'mode': 'native-user', 'acknowledgement': NATIVE_ACK} if native else {'mode': 'isolated-only'}
    fd, name = tempfile.mkstemp(dir=LIBRARY, prefix='.execution-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, LIBRARY / 'execution.json')
    finally:
        if os.path.exists(name):
            os.unlink(name)


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
    if LIBRARY.is_symlink():
        raise SystemExit('Refusing an unexpected code-root symlink')
    LIBRARY.mkdir(exist_ok=True)
    os.chown(LIBRARY, 0, 0)
    LIBRARY.chmod(0o755)
    subprocess.run(["/bin/chmod", "-N", str(LIBRARY)], check=False)
    for name in CODE:
        target = LIBRARY / name
        if target.is_symlink():
            raise SystemExit('Refusing an unexpected code-file symlink')
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
        "allow_dependency_install": False,
        "toolchain": {},
    }
    import json

    path = LIBRARY / "worker.json"
    # Preserve owner decisions (including consent, toolchain paths and device IDs).
    # Never upgrade by importing configuration writable by a job account.
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise SystemExit("Existing worker.json must be a root-owned, non-writable regular file")
        worker.update(json.loads(path.read_text()))
    path.write_text(json.dumps(worker, indent=2) + "\n")
    os.chown(path, 0, 0)
    path.chmod(0o644)
    subprocess.run(["/bin/chmod", "-N", str(path)], check=True)


def _retire_native_host_launcher() -> None:
    """Remove this project\'s old host sudo grant; never replace it with a shell grant."""
    if SUDOERS_DST.exists() or SUDOERS_DST.is_symlink():
        info = SUDOERS_DST.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise SystemExit("Refusing to remove an unexpected sudoers path")
        SUDOERS_DST.unlink()
    binary = LIBRARY / "worker_cap"
    if binary.exists() or binary.is_symlink():
        if binary.is_symlink() or binary.lstat().st_uid != 0:
            raise SystemExit("Refusing to remove an unexpected host helper")
        binary.unlink()


def _install_data() -> None:
    for path in (DATA,*(DATA / name for name in ('work','artifacts','spool','tmp','export'))):
        if path.is_symlink():
            raise SystemExit('Refusing an unexpected data-directory symlink')
    uid = _uid("iosbroker")
    DATA.mkdir(exist_ok=True)
    os.chown(DATA, uid, 20)
    DATA.chmod(0o700)
    # No native job account may traverse host staging. Only the broker/controller
    # handles bounded transfer; all extraction and project work is guest-side.
    subprocess.run(["/bin/chmod", "-N", str(DATA)], check=True)
    for name in ("work", "artifacts", "spool", "tmp"):
        path = DATA / name
        path.mkdir(exist_ok=True)
        os.chown(path, uid, 20)
        path.chmod(0o700)
        subprocess.run(["/bin/chmod", "-N", str(path)], check=True)
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


def _install_daemon(source: Path) -> None:
    shutil.copyfile(source / "com.iosworker.broker.plist", PLIST_DST)
    os.chown(PLIST_DST, 0, 0)
    PLIST_DST.chmod(0o644)
    check = subprocess.run(["/usr/bin/plutil", "-lint", str(PLIST_DST)], capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit(check.stderr[-400:] or "plist lint failed")


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
