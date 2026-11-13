"""Resource and launch-path limits for the broker and the iosagent worker.

The sudoers line names one interpreter and one script. This module is what
that script is allowed to do: fixed paths, a fixed environment, no shell, and
caps on disk, memory, processes, logs, and runtime.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

DISK_BUDGET = 20 * 1024 * 1024 * 1024
MEMORY_LIMIT = 6 * 1024 * 1024 * 1024
PROCESS_LIMIT = 512
LOG_CAP = 64 * 1024
STDOUT_CAP = 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
BUILD_TIMEOUT = 2700
PREPARE_TIMEOUT = 2700
TEST_TIMEOUT = 900
DEFAULT_TIMEOUT = 120

LIBRARY_ROOT = Path("/Library/ios-worker")
WORKER_EXEC = LIBRARY_ROOT / "worker_exec.py"
WORKER_CAP = LIBRARY_ROOT / "worker_cap"
TEMP_ROOT = LIBRARY_ROOT / "data" / "tmp"
BROKER_USER = "iosbroker"
AGENT_USER = "iosagent"
CODE_FILES = (
    "tart_lease.py",
    "egress_policy.py",
    "http_policy.py",
    "host_egress.py",
    "vm_transport.py",
    "vm_service.py",
    "vm_runner.py",
    "vm_launch.py",
    "owner_menu.py",
    "audit.py",
    "policy.py",
    "config.py",
    "memory.py",
    "tarsafe.py",
    "containment.py",
    "worker_exec.py",
    "workspace.py",
    "guest_guard.py",
    "runner.py",
    "isolated_runner.py",
    "execution_policy.py",
    "native_runner.py",
    "scheduler.py",
    "api.py",
    "broker.py",
    "cli.py",
)

SUDO_ARGV = [
    "/usr/bin/sudo",
    "-n",
    "-u",
    "root",
    str(WORKER_CAP),
]

BROKER_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def pin_sys_path(existing: list[str], root: str, cwd: str) -> list[str]:
    """Keep the code directory and drop the working directory and empty entries."""
    root_resolved = str(Path(root).resolve())
    cwd_resolved = str(Path(cwd).resolve())
    kept: list[str] = []
    for entry in existing:
        if not entry:
            continue
        try:
            resolved = str(Path(entry).resolve())
        except OSError:
            continue
        if resolved == cwd_resolved and resolved != root_resolved:
            continue
        if resolved == root_resolved or entry in kept:
            continue
        kept.append(entry)
    return [root_resolved] + kept


def install_import_path() -> None:
    import sys

    root = str(Path(__file__).resolve().parent)
    sys.path[:] = pin_sys_path(list(sys.path), root, os.getcwd())


def worker_child_env(developer_dir: str) -> dict[str, str]:
    return {
        "HOME": "/Users/iosagent",
        "USER": AGENT_USER,
        "LOGNAME": AGENT_USER,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "DEVELOPER_DIR": developer_dir,
        "TMPDIR": str(TEMP_ROOT),
        "CLANG_MODULE_CACHE_PATH": str(TEMP_ROOT / "clang"),
        "MODULE_CACHE_DIR": str(TEMP_ROOT / "clang"),
        "LANG": "C",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "NSUnbufferedIO": "YES",
    }


def apply_rlimits() -> None:
    """Lower the process count. Children inherit rlimits across exec.

    This macOS rejects any finite RLIMIT_AS, RLIMIT_DATA, or RLIMIT_RSS, so a
    6 GB cap cannot be expressed there. launchd sets that cap on the broker,
    and worker_cap sets it on the worker before dropping to iosagent.
    """
    import resource

    for name, value in (
        ("RLIMIT_AS", MEMORY_LIMIT),
        ("RLIMIT_DATA", MEMORY_LIMIT),
        ("RLIMIT_RSS", MEMORY_LIMIT),
        ("RLIMIT_NPROC", PROCESS_LIMIT),
    ):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            _soft, hard = resource.getrlimit(limit)
            chosen = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(limit, (chosen, chosen))
        except (ValueError, OSError):
            continue
    try:
        os.nice(5)
    except OSError:
        pass
    _jetsam_limit(MEMORY_LIMIT // (1024 * 1024))


def _jetsam_limit(limit_mb: int) -> None:
    """Ask memorystatus for a 6 GB jetsam cap. Failure leaves the rlimit in place."""
    try:
        import ctypes

        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        # MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT: flags argument is the limit in MB.
        command = 6
        libc.memorystatus_control(ctypes.c_uint32(command), ctypes.c_int32(os.getpid()), ctypes.c_uint32(limit_mb), None, ctypes.c_size_t(0))
    except Exception:
        return


def directory_size(roots: list[Path]) -> int:
    """Allocated bytes under the roots, counting each inode once.

    Xcode's compilation cache is sparse: a file can report a logical size of
    16 GB while occupying a few kilobytes. The budget is real disk usage.
    Symlinks are not followed.
    """
    total = 0
    seen: set[tuple[int, int]] = set()
    for root in roots:
        try:
            if not root.exists() or root.is_symlink():
                continue
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [name for name in dirnames if not os.path.islink(os.path.join(dirpath, name))]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    continue
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                key = (info.st_dev, info.st_ino)
                if key in seen:
                    continue
                seen.add(key)
                total += info.st_blocks * 512
            if total > DISK_BUDGET:
                return total
    return total


def kill_descendants(pid: int) -> None:
    children = _children_by_parent()
    stack = list(children.get(pid, []))
    ordered: list[int] = []
    while stack:
        current = stack.pop()
        ordered.append(current)
        stack.extend(children.get(current, []))
    for child in reversed(ordered):
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _children_by_parent() -> dict[int, list[int]]:
    try:
        text = subprocess.check_output(["/bin/ps", "-ax", "-o", "pid=,ppid="], text=True)
    except (OSError, subprocess.CalledProcessError):
        return {}
    children: dict[int, list[int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        children.setdefault(int(parts[1]), []).append(int(parts[0]))
    return children


class Tail:
    """Keep the newest bytes so a long compile retains its final errors."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()

    def extend(self, chunk: bytes) -> None:
        self.data.extend(chunk)
        extra = len(self.data) - self.limit
        if extra > 0:
            del self.data[:extra]

    def __bytes__(self) -> bytes:
        return bytes(self.data)


def copy_regular_file(source: Path, artifact_root: Path, dest_dir: Path, name: str, max_bytes: int) -> Path:
    """Copy a worker file into broker-only storage without following a symlink."""
    from policy import PolicyError

    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise PolicyError("invalid_id", "Artifact name is not allowed.")
    if source.parent.resolve() != artifact_root.resolve():
        raise PolicyError("path_escape", "Artifact is outside the artifact directory.")
    info = source.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PolicyError("path_escape", "Artifact must be a regular file owned by this export.")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(source_fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_ino != info.st_ino
            or current.st_dev != info.st_dev
        ):
            raise PolicyError("path_escape", "Artifact changed during export.")
        if current.st_size > max_bytes:
            raise PolicyError("too_large", "Artifact is too large.")
        dest_dir.mkdir(mode=0o700, exist_ok=True)
        dest = dest_dir / name
        dest_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            remaining = current.st_size
            while remaining > 0:
                chunk = os.read(source_fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(dest_fd, view)
                    view = view[written:]
        finally:
            os.close(dest_fd)
    finally:
        os.close(source_fd)
    try:
        os.unlink(source)
    except OSError:
        pass
    return dest


def read_regular_file(path: Path, root: Path, max_bytes: int) -> bytes:
    """Read an exported artifact. A symlink or a swapped inode is refused."""
    from policy import PolicyError

    if path.parent.resolve() != root.resolve():
        raise PolicyError("path_escape", "Artifact is outside broker storage.")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PolicyError("path_escape", "Artifact must be a regular file.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_ino != info.st_ino
            or current.st_dev != info.st_dev
            or current.st_size > max_bytes
        ):
            raise PolicyError("path_escape", "Artifact changed before it was read.")
        chunks = []
        remaining = current.st_size
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def run_contained(
    argv: list[str],
    *,
    timeout: int,
    env: dict[str, str],
    disk_roots: list[Path] | None = None,
    disk_budget: int = DISK_BUDGET,
    cwd: Path | str = "/tmp",
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess:
    if not argv or not argv[0].startswith("/") or any("\x00" in part or not isinstance(part, str) for part in argv):
        raise ValueError("refusing arguments")
    apply_rlimits()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(cwd),
        close_fds=True,
        start_new_session=False,
    )
    stdout = Tail(LOG_CAP)
    stderr = Tail(LOG_CAP)
    pumps = [
        _start_pump(process.stdout, stdout),
        _start_pump(process.stderr, stderr),
    ]
    if input_bytes is not None:
        def write_input():
            try:
                with process.stdin as stream:
                    stream.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass

        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()
        pumps.append(writer)
    start = time.monotonic()
    timed_out = False
    over_disk = False
    try:
        while process.poll() is None:
            if time.monotonic() - start > timeout:
                timed_out = True
                kill_descendants(process.pid)
                break
            if disk_roots and directory_size(list(disk_roots)) > disk_budget:
                over_disk = True
                kill_descendants(process.pid)
                break
            time.sleep(0.2)
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            kill_descendants(process.pid)
            process.wait(timeout=5)
        for pump in pumps:
            pump.join(timeout=2)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()
    if timed_out:
        detail = (bytes(stdout) + b"\n" + bytes(stderr))[-(LOG_CAP - 128):].decode("utf-8", "replace").strip()
        raise TimeoutError(f"{detail}\n{Path(argv[0]).name} timed out after {timeout} seconds".lstrip())
    if over_disk:
        raise RuntimeError("storage_limit")
    return subprocess.CompletedProcess(argv, process.returncode, bytes(stdout), bytes(stderr))


def _start_pump(pipe, sink: Tail):
    def _pump() -> None:
        if pipe is None:
            return
        fd = pipe.fileno()
        os.set_blocking(fd, False)
        while True:
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                if pipe.closed:
                    return
                time.sleep(0.05)
                continue
            if not chunk:
                return
            sink.extend(chunk)

    thread = threading.Thread(target=_pump, daemon=True)
    thread.start()
    return thread


def launch_path_problems(root: Path = LIBRARY_ROOT) -> list[str]:
    """Return reasons the privileged script path is writable by an untrusted user."""
    problems: list[str] = []
    if not root.is_dir():
        return [f"{root} is missing"]
    info = root.lstat()
    if info.st_uid != 0:
        problems.append(f"{root} is not owned by root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        problems.append(f"{root} is writable by group or other")
    problems.extend(_acl_write_problems(root, allow_data=True))
    for name in CODE_FILES:
        path = root / name
        if not path.is_file():
            problems.append(f"{path} is missing")
            continue
        file_info = path.lstat()
        if file_info.st_uid != 0:
            problems.append(f"{path} is not owned by root")
        if stat.S_IMODE(file_info.st_mode) & 0o022:
            problems.append(f"{path} is writable by group or other")
        if stat.S_ISLNK(file_info.st_mode):
            problems.append(f"{path} is a symlink")
        problems.extend(_acl_write_problems(path, allow_data=False))
    data = root / "data"
    if data.exists() and data.lstat().st_uid == 0 and stat.S_IMODE(data.lstat().st_mode) & 0o002:
        problems.append(f"{data} is world-writable")
    return problems


def _acl_write_problems(path: Path, allow_data: bool) -> list[str]:
    if allow_data and path.name == "data":
        return []
    try:
        listing = subprocess.check_output(["/bin/ls", "-led", str(path)], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    problems = []
    for line in listing.splitlines():
        text = line.lower()
        if "iosagent" not in text and "iosbroker" not in text and "everyone" not in text and "staff" not in text:
            continue
        if any(right in text for right in ("add_file", "delete", "write", "append", "writeattr", "writesecurity")):
            if allow_data and "/data" in text:
                continue
            problems.append(f"writable ACL on {path}: {line.strip()}")
    return problems
