"""Owner-only execution-mode selection. Missing policy always means VM-only.

Neither API input, broker.json, worker.json nor environment variables can opt in
native execution. That choice lives in a separate protected host policy file.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

from policy import PolicyError

POLICY_PATH = Path('/Library/ios-worker/execution.json')
ISOLATED = 'isolated-only'
NATIVE = 'native-user'
NATIVE_ACK = 'I accept account separation without VM or network isolation.'
MAX_POLICY_BYTES = 4096


def require_protected_file(path: Path, executable: bool = False) -> None:
    """Reject replaceable paths, symlinks and writable ACLs, including ancestors."""
    for current in [path, *path.parents]:
        info = current.lstat()
        expected_type = stat.S_ISREG if current == path else stat.S_ISDIR
        if not expected_type(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PolicyError('unsafe_execution_policy', 'Execution policy/helper path is not root-controlled.')
        # POSIX modes alone miss macOS ACL grants. Fail closed if we cannot inspect.
        try:
            result = subprocess.run(['/bin/ls', '-led', str(current)], capture_output=True, text=True, timeout=5)
        except subprocess.SubprocessError as exc:
            raise PolicyError('unsafe_execution_policy', 'Cannot inspect execution-policy ACLs.') from exc
        if result.returncode != 0:
            raise PolicyError('unsafe_execution_policy', 'Cannot inspect execution-policy ACLs.')
        for line in result.stdout.splitlines()[1:]:
            if ' allow ' in line and any(right in line for right in ('write', 'append', 'delete', 'add_file', 'add_subdirectory', 'chown')):
                raise PolicyError('unsafe_execution_policy', 'Writable ACL on execution policy/helper path.')
        if os.geteuid() != 0 and os.access(current, os.W_OK):
            raise PolicyError('unsafe_execution_policy', 'Execution policy/helper path is writable by caller.')
    if executable and not os.access(path, os.X_OK):
        raise PolicyError('unsafe_execution_policy', 'Worker helper is not executable.')


def parse_policy(data: object) -> str:
    if not isinstance(data, dict) or set(data) - {'mode', 'acknowledgement'}:
        raise PolicyError('bad_execution_policy', 'Invalid execution policy fields.')
    mode = data.get('mode')
    if mode == ISOLATED and 'acknowledgement' not in data:
        return ISOLATED
    if mode == NATIVE and data.get('acknowledgement') == NATIVE_ACK:
        return NATIVE
    raise PolicyError('bad_execution_policy', 'Native mode requires explicit owner acknowledgement; unknown modes fail closed.')


def execution_mode() -> str:
    try:
        POLICY_PATH.lstat()
    except FileNotFoundError:
        return ISOLATED
    require_protected_file(POLICY_PATH)
    fd = os.open(POLICY_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PolicyError('unsafe_execution_policy', 'Execution policy changed while opening.')
        data = os.read(fd, MAX_POLICY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError('bad_execution_policy', 'Execution policy exceeds its size limit.')
    try:
        return parse_policy(json.loads(data))
    except (ValueError, UnicodeError) as exc:
        raise PolicyError('bad_execution_policy', 'Execution policy is not valid JSON.') from exc


def require_worker_account() -> None:
    import grp
    import pwd
    try:
        account = pwd.getpwnam('iosagent')
        admin_gid = grp.getgrnam('admin').gr_gid
        groups = os.getgrouplist(account.pw_name, account.pw_gid)
    except (KeyError, OSError) as exc:
        raise PolicyError('worker_account', 'Cannot validate the dedicated worker account.') from exc
    if (account.pw_uid == 0 or account.pw_dir != '/Users/iosagent'
            or os.getuid() != account.pw_uid or os.geteuid() != account.pw_uid
            or admin_gid in groups or admin_gid in os.getgroups()):
        raise PolicyError('worker_account', 'Worker must run as the dedicated non-admin iosagent account.')


def require_worker_execution() -> str:
    require_worker_account()
    mode = execution_mode()
    if mode == ISOLATED:
        from guest_guard import require_macos_guest
        require_macos_guest()
    return mode


def require_native_config(cfg) -> None:
    root = Path('/Library/ios-worker/data')
    for field, name in [('workspace_root', 'work'), ('spool_root', 'spool'), ('artifact_root', 'artifacts')]:
        if getattr(cfg, field) != root / name:
            raise PolicyError('bad_execution_policy', 'Native storage must use the dedicated worker data roots.')
