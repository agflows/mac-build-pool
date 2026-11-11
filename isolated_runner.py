"""Host-side contract for a real isolated executor. No native fallback.

The VM/network controller is intentionally NOT implemented by a shell recipe or
an 'isolation=true' setting. Until the owner installs a reviewed controller at
EXECUTOR, jobs fail closed. See docs/ISOLATION_CONTRACT.md.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

from containment import BROKER_ENV, BUILD_TIMEOUT, PREPARE_TIMEOUT, DEFAULT_TIMEOUT, TEST_TIMEOUT
from policy import PolicyError, check_device
from runner import WorkerFailure, _read_capped, _failure_from_stderr

EXECUTOR = Path("/Library/ios-worker/isolation-executor")


class IsolatedRunner:
    def __init__(self, allowlist: set[str], denylist: set[str]):
        self.allowlist = allowlist
        self.denylist = denylist

    def installed(self) -> bool:
        """Presence/ownership only, NOT an attestation that isolation is correct."""
        try:
            self._require_controller()
        except (PolicyError, OSError):
            return False
        return True

    def _require_controller(self) -> None:
        try:
            info = EXECUTOR.lstat()
        except FileNotFoundError as exc:
            raise PolicyError("isolation_required", "Isolated executor is not installed. Native host execution is disabled; provision and validate the VM/network controller.") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not os.access(EXECUTOR, os.X_OK):
            raise PolicyError("unsafe_executor", "Isolation controller must be a root-owned, non-writable executable, not a symlink.")
        for parent in EXECUTOR.parents:
            current = parent.lstat()
            if stat.S_ISLNK(current.st_mode) or current.st_uid != 0 or current.st_mode & 0o022 or os.access(parent, os.W_OK):
                raise PolicyError("unsafe_executor", "Isolation controller parent is writable or untrusted.")
        if os.access(EXECUTOR, os.W_OK):
            raise PolicyError("unsafe_executor", "Broker must not be able to modify the isolation controller.")

    def _call(self, payload: dict, timeout: int) -> dict:
        self._require_controller()
        process = subprocess.Popen(
            [str(EXECUTOR)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd="/tmp", env={**BROKER_ENV, "HOME": "/Users/iosbroker", "USER": "iosbroker", "LOGNAME": "iosbroker"},
            close_fds=True, start_new_session=True,
        )
        stdout, stderr = _read_capped(process, json.dumps(payload).encode(), timeout)
        if process.returncode != 0:
            raise _failure_from_stderr(stderr, process.returncode)
        try:
            result = json.loads(stdout)
        except (ValueError, UnicodeError) as exc:
            raise WorkerFailure("Isolated executor returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise WorkerFailure("Isolated executor did not confirm successful execution")
        return result

    def run(self, job) -> dict:
        if job.device_id:
            check_device(job.device_id, self.allowlist, self.denylist)
        payload = {
            "op": job.kind, "job_id": job.id, "lease_id": job.lease_id,
            "revision_id": job.revision_id, "session_id": job.session_id,
            "device_id": job.device_id, "scheme": job.scheme, "recipe": job.recipe,
            "public_env": job.public_env, "configuration": job.configuration,
            "for_testing": job.for_testing, "artifact_id": job.artifact_id,
            "archive": job.archive, "approved": job.approved,
        }
        timeout = {"prepare": PREPARE_TIMEOUT, "build": BUILD_TIMEOUT + 60,
                   "uitest": TEST_TIMEOUT + 480, "launch": 600,
                   "boot": 420, "screenshot": 480, "reset": 300}.get(job.kind, DEFAULT_TIMEOUT)
        return self._call(payload, timeout)

    def is_booted(self, device_id: str) -> bool:
        device = check_device(device_id, self.allowlist, self.denylist)
        return bool(self._call({"op": "booted", "device_id": device}, 30).get("booted"))

    def shutdown(self, device_id: str) -> None:
        device = check_device(device_id, self.allowlist, self.denylist)
        self._call({"op": "shutdown", "device_id": device}, 90)
