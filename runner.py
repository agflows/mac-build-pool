"""Guest-only helper transport; NEVER the personal Mac host execution backend.

The host broker uses IsolatedRunner instead. This remains a reference for a
protected helper inside a disposable guest, not a host fallback.

Run a worker operation through the fixed root helper.

sudo is allowed to execute one argv and nothing else. The helper drops to
iosagent before Python starts. The broker environment is not forwarded.
stdin carries the job JSON and no other file descriptors.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time

from containment import BROKER_ENV, BUILD_TIMEOUT, PREPARE_TIMEOUT, DEFAULT_TIMEOUT, LOG_CAP, STDOUT_CAP, SUDO_ARGV, TEST_TIMEOUT
from policy import PolicyError, check_device

IOSAGENT_USER = "iosagent"


class WorkerFailure(RuntimeError):
    def __init__(self, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.log = message[-LOG_CAP:]


class SudoRunner:
    def __init__(self, allowlist: set[str], denylist: set[str], argv: list[str] | None = None) -> None:
        self.allowlist = {item.upper() for item in allowlist}
        self.denylist = {item.upper() for item in denylist}
        self.argv = list(argv or SUDO_ARGV)
        if self.argv != SUDO_ARGV:
            raise PolicyError("bad_argv", "The worker launch command is fixed.")

    def is_booted(self, device_id: str) -> bool:
        device_id = check_device(device_id, self.allowlist, self.denylist)
        result = self._call({"op": "booted", "device_id": device_id}, timeout=30)
        return bool(result.get("booted"))

    def shutdown(self, device_id: str) -> None:
        device_id = check_device(device_id, self.allowlist, self.denylist)
        self._call({"op": "shutdown", "device_id": device_id}, timeout=60)

    def run(self, job) -> dict:
        payload = {
            "op": job.kind,
            "job_id": job.id,
            "revision_id": job.revision_id,
            "session_id": job.session_id,
            "device_id": job.device_id,
            "scheme": job.scheme,
            "recipe": job.recipe,
            "public_env": job.public_env,
            "configuration": job.configuration,
            "for_testing": job.for_testing,
            "artifact_id": job.artifact_id,
            "archive": job.archive,
            "approved": job.approved,
        }
        timeout = {"prepare": PREPARE_TIMEOUT, "build": BUILD_TIMEOUT + 60, "uitest": TEST_TIMEOUT + 480,
                   "launch": 600, "boot": 420, "screenshot": 480, "reset": 300}.get(job.kind, DEFAULT_TIMEOUT)
        return self._call(payload, timeout=timeout)

    def _call(self, payload: dict, timeout: int) -> dict:
        if payload.get("device_id"):
            payload["device_id"] = check_device(payload["device_id"], self.allowlist, self.denylist)
        if self.argv != SUDO_ARGV:
            raise PolicyError("bad_argv", "The worker launch command is fixed.")
        process = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=BROKER_ENV,
            cwd="/tmp",
            close_fds=True,
            start_new_session=True,
        )
        stdout, stderr = _read_capped(process, json.dumps(payload).encode(), timeout)
        if process.returncode != 0:
            raise _failure_from_stderr(stderr, process.returncode)
        try:
            return json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise WorkerFailure("worker returned no JSON", process.returncode) from exc


def _failure_from_stderr(stderr: bytes, returncode: int) -> WorkerFailure:
    text = stderr.decode("utf-8", "replace").strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        message = str(payload.get("message") or payload.get("error") or "worker failed")
        exit_code = payload.get("exitCode")
        if not isinstance(exit_code, int):
            exit_code = returncode
        return WorkerFailure(message, exit_code)
    return WorkerFailure(text[-LOG_CAP:] or f"worker exited {returncode}", returncode)


def _read_capped(process: subprocess.Popen, payload: bytes, timeout: int) -> tuple[bytes, bytes]:
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    process.stdin.write(payload[:STDOUT_CAP])
    process.stdin.close()
    os.set_blocking(process.stdout.fileno(), False)
    os.set_blocking(process.stderr.fileno(), False)
    stdout = bytearray()
    stderr = bytearray()
    start = time.monotonic()
    while process.poll() is None:
        if time.monotonic() - start > timeout:
            _kill_group(process.pid)
            process.wait(timeout=5)
            raise RuntimeError("worker timed out")
        _take(process.stdout, stdout)
        _take(process.stderr, stderr)
        if len(stdout) > STDOUT_CAP or len(stderr) > STDOUT_CAP:
            _kill_group(process.pid)
            process.wait(timeout=5)
            raise RuntimeError("worker output exceeded the cap")
        time.sleep(0.05)
    _take(process.stdout, stdout)
    _take(process.stderr, stderr)
    return bytes(stdout), bytes(stderr)


def _take(pipe, sink: bytearray) -> None:
    while len(sink) <= STDOUT_CAP:
        try:
            chunk = os.read(pipe.fileno(), 65536)
        except BlockingIOError:
            return
        if not chunk:
            return
        room = STDOUT_CAP + 1 - len(sink)
        sink.extend(chunk[:room])
        if len(chunk) > room:
            return


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def guard_device(device_id: str, allowlist: set[str], denylist: set[str]) -> str:
    return check_device(device_id, allowlist, denylist)
