"""One running build or test, with a short queue of builds.

The personal simulator is never booted or shut down. When memory pressure or
swap activity says a worker simulator should stay off, the job waits until
POST /v1/jobs/<id>/approve.
"""

from __future__ import annotations

import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from containment import DISK_BUDGET, LOG_CAP
from memory import MemorySample, boot_needs_approval, build_needs_approval
from policy import PolicyError, check_device, require_id, require_scheme, require_under

Clock = Callable[[], float]
MemoryFn = Callable[[], MemorySample]
DiskFn = Callable[[], int]
BOOT_KINDS = frozenset({"launch", "uitest", "screenshot", "boot"})


class QueueFull(Exception):
    pass


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    revision_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    scheme: Optional[str] = None
    artifact_id: Optional[str] = None
    archive: Optional[str] = None
    approved: bool = False
    followup_id: Optional[str] = None
    error: Optional[str] = None
    log: str = ""
    result: dict = field(default_factory=dict)


class Scheduler:
    def __init__(
        self,
        runner,
        memory: MemoryFn,
        *,
        allowlist: set[str],
        denylist: set[str],
        default_device: str,
        clock: Clock,
        artifact_root: Path,
        max_running: int = 1,
        max_build_jobs: int = 2,
        max_pending_jobs: int = 8,
        idle_seconds: float = 600.0,
        disk_used: DiskFn | None = None,
        disk_budget: int = DISK_BUDGET,
    ) -> None:
        self.runner = runner
        self.memory = memory
        self.allowlist = {item.upper() for item in allowlist}
        self.denylist = {item.upper() for item in denylist}
        self.default_device = check_device(default_device, self.allowlist, self.denylist)
        self.clock = clock
        self.artifact_root = artifact_root
        self.max_running = max_running
        self.max_build_jobs = max_build_jobs
        self.max_pending_jobs = max_pending_jobs
        self.idle_seconds = idle_seconds
        self.disk_used = disk_used or (lambda: 0)
        self.disk_budget = disk_budget
        self.last_sample: Optional[MemorySample] = None
        self.jobs: dict[str, Job] = {}
        self.order: list[str] = []
        self.revisions: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.artifacts: dict[str, str] = {}
        self.running_ids: set[str] = set()
        self._previous_memory: Optional[MemorySample] = None
        self._last_busy = clock()
        self._lock = threading.Lock()
        self._wake = threading.Event()

    def add_revision(self, revision_id: str, archive_path: str) -> None:
        require_id(revision_id, "revision")
        with self._lock:
            self.revisions[revision_id] = {"status": "uploaded", "archive": archive_path}

    def submit_ingest(self, revision_id: str) -> Job:
        require_id(revision_id, "revision")
        with self._lock:
            revision = self.revisions.get(revision_id)
            if revision is None:
                raise KeyError(revision_id)
            job = Job(id=_new_id(), kind="ingest", revision_id=revision_id, archive=revision["archive"])
            self._put_locked(job)
        self._wake.set()
        return job

    def submit_build(self, revision_id: str, scheme: Optional[str]) -> Job:
        require_id(revision_id, "revision")
        if scheme is not None:
            require_scheme(scheme)
        with self._lock:
            job = Job(id=_new_id(), kind="build", revision_id=revision_id, scheme=scheme, device_id=self.default_device)
            self._put_locked(job)
        self._wake.set()
        return job

    def submit_launch(self, revision_id: str, device_id: Optional[str]) -> tuple[Job, str]:
        device = self._device(device_id)
        session_id = _new_id()
        job = Job(
            id=_new_id(),
            kind="launch",
            revision_id=require_id(revision_id, "revision"),
            session_id=session_id,
            device_id=device,
        )
        with self._lock:
            self._put_locked(job)
            self.sessions[session_id] = {"job_id": job.id, "device_id": device, "revision_id": revision_id}
        self._wake.set()
        return job, session_id

    def submit_screenshot(self, session_id: str) -> Job:
        session = self._session(session_id)
        job = Job(
            id=_new_id(),
            kind="screenshot",
            session_id=session_id,
            device_id=session["device_id"],
            revision_id=session["revision_id"],
        )
        job.artifact_id = job.id
        return self._enqueue(job)

    def submit_uitest(self, revision_id: str, scheme: Optional[str], device_id: Optional[str]) -> Job:
        if scheme is not None:
            require_scheme(scheme)
        return self._enqueue(
            Job(
                id=_new_id(),
                kind="uitest",
                revision_id=require_id(revision_id, "revision"),
                scheme=scheme,
                device_id=self._device(device_id),
            )
        )

    def submit_logs(self, session_id: str) -> Job:
        session = self._session(session_id)
        return self._enqueue(
            Job(
                id=_new_id(),
                kind="logs",
                session_id=session_id,
                device_id=session["device_id"],
                revision_id=session["revision_id"],
            )
        )

    def submit_reset(self, revision_id: Optional[str], device_id: Optional[str]) -> Job:
        if revision_id is not None:
            require_id(revision_id, "revision")
        return self._enqueue(
            Job(id=_new_id(), kind="reset", revision_id=revision_id, device_id=self._device(device_id))
        )

    def approve(self, job_id: str) -> Job:
        with self._lock:
            job = self._job_locked(job_id)
            job.approved = True
            if job.status == "waiting_for_approval":
                job.status = "queued"
        self._wake.set()
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            return self._copy(self._job_locked(job_id))

    def artifact_path(self, artifact_id: str) -> str:
        require_id(artifact_id, "artifact")
        with self._lock:
            try:
                return self.artifacts[artifact_id]
            except KeyError as exc:
                raise KeyError(artifact_id) from exc

    def latest_log(self, session_id: str) -> str:
        require_id(session_id, "session")
        with self._lock:
            if session_id not in self.sessions:
                raise KeyError(session_id)
            texts = [
                job.log
                for job in self.jobs.values()
                if job.session_id == session_id and job.kind == "logs" and job.status == "succeeded"
            ]
        if not texts:
            raise KeyError(session_id)
        return texts[-1]

    def counts(self) -> dict:
        with self._lock:
            queued = sum(1 for job in self.jobs.values() if job.status in ("queued", "waiting_for_approval"))
            return {"running": len(self.running_ids), "queued": queued}

    def step(self) -> None:
        to_shutdown: list[str] = []
        with self._lock:
            if len(self.running_ids) < self.max_running:
                sample = self.memory()
                previous = self._previous_memory
                self._previous_memory = sample
                self.last_sample = sample
                for job_id in list(self.order):
                    job = self.jobs[job_id]
                    if job.status not in ("queued", "waiting_for_approval"):
                        continue
                    decision = self._admit(job, sample, previous)
                    if decision == "skip":
                        continue
                    if decision == "wait":
                        job.status = "waiting_for_approval"
                        continue
                    self._start_locked(job)
                    break
            to_shutdown = self._idle_devices_locked()
        for device in to_shutdown:
            try:
                self.runner.shutdown(device)
            except PolicyError:
                continue
            except Exception as exc:
                sys.stderr.write("idle shutdown failed: " + exc.__class__.__name__ + "\n")

    def _admit(self, job: Job, sample: MemorySample, previous: Optional[MemorySample]) -> str:
        if job.kind in ("build", "launch", "uitest"):
            revision = self.revisions.get(job.revision_id or "")
            if revision is None or revision["status"] != "ready":
                return "skip"
        if job.kind in ("screenshot", "logs"):
            ready = self._session_ready(job.session_id)
            if ready == "missing":
                job.status = "failed"
                job.error = "unknown session"
                return "skip"
            if ready == "failed":
                job.status = "failed"
                job.error = "session unavailable"
                return "skip"
            if ready != "ready":
                return "skip"
        if self._needs_boot(job) and boot_needs_approval(previous, sample, job.approved):
            return "wait"
        if job.kind == "build" and build_needs_approval(previous, sample, job.approved):
            return "wait"
        return "allow"

    def _session_ready(self, session_id: Optional[str]) -> str:
        if not session_id or session_id not in self.sessions:
            return "missing"
        launch = self.jobs.get(self.sessions[session_id]["job_id"])
        if launch is None or launch.status == "failed":
            return "failed"
        if launch.status == "succeeded":
            return "ready"
        return "pending"

    def _needs_boot(self, job: Job) -> bool:
        if job.kind not in BOOT_KINDS or not job.device_id:
            return False
        return not self.runner.is_booted(job.device_id)

    def _start_locked(self, job: Job) -> None:
        job.status = "running"
        self.running_ids.add(job.id)
        self._last_busy = self.clock()
        threading.Thread(target=self._execute, args=(job.id,), daemon=True).start()

    def _execute(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs[job_id]
        try:
            if self.disk_used() > self.disk_budget:
                raise PolicyError("storage_limit", "Worker storage is over the 20 GB budget.")
            if job.kind == "build" and job.device_id:
                self.runner.shutdown(job.device_id)
            result = self.runner.run(job)
            log = str(result.get("log", ""))[-LOG_CAP:] if isinstance(result, dict) else ""
            with self._lock:
                current = self.jobs[job_id]
                current.result = result if isinstance(result, dict) else {"ok": True}
                current.log = log
                self._register_artifact(current)
                if current.kind == "ingest" and current.revision_id in self.revisions:
                    self.revisions[current.revision_id]["status"] = "ready"
                if current.kind == "build" and current.device_id:
                    current.followup_id = self._queue_restart_locked(current.device_id)
                current.status = "succeeded"
        except Exception as exc:
            with self._lock:
                current = self.jobs[job_id]
                current.status = "failed"
                detail = str(exc).strip().splitlines()
                current.error = (detail[-1][:300] if detail else exc.__class__.__name__)
                if current.kind == "ingest" and current.revision_id in self.revisions:
                    self.revisions[current.revision_id]["status"] = "failed"
        finally:
            with self._lock:
                self.running_ids.discard(job_id)
                self._last_busy = self.clock()
            self._wake.set()

    def _register_artifact(self, job: Job) -> None:
        artifact = job.result.get("artifact_id")
        path = job.result.get("artifact_path")
        if not isinstance(artifact, str) or not isinstance(path, str):
            return
        require_id(artifact, "artifact")
        stored = require_under(Path(path), self.artifact_root)
        self.artifacts[artifact] = str(stored)
        job.artifact_id = artifact

    def _idle_devices_locked(self) -> list[str]:
        if self.running_ids:
            return []
        if self.clock() - self._last_busy < self.idle_seconds:
            return []
        if any(
            job.status in ("queued", "waiting_for_approval", "running") and job.kind in BOOT_KINDS
            for job in self.jobs.values()
        ):
            return []
        chosen = []
        for device in sorted(self.allowlist):
            try:
                check_device(device, self.allowlist, self.denylist)
            except PolicyError:
                continue
            if self.runner.is_booted(device):
                chosen.append(device)
        if chosen:
            self._last_busy = self.clock()
        return chosen

    def _enqueue(self, job: Job) -> Job:
        with self._lock:
            self._put_locked(job)
        self._wake.set()
        return job

    def _queue_restart_locked(self, device_id: str) -> Optional[str]:
        try:
            device_id = check_device(device_id, self.allowlist, self.denylist)
        except PolicyError:
            return None
        for item in self.jobs.values():
            if item.kind == "boot" and item.device_id == device_id and item.status in ("queued", "waiting_for_approval", "running"):
                return item.id
        job = Job(id=_new_id(), kind="boot", device_id=device_id)
        try:
            self._put_locked(job)
        except QueueFull:
            return None
        return job.id

    def _put_locked(self, job: Job) -> None:
        pending = sum(
            1
            for item in self.jobs.values()
            if item.status in ("queued", "waiting_for_approval", "running")
        )
        if pending >= self.max_pending_jobs:
            raise QueueFull("job queue is full")
        if job.kind == "build" and self._open_builds() >= self.max_build_jobs:
            raise QueueFull("build queue is full")
        self.jobs[job.id] = job
        self.order.append(job.id)

    def pressure_name(self) -> str:
        with self._lock:
            if self.last_sample is None:
                return "unknown"
            return self.last_sample.pressure_name

    def _device(self, device_id: Optional[str]) -> str:
        if device_id is None:
            return self.default_device
        return check_device(device_id, self.allowlist, self.denylist)

    def _session(self, session_id: str) -> dict:
        require_id(session_id, "session")
        with self._lock:
            try:
                return dict(self.sessions[session_id])
            except KeyError as exc:
                raise KeyError(session_id) from exc

    def _job_locked(self, job_id: str) -> Job:
        try:
            return self.jobs[job_id]
        except KeyError as exc:
            raise KeyError(job_id) from exc

    def _copy(self, job: Job) -> Job:
        return Job(
            id=job.id,
            kind=job.kind,
            status=job.status,
            revision_id=job.revision_id,
            session_id=job.session_id,
            device_id=job.device_id,
            scheme=job.scheme,
            artifact_id=job.artifact_id,
            archive=job.archive,
            approved=job.approved,
            followup_id=job.followup_id,
            error=job.error,
            log=job.log,
            result=dict(job.result),
        )

    def _open_builds(self) -> int:
        return sum(
            1
            for job in self.jobs.values()
            if job.kind == "build" and job.status in ("queued", "waiting_for_approval", "running")
        )

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.step()
            except Exception as exc:
                sys.stderr.write("scheduler step failed: " + exc.__class__.__name__ + "\n")
            self._wake.wait(0.5)
            self._wake.clear()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]
