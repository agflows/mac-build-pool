"""Scheduler policy: one running job, two builds, and no personal-simulator shutdown."""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory import PRESSURE_NORMAL, PRESSURE_URGENT, PRESSURE_WARNING, MemorySample
from policy import PolicyError, check_device
from scheduler import QueueFull, Scheduler

WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"
PERSONAL = "4D015300-4BAE-4E6D-89C9-BC4D454E4216"


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class Memory:
    def __init__(self, sample: MemorySample) -> None:
        self.sample = sample

    def __call__(self) -> MemorySample:
        return self.sample


class FakeRunner:
    def __init__(self, block: bool = False) -> None:
        self.started = []
        self.shutdowns = []
        self.probes = []
        self.booted = set()
        self.gate = threading.Event()
        self.entered = threading.Event()
        self.result = {"ok": True, "log": "ok"}
        self.failure = None
        if not block:
            self.gate.set()

    def is_booted(self, device_id: str) -> bool:
        self.probes.append(device_id)
        return device_id in self.booted

    def shutdown(self, device_id: str) -> None:
        self.shutdowns.append(device_id)
        check_device(device_id, {WORKER}, set())
        self.booted.discard(device_id)

    def run(self, job):
        self.started.append((job.kind, job.device_id))
        self.entered.set()
        if self.failure is not None:
            raise self.failure
        if not self.gate.wait(3):
            raise TimeoutError("runner was not released")
        if job.kind in {"launch", "uitest"}:
            self.booted.add(job.device_id)
        return dict(self.result)


class SchedulerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = FakeRunner()
        self.memory = Memory(MemorySample(PRESSURE_NORMAL, 0, 0))
        self.clock = Clock()
        self.scheduler = self._scheduler()
        self.addCleanup(self.runner.gate.set)

    def _scheduler(self, **kwargs) -> Scheduler:
        return Scheduler(
            self.runner,
            self.memory,
            allowlist={WORKER},
            denylist=set(),
            default_device=WORKER,
            clock=self.clock,
            artifact_root=Path("/tmp/ios-worker-test-artifacts"),
            **kwargs,
        )

    def _lease(self) -> str:
        return self.scheduler.acquire_lease()

    def _ready(self, revision: str = "rev0001") -> str:
        self.scheduler.revisions[revision] = {"status": "ready", "archive": ""}
        return revision

    def _wait_idle(self, job_id: str) -> None:
        for _ in range(100):
            if self.scheduler.get(job_id).status in {"succeeded", "failed"} and self.scheduler.counts()["running"] == 0:
                return
            time.sleep(0.01)
        self.fail("job did not finish")

    def test_third_build_is_rejected_and_a_test_can_still_queue(self) -> None:
        revision = self._ready()
        lease = self._lease()
        self.scheduler.submit_build(revision, None, lease)
        self.scheduler.submit_build(revision, None, lease)
        with self.assertRaises(QueueFull):
            self.scheduler.submit_build(revision, None, lease)
        self.scheduler.submit_uitest(revision, None, None, lease)

    def test_one_job_runs_at_a_time(self) -> None:
        self.runner = FakeRunner(block=True)
        self.addCleanup(self.runner.gate.set)
        self.scheduler = self._scheduler()
        revision = self._ready()
        lease = self._lease()
        first = self.scheduler.submit_build(revision, None, lease)
        second = self.scheduler.submit_build(revision, None, lease)
        self.scheduler.step()
        self.assertTrue(self.runner.entered.wait(2))
        self.assertEqual([item[0] for item in self.runner.started], ["build"])
        self.scheduler.step()
        self.assertEqual(len(self.runner.started), 1)
        self.runner.entered.clear()
        self.runner.gate.set()
        self._wait_idle(first.id)
        self.scheduler.step()
        self.assertTrue(self.runner.entered.wait(2))
        self.assertEqual([item[0] for item in self.runner.started], ["build", "build"])
        self.assertEqual(self.runner.started[0][1], WORKER)
        self.assertNotEqual(second.device_id, PERSONAL)

    def test_warning_queues_launch_until_approved(self) -> None:
        self.memory.sample = MemorySample(PRESSURE_WARNING, 10, 10)
        revision = self._ready()
        job, _session = self.scheduler.submit_launch(revision, None, self._lease())
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "waiting_for_approval")
        self.assertEqual(self.runner.started, [])
        self.scheduler.approve(job.id)
        self.scheduler.step()
        self.assertTrue(self.runner.entered.wait(2))
        self.assertEqual(self.runner.started, [("launch", WORKER)])

    def test_swap_activity_queues_boot(self) -> None:
        self.memory.sample = MemorySample(PRESSURE_NORMAL, 1000, 1000)
        self.scheduler.step()
        self.memory.sample = MemorySample(PRESSURE_NORMAL, 1000, 1000 + 256)
        revision = self._ready()
        job, _session = self.scheduler.submit_launch(revision, None, self._lease())
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "waiting_for_approval")
        self.assertEqual(self.runner.started, [])

    def test_small_swap_delta_still_boots(self) -> None:
        self.memory.sample = MemorySample(PRESSURE_NORMAL, 1000, 1000)
        self.scheduler.step()
        self.memory.sample = MemorySample(PRESSURE_NORMAL, 1000, 1000 + 255)
        revision = self._ready()
        job, _session = self.scheduler.submit_launch(revision, None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.scheduler.get(job.id).status, "succeeded")

    def test_build_runs_at_warning_without_booting(self) -> None:
        self.memory.sample = MemorySample(PRESSURE_WARNING, 10, 10)
        revision = self._ready()
        job = self.scheduler.submit_build(revision, None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.runner.started, [("build", WORKER)])
        self.assertEqual(self.runner.shutdowns, [WORKER])
        self.assertNotIn(PERSONAL, self.runner.shutdowns)
        self.assertEqual(self.scheduler.get(job.id).status, "succeeded")
        self.scheduler.step()
        followup = self.scheduler.get(self.scheduler.get(job.id).followup_id)
        self.assertEqual(followup.kind, "boot")
        self.assertEqual(followup.device_id, WORKER)
        self.assertEqual(followup.status, "waiting_for_approval")
        self.assertEqual(self.runner.started, [("build", WORKER)])

    def test_storage_limit_fails_before_the_build_runs(self) -> None:
        self.scheduler.disk_used = lambda: 20 * 1024 * 1024 * 1024 + 1
        revision = self._ready()
        job = self.scheduler.submit_build(revision, None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.scheduler.get(job.id).status, "failed")
        self.assertEqual(self.runner.started, [])
        self.assertEqual(self.runner.shutdowns, [])

    def test_urgent_pressure_holds_a_build(self) -> None:
        self.memory.sample = MemorySample(PRESSURE_URGENT, 10, 10)
        revision = self._ready()
        job = self.scheduler.submit_build(revision, None, self._lease())
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "waiting_for_approval")
        self.assertEqual(self.runner.started, [])

    def test_screenshot_of_booted_worker_runs_under_warning(self) -> None:
        self.runner.booted.add(WORKER)
        self.runner.booted.add(PERSONAL)
        revision = self._ready()
        launch_id = "a" * 16
        session_id = "b" * 16
        from scheduler import Job

        launch = Job(
            id=launch_id,
            kind="launch",
            status="succeeded",
            revision_id=revision,
            session_id=session_id,
            device_id=WORKER,
        )
        self.scheduler.jobs[launch_id] = launch
        lease = self.scheduler.acquire_lease()
        self.scheduler.sessions[session_id] = {
            "job_id": launch_id,
            "device_id": WORKER,
            "revision_id": revision,
            "lease_id": lease,
        }
        self.memory.sample = MemorySample(PRESSURE_WARNING, 10, 10)
        job = self.scheduler.submit_screenshot(session_id)
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.runner.started, [("screenshot", WORKER)])
        self.assertNotIn(PERSONAL, self.runner.shutdowns)

    def test_idle_shutdown_stops_only_the_worker_simulator(self) -> None:
        self.runner.booted.update({WORKER, PERSONAL})
        self.clock.now = 601
        self.scheduler.step()
        self.assertEqual(self.runner.shutdowns, [WORKER])
        self.assertNotIn(PERSONAL, self.runner.probes)

    def test_active_lease_blocks_idle_shutdown(self) -> None:
        self.runner.booted.add(WORKER)
        lease=self.scheduler.acquire_lease()
        self.clock.now=299
        self.scheduler.renew_lease(lease)
        self.clock.now=598
        self.scheduler.renew_lease(lease)
        self.clock.now = 601
        self.scheduler.step()
        self.assertEqual(self.runner.shutdowns, [])

    def test_expired_lease_cannot_be_renewed_or_submit_jobs(self):
        lease=self.scheduler.acquire_lease()
        self.clock.now=300
        with self.assertRaises(PolicyError):
            self.scheduler.renew_lease(lease)
        with self.assertRaises(PolicyError):
            self.scheduler.submit_build('rev1',None,lease)
        self.scheduler.step()
        self.assertEqual(self.scheduler.lease['status'],'released')

    def test_controller_stopped_guest_releases_lease_and_fails_pending_work(self):
        lease=self.scheduler.acquire_lease()
        job=self.scheduler.submit_build(self._ready(),None,lease,boot_after=False)
        self.runner.lease_alive=lambda identifier:False
        self.scheduler.step()
        self.assertEqual(self.scheduler.lease['status'],'released')
        self.assertEqual(self.scheduler.get(job.id).status,'failed')
        self.assertFalse(self.runner.started)

    def test_personal_device_is_refused_even_if_the_denylist_is_empty(self) -> None:
        with self.assertRaises(PolicyError) as caught:
            self.scheduler.submit_launch("rev0001", PERSONAL, "leasetest1")
        self.assertEqual(caught.exception.code, "personal_simulator")
        with self.assertRaises(PolicyError) as direct:
            check_device(PERSONAL, {PERSONAL}, set())
        self.assertEqual(direct.exception.code, "personal_simulator")

    def test_artifact_path_outside_the_root_is_not_registered(self) -> None:
        self.runner.result = {
            "ok": True,
            "artifact_id": "shot0001",
            "artifact_path": "/Users/leolurch/.ssh/id_rsa",
        }
        revision = self._ready()
        job = self.scheduler.submit_reset(revision, None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.scheduler.get(job.id).status, "failed")
        self.assertEqual(self.scheduler.artifacts, {})

    def test_unknown_revision_fails_instead_of_waiting(self) -> None:
        job = self.scheduler.submit_build("missingrev", None, self._lease())
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "failed")
        self.assertEqual(self.scheduler.get(job.id).error, "unknown revision")
        self.assertEqual(self.runner.started, [])

    def test_failed_revision_fails_the_build(self) -> None:
        self.scheduler.revisions["revfailed"] = {"status": "failed", "archive": ""}
        job = self.scheduler.submit_build("revfailed", None, self._lease())
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).error, "revision failed")

    def test_compiler_tail_and_exit_code_are_kept(self) -> None:
        from runner import WorkerFailure

        self.runner.failure = WorkerFailure("compile started\nerror: use of undeclared identifier 'nope'", 65)
        job = self.scheduler.submit_build(self._ready(), None, self._lease(), boot_after=False)
        self.scheduler.step()
        self._wait_idle(job.id)
        finished = self.scheduler.get(job.id)
        self.assertEqual(finished.status, "failed")
        self.assertEqual(finished.exit_code, 65)
        self.assertIn("undeclared identifier 'nope'", finished.log)
        self.assertIsNone(finished.followup_id)

    def test_symlink_artifact_is_not_exported(self) -> None:
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "artifacts"
        export = Path(tmp.name) / "export"
        root.mkdir()
        outside = Path(tmp.name) / "canary.txt"
        outside.write_text("canary-secret")
        link = root / "shot.png"
        link.symlink_to(outside)
        self.scheduler.artifact_root = root
        self.scheduler.export_root = export
        self.runner.result = {"ok": True, "artifact_id": "shot0001", "artifact_path": str(link)}
        job = self.scheduler.submit_reset(self._ready(), None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.scheduler.get(job.id).status, "failed")
        self.assertEqual(self.scheduler.artifacts, {})
        self.assertTrue(outside.read_text() == "canary-secret")

    def test_regular_artifact_is_copied_out_of_the_worker_directory(self) -> None:
        import tempfile

        from containment import read_regular_file

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "artifacts"
        export = Path(tmp.name) / "export"
        root.mkdir()
        source = root / "shot0001.png"
        source.write_bytes(b"png-bytes")
        self.scheduler.artifact_root = root
        self.scheduler.export_root = export
        self.runner.result = {"ok": True, "artifact_id": "shot0001", "artifact_path": str(source)}
        job = self.scheduler.submit_reset(self._ready(), None, self._lease())
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.scheduler.get(job.id).status, "succeeded")
        exported = Path(self.scheduler.artifacts["shot0001"])
        self.assertEqual(exported.parent, export)
        self.assertFalse(exported.is_symlink())
        self.assertFalse(source.exists())
        self.assertEqual(read_regular_file(exported, export, 100), b"png-bytes")
        exported.unlink()
        exported.symlink_to(Path(tmp.name) / "canary.txt")
        (Path(tmp.name) / "canary.txt").write_text("nope")
        from policy import PolicyError

        with self.assertRaises(PolicyError):
            read_regular_file(exported, export, 100)


    def test_preparation_requires_lease_and_counts_toward_build_queue(self):
        revision = self._ready()
        with self.assertRaises(PolicyError):
            self.scheduler.submit_prepare(revision, "missing", "expo-ios", {})
        lease = self.scheduler.acquire_lease()
        self.scheduler.submit_prepare(revision, lease, "expo-ios", {})
        self.scheduler.submit_build(revision, None, lease, boot_after=False)
        with self.assertRaises(QueueFull):
            self.scheduler.submit_build(revision, None, lease)

    def test_preparation_waits_for_memory_approval_without_booting(self):
        self.memory.sample = MemorySample(PRESSURE_URGENT, 0, 0)
        job = self.scheduler.submit_prepare(self._ready(), self.scheduler.acquire_lease(), "expo-ios", {})
        self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "waiting_for_approval")
        self.assertEqual(self.runner.probes, [])
        self.scheduler.approve(job.id)
        self.scheduler.step()
        self._wait_idle(job.id)
        self.assertEqual(self.runner.started, [("prepare", None)])
        self.assertEqual(self.runner.shutdowns, [])

    def test_build_waits_for_preparation_and_fails_if_it_failed(self):
        revision = self._ready()
        lease = self.scheduler.acquire_lease()
        prep = self.scheduler.submit_prepare(revision, lease, "expo-ios", {})
        build = self.scheduler.submit_build(revision, None, lease, boot_after=False)
        sample = MemorySample(PRESSURE_NORMAL, 0, 0)
        self.assertEqual(self.scheduler._admit(build, sample, None), "skip")
        prep.status = "failed"
        self.assertEqual(self.scheduler._admit(build, sample, None), "skip")
        self.assertEqual(build.status, "failed")
        self.assertEqual(build.error, "preparation failed")

    def test_releasing_running_job_does_not_allow_overlapping_lease(self):
        self.runner = FakeRunner(block=True)
        self.addCleanup(self.runner.gate.set)
        self.scheduler = self._scheduler()
        revision = self._ready()
        lease = self.scheduler.acquire_lease()
        prep = self.scheduler.submit_prepare(revision, lease, "expo-ios", {})
        self.scheduler.step()
        self.assertTrue(self.runner.entered.wait(2))
        self.scheduler.release_lease(lease)
        with self.assertRaises(PolicyError):
            self.scheduler.acquire_lease()
        self.runner.gate.set()
        self._wait_idle(prep.id)
        self.assertEqual(self.scheduler.get(prep.id).status,'failed')
        self.assertIn('Lease ended',self.scheduler.get(prep.id).error)
        self.assertTrue(self.scheduler.acquire_lease())

    def test_automatic_boot_inherits_lease_and_is_cancelled_on_release(self):
        lease = self.scheduler.acquire_lease()
        job = self.scheduler.submit_build(self._ready(), None, lease)
        self.scheduler.step()
        self._wait_idle(job.id)
        followup = self.scheduler.get(self.scheduler.get(job.id).followup_id)
        self.assertEqual(followup.lease_id, lease)
        self.scheduler.release_lease(lease)
        self.assertEqual(self.scheduler.get(followup.id).status, "failed")


    def test_controller_probe_failure_fails_job_instead_of_hanging(self):
        from unittest.mock import patch
        lease = self.scheduler.acquire_lease()
        job, _ = self.scheduler.submit_launch(self._ready(), None, lease)
        with patch.object(self.runner, "is_booted", side_effect=PolicyError("isolation_required", "controller missing")):
            self.scheduler.step()
        self.assertEqual(self.scheduler.get(job.id).status, "failed")
        self.assertEqual(self.runner.started, [])


if __name__ == "__main__":
    unittest.main()
