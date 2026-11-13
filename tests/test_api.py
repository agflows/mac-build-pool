"""HTTP API: auth, device refusal, queue cap, and no shell route."""

from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import App, serve
from config import peer_allowed, validate_listen
from memory import PRESSURE_WARNING, MemorySample
from policy import PolicyError
from scheduler import Scheduler

WORKER = "3C8BB98E-6383-446B-AF87-1E1282762A13"
PERSONAL = "4D015300-4BAE-4E6D-89C9-BC4D454E4216"
TOKEN = "test-token"
OPERATOR = "operator-token-value"


class Memory:
    def __init__(self, sample: MemorySample) -> None:
        self.sample = sample

    def __call__(self) -> MemorySample:
        return self.sample


class Runner:
    def __init__(self) -> None:
        self.started = []
        self.booted = set()

    def is_booted(self, device_id: str) -> bool:
        return device_id in self.booted

    def shutdown(self, device_id: str) -> None:
        raise AssertionError(device_id)

    def run(self, job):
        self.started.append((job.kind, job.device_id))
        return {"ok": True, "log": job.kind}


class ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        spool = Path(self.tmp.name) / "spool"
        spool.mkdir()
        self.memory = Memory(MemorySample(PRESSURE_WARNING, 0, 0))
        self.runner = Runner()
        self.scheduler = Scheduler(
            self.runner,
            self.memory,
            allowlist={WORKER},
            denylist=set(),
            default_device=WORKER,
            clock=lambda: 0.0,
            artifact_root=Path(self.tmp.name) / "artifacts",
            idle_seconds=600,
        )
        app = App(self.scheduler, TOKEN, OPERATOR, spool, allow_loopback=True, max_upload_bytes=1024 * 1024)
        self.httpd = serve(app, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.httpd.server_close)
        self.port = self.httpd.server_address[1]

    def _request(self, method: str, path: str, body: bytes | None = None, token: str | None = TOKEN, content_type: str = "application/json"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["Content-Type"] = content_type
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, payload

    def test_missing_and_wrong_token_are_rejected(self) -> None:
        status, _payload = self._request("GET", "/v1/health", token=None)
        self.assertEqual(status, 401)
        status, _payload = self._request("GET", "/v1/health", token="nope")
        self.assertEqual(status, 401)

    def test_trial_limits_access_to_its_peer_and_rejects_operator_credentials(self) -> None:
        self.httpd.app.trial_peer = "100.78.73.28"
        self.assertEqual(self._request("GET", "/v1/health")[0], 403)
        self.httpd.app.trial_peer = "127.0.0.1"
        status, payload = self._request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["remoteTrial"])
        self.assertEqual(self._request("GET", "/v1/health", token=None)[0], 401)
        self.assertEqual(self._request("POST", "/v1/jobs/probe/approve", b"{}", token=OPERATOR)[0], 403)

    def test_health_and_missing_shell_route(self) -> None:
        status, payload = self._request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["ok"], True)
        status, payload = self._request("POST", "/v1/shell", b"{\"command\":\"id\"}")
        self.assertEqual(status, 404)
        status, _payload = self._request("GET", "/v1/artifacts/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(status, 400)

    def test_simulator_input_targets_the_leased_device_and_rejects_overrides(self):
        lease = self.scheduler.acquire_lease()
        self.scheduler.revisions["test"] = {"status": "ready"}
        _, session = self.scheduler.submit_launch("test", None, lease)
        path = f"/v1/sessions/{session}/input"
        for action in ({"action": "tap", "x": True, "y": 3},
                       {"action": "button", "button": "lock", "udid": PERSONAL},
                       {"action": "shell", "command": "id"}):
            self.assertEqual(self._request("POST", path, json.dumps(action).encode())[0], 400)
        action = {"action": "pinch", "scale": 1.5}
        status, payload = self._request("POST", path, json.dumps(action).encode())
        self.assertEqual(status, 202)
        job = self.scheduler.get(json.loads(payload)["jobId"])
        self.assertEqual((job.device_id, job.lease_id, job.input_action), (WORKER, lease, action))
        self.scheduler.release_lease(lease)
        self.assertNotEqual(self._request("POST", path, json.dumps(action).encode())[0], 202)

    def test_input_failure_returns_structured_snapshot_until_lease_release(self):
        lease = self.scheduler.acquire_lease()
        self.scheduler.revisions["test"] = {"status": "ready"}
        launch, session = self.scheduler.submit_launch("test", None, lease)
        self.scheduler.jobs[launch.id].status = "succeeded"
        self.runner.run = lambda job: {
            "ok": True,
            "exitCode": 1,
            "simulatorUI": {"error": {"code": "screenChanged"}, "capture": {"rows": []}},
        }
        action = {"action": "tapElement", "snapshotId": WORKER, "ref": "e12"}
        status, payload = self._request("POST", f"/v1/sessions/{session}/input", json.dumps(action).encode())
        self.assertEqual(status, 202)
        job = json.loads(payload)["jobId"]
        self.scheduler.step()
        deadline = time.monotonic() + 2
        while self.scheduler.get(job).status in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(0.01)
        path = f"/v1/jobs/{job}"
        failed = json.loads(self._request("GET", path)[1])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["simulatorUI"]["error"]["code"], "screenChanged")
        self.assertEqual(failed["simulatorUI"]["capture"]["rows"], [])
        self.scheduler.release_lease(lease)
        self.assertNotIn("simulatorUI", json.loads(self._request("GET", path)[1]))

    def test_personal_simulator_is_forbidden(self) -> None:
        body = json.dumps({"revisionId": "rev0001", "deviceId": PERSONAL}).encode()
        status, payload = self._request("POST", "/v1/sessions", body)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "personal_simulator")
        self.assertNotIn(b"/Users", payload)

    def _lease(self) -> str:
        status, payload = self._request("POST", "/v1/leases", b"{}")
        self.assertEqual(status, 201)
        return json.loads(payload)["leaseId"]

    def test_second_lease_is_rejected(self) -> None:
        self._lease()
        status, payload = self._request("POST", "/v1/leases", b"{}")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["error"], "session_busy")

    def test_simulator_only_lease_exposes_a_screenshot_session(self) -> None:
        self.runner.vm_backend = True
        status, payload = self._request("POST", "/v1/leases", b'{"bootSimulator":true}')
        self.assertEqual(status, 201)
        lease = json.loads(payload)
        start = self.scheduler.get(lease["startJobId"])
        self.assertEqual(start.kind, "boot")
        self.assertEqual(start.device_id, WORKER)
        screenshot = f'/v1/sessions/{lease["sessionId"]}/screenshot'
        status, payload = self._request("POST", screenshot, b"{}")
        self.assertEqual(status, 202)
        job = self.scheduler.get(json.loads(payload)["jobId"])
        self.assertEqual(job.lease_id, lease["leaseId"])
        self.assertIsNone(job.revision_id)
        self.assertEqual(self._request("POST", f'/v1/leases/{lease["leaseId"]}/release', b"{}")[0], 200)
        self.assertEqual(self._request("POST", screenshot, b"{}")[0], 409)

    def test_named_watch_lease_boots_the_allowed_watch(self) -> None:
        watch = "A23FD418-22F2-4BA4-9E87-91E86A9D3F09"
        self.scheduler.allowlist.add(watch)
        self.runner.vm_backend = True
        body = json.dumps({"name": "Watch QA", "deviceId": watch, "bootSimulator": True}).encode()
        status, raw = self._request("POST", "/v1/leases", body)
        self.assertEqual(status, 201)
        self.assertEqual(self.scheduler.lease["name"], "Watch QA")
        self.assertEqual(self.scheduler.get(json.loads(raw)["startJobId"]).device_id, watch)

    def test_third_build_returns_queue_full(self) -> None:
        body = json.dumps({"revisionId": "rev0001", "leaseId": self._lease()}).encode()
        self.assertEqual(self._request("POST", "/v1/builds", body)[0], 202)
        self.assertEqual(self._request("POST", "/v1/builds", body)[0], 202)
        status, payload = self._request("POST", "/v1/builds", body)
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(payload)["error"], "queue_full")

    def test_source_upload_returns_an_id_not_a_path(self) -> None:
        status, payload = self._request("POST", "/v1/sources", b"not-a-tar", content_type="application/gzip")
        self.assertEqual(status, 202)
        data = json.loads(payload)
        self.assertEqual(len(data["revisionId"]), 16)
        self.assertNotIn(b"/Users", payload)
        self.assertNotIn(b"spool", payload)

    def test_approval_then_launch_uses_the_worker_device(self) -> None:
        self.scheduler.revisions["rev0001"] = {"status": "ready", "archive": ""}
        body = json.dumps({"revisionId": "rev0001", "leaseId": self._lease()}).encode()
        status, payload = self._request("POST", "/v1/sessions", body)
        self.assertEqual(status, 202)
        job_id = json.loads(payload)["jobId"]
        self.scheduler.step()
        status, payload = self._request("GET", "/v1/jobs/" + job_id)
        self.assertEqual(json.loads(payload)["status"], "waiting_for_approval")
        status, payload = self._request("POST", "/v1/jobs/" + job_id + "/approve", b"{}")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "operator_required")
        status, _payload = self._request("POST", "/v1/jobs/" + job_id + "/approve", b"{}", token=OPERATOR)
        self.assertEqual(status, 200)
        self.scheduler.step()
        for _ in range(100):
            if self.runner.started:
                break
            time.sleep(0.01)
        self.assertEqual(self.runner.started, [("launch", WORKER)])

    def test_source_over_the_disk_budget_is_rejected(self) -> None:
        self.httpd.app.disk_budget = 10
        self.httpd.app.disk_used = lambda: 10
        status, payload = self._request("POST", "/v1/sources", b"tar-bytes", content_type="application/gzip")
        self.assertEqual(status, 507)
        self.assertEqual(json.loads(payload)["error"], "storage_limit")

    def test_listen_address_must_be_tailscale(self) -> None:
        with self.assertRaises(PolicyError):
            validate_listen("0.0.0.0", False)
        with self.assertRaises(PolicyError):
            validate_listen("10.6.50.241", False)
        with self.assertRaises(PolicyError):
            validate_listen("127.0.0.1", False)
        validate_listen("100.114.181.78", False)
        validate_listen("127.0.0.1", True)
        self.assertFalse(peer_allowed("10.6.50.241", False))
        self.assertTrue(peer_allowed("100.114.181.78", False))
        self.assertFalse(peer_allowed("127.0.0.1", False))


    def test_preparation_requires_lease_and_accepts_only_named_recipe(self):
        body = {"revisionId": "rev1", "recipe": "expo-ios"}
        self.assertEqual(self._request("POST", "/v1/preparations", json.dumps(body).encode())[0], 400)
        body["leaseId"] = self._lease()
        body["recipe"] = "shell"
        self.assertEqual(self._request("POST", "/v1/preparations", json.dumps(body).encode())[0], 400)
        body["recipe"] = "expo-ios"
        body["publicEnv"] = {"PATH": "/tmp"}
        self.assertEqual(self._request("POST", "/v1/preparations", json.dumps(body).encode())[0], 400)
        body["publicEnv"] = {"EXPO_PUBLIC_API_URL": "https://example.test"}
        status, raw = self._request("POST", "/v1/preparations", json.dumps(body).encode())
        self.assertEqual(status, 202)
        result = json.loads(raw)
        self.assertEqual(result["kind"], "prepare")
        self.assertEqual(result["recipe"], "expo-ios")
        self.assertNotIn("publicEnv", result)

    def test_release_build_options_are_validated_and_forwarded(self):
        body = {"revisionId": "rev1", "leaseId": self._lease(), "configuration": "Release", "forTesting": False, "bootSimulator": False}
        status, raw = self._request("POST", "/v1/builds", json.dumps(body).encode())
        self.assertEqual(status, 202)
        result = json.loads(raw)
        self.assertEqual(result["configuration"], "Release")
        self.assertFalse(result["forTesting"])
        body["configuration"] = "Release; /bin/sh"
        self.assertEqual(self._request("POST", "/v1/builds", json.dumps(body).encode())[0], 400)
        body["configuration"] = "Debug"
        body["forTesting"] = "false"
        self.assertEqual(self._request("POST", "/v1/builds", json.dumps(body).encode())[0], 400)


    def test_missing_isolation_adapter_refuses_work_before_staging_source(self):
        self.runner.installed = lambda: False
        status, raw = self._request("POST", "/v1/sources", b"not-staged", content_type="application/gzip")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["error"], "isolation_required")
        self.assertEqual(list(self.httpd.app.spool_root.iterdir()), [])
        self.assertEqual(self._request("POST", "/v1/leases", b"{}")[0], 503)

    def test_native_health_does_not_claim_isolation_or_signing(self):
        self.runner.execution_mode = "native-user"
        self.runner.installed = lambda: True
        status, raw = self._request("GET", "/v1/health")
        self.assertEqual(status, 200)
        result = json.loads(raw)
        self.assertEqual(result["securityBoundary"], "unix-account")
        self.assertFalse(result["networkIsolationVerified"])
        self.assertFalse(result["signingAPIEnabled"])
        self.assertFalse(result["usbAPIEnabled"])
        for route in ("execution-mode", "sign", "deploy", "usb"):
            self.assertEqual(self._request("POST", "/v1/" + route, b'{}')[0], 404)

    def test_unavailable_native_backend_never_stages_uploads(self):
        self.runner.execution_mode = "native-user"
        self.runner.unavailable_code = "native_worker_unavailable"
        self.runner.installed = lambda: False
        status, raw = self._request("POST", "/v1/sources", b"not-staged", content_type="application/gzip")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["error"], "native_worker_unavailable")
        self.assertEqual(list(self.httpd.app.spool_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
