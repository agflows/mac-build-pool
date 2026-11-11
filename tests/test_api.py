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
        app = App(self.scheduler, TOKEN, spool, allow_loopback=True, max_upload_bytes=1024 * 1024)
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

    def test_health_and_missing_shell_route(self) -> None:
        status, payload = self._request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["ok"], True)
        status, payload = self._request("POST", "/v1/shell", b"{\"command\":\"id\"}")
        self.assertEqual(status, 404)
        status, _payload = self._request("GET", "/v1/artifacts/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(status, 400)

    def test_personal_simulator_is_forbidden(self) -> None:
        body = json.dumps({"revisionId": "rev0001", "deviceId": PERSONAL}).encode()
        status, payload = self._request("POST", "/v1/sessions", body)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"], "personal_simulator")
        self.assertNotIn(b"/Users", payload)

    def test_third_build_returns_queue_full(self) -> None:
        body = json.dumps({"revisionId": "rev0001"}).encode()
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
        status, payload = self._request("POST", "/v1/sessions", json.dumps({"revisionId": "rev0001"}).encode())
        self.assertEqual(status, 202)
        job_id = json.loads(payload)["jobId"]
        self.scheduler.step()
        status, payload = self._request("GET", "/v1/jobs/" + job_id)
        self.assertEqual(json.loads(payload)["status"], "waiting_for_approval")
        status, _payload = self._request("POST", "/v1/jobs/" + job_id + "/approve", b"{}")
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


if __name__ == "__main__":
    unittest.main()
