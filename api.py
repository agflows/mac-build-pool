"""Authenticated API for the worker.

Routes name revisions, sessions, jobs, and artifacts. They do not accept a
host path or a shell command. The listener is the Tailscale address, and the
peer address has to fall in the Tailscale CGNAT range.
"""

from __future__ import annotations

import hmac
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from containment import DISK_BUDGET, MAX_ARTIFACT_BYTES
from policy import PolicyError, require_id
from scheduler import QueueFull

JSON = "application/json"
MAX_JSON_BYTES = 1024 * 1024


class App:
    def __init__(
        self,
        scheduler,
        token: str,
        spool_root: Path,
        allow_loopback: bool,
        max_upload_bytes: int,
        disk_used=None,
        disk_budget: int = DISK_BUDGET,
    ) -> None:
        self.scheduler = scheduler
        self.token = token
        self.spool_root = spool_root
        self.allow_loopback = allow_loopback
        self.max_upload_bytes = max_upload_bytes
        self.disk_used = disk_used or (lambda: 0)
        self.disk_budget = disk_budget


class WorkerHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16


class Handler(BaseHTTPRequestHandler):
    server_version = "ios-worker"
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def log_message(self, fmt: str, *args) -> None:
        return

    def _handle(self, method: str) -> None:
        app: App = self.server.app  # type: ignore[attr-defined]
        try:
            if self.headers.get("Transfer-Encoding"):
                self._json(400, {"error": "invalid_body"})
                return
            from config import peer_allowed

            if not peer_allowed(self.client_address[0], app.allow_loopback):
                self._json(403, {"error": "forbidden"})
                return
            if not authorized(self.headers.get("Authorization", ""), app.token):
                self._json(401, {"error": "unauthorized"})
                return
            segments = path_segments(self.path)
            body = self._read_body(app, segments, method)
            status, payload, content_type = dispatch(app, method, segments, body, self.headers.get("Content-Type", ""))
            if content_type == JSON:
                self._json(status, payload)
            else:
                self._bytes(status, payload, content_type)
        except PolicyError as exc:
            self._json(status_for(exc), {"error": exc.code})
        except QueueFull:
            self._json(429, {"error": "queue_full"})
        except KeyError:
            self._json(404, {"error": "not_found"})
        except Exception:
            self._json(500, {"error": "internal"})

    def _read_body(self, app: App, segments: list[str], method: str) -> bytes:
        if method == "GET":
            return b""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise PolicyError("invalid_body", "Content-Length is invalid.") from exc
        if length < 0:
            raise PolicyError("invalid_body", "Content-Length is invalid.")
        limit = app.max_upload_bytes if segments == ["v1", "sources"] else MAX_JSON_BYTES
        if length > limit:
            raise PolicyError("too_large", "Request body is too large.")
        if length == 0:
            return b""
        return self.rfile.read(length)

    def _json(self, status: int, payload: dict) -> None:
        self._bytes(status, json.dumps(payload).encode(), JSON)

    def _bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)


def dispatch(app: App, method: str, segments: list[str], body: bytes, content_type: str):
    scheduler = app.scheduler
    if method == "GET" and segments == ["v1", "health"]:
        counts = scheduler.counts()
        return 200, {"ok": True, "pressure": scheduler.pressure_name(), **counts}, JSON
    if method == "POST" and segments == ["v1", "sources"]:
        return accept_source(app, body, content_type)
    if method == "POST" and segments == ["v1", "builds"]:
        data = read_json(body)
        job = scheduler.submit_build(require_id(data.get("revisionId"), "revision"), optional_scheme(data))
        return 202, job_view(job), JSON
    if method == "POST" and segments == ["v1", "sessions"]:
        data = read_json(body)
        job, session_id = scheduler.submit_launch(
            require_id(data.get("revisionId"), "revision"),
            optional_device(data),
        )
        view = job_view(job)
        view["sessionId"] = session_id
        return 202, view, JSON
    if method == "POST" and segments == ["v1", "tests"]:
        data = read_json(body)
        job = scheduler.submit_uitest(
            require_id(data.get("revisionId"), "revision"),
            optional_scheme(data),
            optional_device(data),
        )
        return 202, job_view(job), JSON
    if method == "POST" and segments == ["v1", "reset"]:
        data = read_json(body) if body else {}
        revision = data.get("revisionId")
        if revision is not None:
            revision = require_id(revision, "revision")
        job = scheduler.submit_reset(revision, optional_device(data))
        return 202, job_view(job), JSON
    if len(segments) == 4 and segments[0] == "v1" and segments[1] == "sessions":
        session_id = require_id(segments[2], "session")
        action = segments[3]
        if method == "POST" and action == "screenshot":
            return 202, job_view(scheduler.submit_screenshot(session_id)), JSON
        if method == "POST" and action == "logs":
            return 202, job_view(scheduler.submit_logs(session_id)), JSON
        if method == "GET" and action == "logs":
            return 200, {"log": scheduler.latest_log(session_id)}, JSON
    if len(segments) == 3 and segments[0] == "v1" and segments[1] == "jobs":
        job_id = require_id(segments[2], "job")
        if method == "GET":
            return 200, job_view(scheduler.get(job_id)), JSON
    if len(segments) == 4 and segments[0] == "v1" and segments[1] == "jobs":
        job_id = require_id(segments[2], "job")
        action = segments[3]
        if method == "GET" and action == "logs":
            return 200, {"log": scheduler.get(job_id).log}, JSON
        if method == "POST" and action == "approve":
            scheduler.approve(job_id)
            return 200, job_view(scheduler.get(job_id)), JSON
    if method == "GET" and len(segments) == 3 and segments[0] == "v1" and segments[1] == "artifacts":
        artifact_id = require_id(segments[2], "artifact")
        path = Path(scheduler.artifact_path(artifact_id))
        if not path.is_file():
            raise KeyError(artifact_id)
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise PolicyError("too_large", "Artifact is too large.")
        kind = "image/png" if path.suffix == ".png" else "application/octet-stream"
        return 200, path.read_bytes(), kind
    return 404, {"error": "not_found"}, JSON


def accept_source(app: App, body: bytes, content_type: str):
    if not body:
        raise PolicyError("invalid_body", "Source snapshot is empty.")
    if app.disk_used() + len(body) > app.disk_budget:
        raise PolicyError("storage_limit", "Worker storage is over the 20 GB budget.")
    if content_type.split(";")[0].strip() not in {
        "application/gzip",
        "application/x-tar",
        "application/x-gtar",
        "application/octet-stream",
    }:
        raise PolicyError("invalid_body", "Source snapshot must be a tar or gzip body.")
    revision_id = uuid.uuid4().hex[:16]
    archive = app.spool_root / f"{revision_id}.tar"
    archive.write_bytes(body)
    app.scheduler.add_revision(revision_id, str(archive))
    job = app.scheduler.submit_ingest(revision_id)
    view = job_view(job)
    view["revisionId"] = revision_id
    return 202, view, JSON


def job_view(job) -> dict:
    return {
        "jobId": job.id,
        "kind": job.kind,
        "status": job.status,
        "revisionId": job.revision_id,
        "sessionId": job.session_id,
        "deviceId": job.device_id,
        "artifactId": job.artifact_id,
        "followupJobId": job.followup_id,
        "error": job.error,
    }


def read_json(body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid_body", "Body must be JSON.") from exc
    if not isinstance(data, dict):
        raise PolicyError("invalid_body", "Body must be a JSON object.")
    return data


def optional_scheme(data: dict):
    scheme = data.get("scheme")
    if scheme is None:
        return None
    from policy import require_scheme

    return require_scheme(scheme)


def optional_device(data: dict):
    device = data.get("deviceId")
    if device is None:
        return None
    if not isinstance(device, str):
        raise PolicyError("invalid_device", "Device id must be a simulator UDID.")
    return device


def path_segments(raw: str) -> list[str]:
    path = urlsplit(raw).path
    segments = []
    for part in path.split("/"):
        if part == "":
            continue
        decoded = unquote(part)
        if decoded in {".", ".."} or "/" in decoded or "\\" in decoded:
            raise PolicyError("invalid_id", "Path is not allowed.")
        segments.append(decoded)
    return segments


def authorized(header: str, token: str) -> bool:
    if not header.startswith("Bearer ") or not token:
        return False
    presented = header[7:].encode()
    expected = token.encode()
    try:
        return hmac.compare_digest(presented, expected)
    except Exception:
        return False


def status_for(exc: PolicyError) -> int:
    if exc.code in {"personal_simulator", "device_not_allowed"}:
        return 403
    if exc.code == "too_large":
        return 413
    if exc.code == "storage_limit":
        return 507
    return 400


def serve(app: App, host: str, port: int) -> WorkerHTTPServer:
    from config import validate_listen

    validate_listen(host, app.allow_loopback)
    httpd = WorkerHTTPServer((host, port), Handler)
    httpd.app = app  # type: ignore[attr-defined]
    return httpd
