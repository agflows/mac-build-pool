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

from containment import DISK_BUDGET, MAX_ARTIFACT_BYTES, read_regular_file
from policy import PolicyError, require_id, require_configuration, require_bool, require_recipe, require_public_env
from scheduler import QueueFull
from policy import simulator_input

JSON = "application/json"
MAX_JSON_BYTES = 1024 * 1024


class App:
    def __init__(
        self,
        scheduler,
        token: str,
        operator_token: str,
        spool_root: Path,
        allow_loopback: bool,
        max_upload_bytes: int,
        disk_used=None,
        disk_budget: int = DISK_BUDGET,
        *,
        trial_peer: str | None = None,
    ) -> None:
        self.scheduler = scheduler
        self.token = token
        self.operator_token = operator_token
        self.spool_root = spool_root
        self.allow_loopback = allow_loopback
        self.max_upload_bytes = max_upload_bytes
        self.disk_used = disk_used or (lambda: 0)
        self.disk_budget = disk_budget
        self.trial_peer = trial_peer


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

            peer = self.client_address[0]
            if ((app.trial_peer is not None and peer != app.trial_peer)
                    or not peer_allowed(peer, app.allow_loopback)):
                self._json(403, {"error": "forbidden"})
                return
            header = self.headers.get("Authorization", "")
            try:
                segments = path_segments(self.path)
            except PolicyError:
                if not authorized(header, app.token):
                    self._json(401, {"error": "unauthorized"})
                    return
                raise
            if operator_route(method, segments):
                if (app.trial_peer is not None or not authorized(header, app.operator_token)
                        or authorized(header, app.token)):
                    self._json(403, {"error": "operator_required"})
                    return
            elif not authorized(header, app.token):
                self._json(401, {"error": "unauthorized"})
                return
            if method == "POST" and segments in (["v1", "sources"], ["v1", "leases"], ["v1", "preparations"],
                                                   ["v1", "builds"], ["v1", "sessions"], ["v1", "tests"], ["v1", "reset"]):
                installed = getattr(app.scheduler.runner, "installed", None)
                if installed is not None and not installed():
                    raise PolicyError(getattr(app.scheduler.runner, "unavailable_code", "isolation_required"),
                                      "The configured execution backend is unavailable. No fallback is allowed.")
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
        installed = getattr(scheduler.runner, "installed", lambda: False)()
        mode = getattr(scheduler.runner, "execution_mode", "isolated-only")
        vm_backend=getattr(scheduler.runner,'vm_backend',False)
        platforms=getattr(getattr(scheduler.runner,'worker',None),'device_platforms',{})
        lease=scheduler.lease or {}
        return 200, {"ok": True, "executionMode": mode, "executorInstalled": installed,
                     "securityBoundary": "unix-account" if mode == "native-user" else ('macOS-vm' if vm_backend else "external-vm-controller-required"),
                     "networkIsolationVerified": bool(vm_backend and installed and scheduler.runner.verified()),
                     "remoteTrial": app.trial_peer is not None,
                     "leaseActive":lease.get('status')=='active',
                     "leaseExpiresIn":max(0,lease.get('expires',0)-scheduler.clock()),
                     "simulators":[{"deviceId":device,"platform":platforms.get(device,"iOS")}
                                   for device in sorted(scheduler.allowlist)],
                     "signingAPIEnabled": False, "usbAPIEnabled": False,
                     "pressure": scheduler.pressure_name(), **counts}, JSON
    if method == "POST" and segments == ["v1", "sources"]:
        return accept_source(app, body, content_type)
    if method == "POST" and segments == ["v1", "leases"]:
        data=read_json(body)
        lease_id=scheduler.acquire_lease(data.get('ttl',300),data.get('bootSimulator',False),
                                         guard_device(scheduler, data),data.get('name'))
        lease=scheduler.lease
        metadata={key:lease[key] for key in ('startJobId','sessionId') if key in lease}
        return 201, {"leaseId":lease_id,"expiresIn":data.get('ttl',300),**metadata}, JSON
    if method == "POST" and len(segments)==4 and segments[:2]==["v1","leases"] and segments[3]=='renew':
        data=read_json(body)
        return 200,scheduler.renew_lease(require_id(segments[2],'lease'),data.get('ttl',300)),JSON
    if method == "POST" and len(segments) == 4 and segments[:2] == ["v1", "leases"] and segments[3] == "release":
        scheduler.release_lease(require_id(segments[2], "lease"))
        return 200, {"released": True}, JSON
    if method == "POST" and segments == ["v1", "preparations"]:
        data = read_json(body)
        job = scheduler.submit_prepare(
            require_id(data.get("revisionId"), "revision"), require_lease(data),
            require_recipe(data.get("recipe")), require_public_env(data.get("publicEnv", {})), optional_scheme(data),
        )
        return 202, job_view(job), JSON
    if method == "POST" and segments == ["v1", "builds"]:
        data = read_json(body)
        job = scheduler.submit_build(
            require_id(data.get("revisionId"), "revision"),
            optional_scheme(data),
            require_lease(data),
            boot_after(data),
            require_configuration(data.get("configuration", "Debug")),
            require_bool(data.get("forTesting", True), "forTesting"),
            guard_device(scheduler, data),
        )
        return 202, job_view(job), JSON
    if method == "POST" and segments == ["v1", "sessions"]:
        data = read_json(body)
        device = guard_device(scheduler, data)
        job, session_id = scheduler.submit_launch(
            require_id(data.get("revisionId"), "revision"),
            device,
            require_lease(data),
            require_configuration(data.get("configuration", "Debug")),
        )
        view = job_view(job)
        view["sessionId"] = session_id
        return 202, view, JSON
    if method == "POST" and segments == ["v1", "tests"]:
        data = read_json(body)
        device = guard_device(scheduler, data)
        job = scheduler.submit_uitest(
            require_id(data.get("revisionId"), "revision"),
            optional_scheme(data),
            device,
            require_lease(data),
            require_configuration(data.get("configuration", "Debug")),
        )
        return 202, job_view(job), JSON
    if method == "POST" and segments == ["v1", "reset"]:
        data = read_json(body) if body else {}
        revision = data.get("revisionId")
        if revision is not None:
            revision = require_id(revision, "revision")
        device = guard_device(scheduler, data)
        job = scheduler.submit_reset(revision, device, require_lease(data))
        return 202, job_view(job), JSON
    if len(segments) == 4 and segments[0] == "v1" and segments[1] == "sessions":
        session_id = require_id(segments[2], "session")
        action = segments[3]
        if method == "POST" and action == "screenshot":
            return 202, job_view(scheduler.submit_screenshot(session_id)), JSON
        if method == "POST" and action == "input":
            body = read_json(body)
            simulator_input(body)
            return 202, job_view(scheduler.submit_input(session_id, body)), JSON
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
        kind = "image/png" if path.suffix == ".png" else "application/octet-stream"
        return 200, read_regular_file(path, scheduler.export_root, MAX_ARTIFACT_BYTES), kind
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
    view = {
        "jobId": job.id,
        "kind": job.kind,
        "status": job.status,
        "revisionId": job.revision_id,
        "sessionId": job.session_id,
        "deviceId": job.device_id,
        "artifactId": job.artifact_id,
        "followupJobId": job.followup_id,
        "leaseId": job.lease_id,
        "recipe": job.recipe,
        "configuration": job.configuration,
        "forTesting": job.for_testing,
        "exitCode": job.exit_code,
        "error": job.error,
    }
    ui = job.result.get("simulatorUI")
    if job.kind == "input" and isinstance(ui, dict):
        view["simulatorUI"] = ui
    return view


def read_json(body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid_body", "Body must be JSON.") from exc
    if not isinstance(data, dict):
        raise PolicyError("invalid_body", "Body must be a JSON object.")
    return data


def guard_device(scheduler, data: dict):
    device = optional_device(data)
    if device is not None:
        scheduler._device(device)
    return device


def require_lease(data: dict) -> str:
    lease = data.get("leaseId")
    if not isinstance(lease, str):
        raise PolicyError("lease_required", "A session lease is required.")
    return require_id(lease, "lease")


def boot_after(data: dict) -> bool:
    value = data.get("bootSimulator", True)
    if not isinstance(value, bool):
        raise PolicyError("invalid_body", "bootSimulator must be a boolean.")
    return value


def operator_route(method: str, segments: list[str]) -> bool:
    return method == "POST" and len(segments) == 4 and segments[:2] == ["v1", "jobs"] and segments[3] == "approve"


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
    if exc.code in {"isolation_required", "unsafe_executor", "native_worker_unavailable", "unsafe_execution_policy", "bad_execution_policy"}:
        return 503
    if exc.code in {"personal_simulator", "device_not_allowed"}:
        return 403
    if exc.code == "too_large":
        return 413
    if exc.code == "storage_limit":
        return 507
    if exc.code == "session_busy":
        return 409
    return 400


def serve(app: App, host: str, port: int) -> WorkerHTTPServer:
    from config import validate_listen

    validate_listen(host, app.allow_loopback)
    httpd = WorkerHTTPServer((host, port), Handler)
    httpd.app = app  # type: ignore[attr-defined]
    return httpd
