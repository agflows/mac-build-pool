"""Exercise the real remote simulator interface using the SwiftProbe fixture."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cli import call, read_secret


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("IOS_WORKER_URL", "http://127.0.0.1:8742"))
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    token = read_secret(args.token_file)
    evidence = {"jobs": [], "actions": []}
    args.output.mkdir(mode=0o700)

    def request(method, path, data=None, *, accepted=(200, 201, 202)):
        mime = "application/json"
        if isinstance(data, bytes):
            mime = "application/gzip"
        elif data is not None:
            data = json.dumps(data).encode()
        status, body = call(args.url, token, method, path, data, mime)
        if status not in accepted:
            raise RuntimeError(f"{method} {path} returned HTTP {status}")
        return json.loads(body)

    def wait(job, *, allow_failure=False):
        deadline = time.monotonic() + 3000
        while time.monotonic() < deadline:
            state = request("GET", f"/v1/jobs/{job}")
            if state["status"] == "succeeded":
                evidence["jobs"].append({"jobId": job, "kind": state["kind"]})
                return state
            if state["status"] == "failed" and allow_failure:
                return state
            if state["status"] == "failed":
                raise RuntimeError(f"Job {job} failed: {state.get('error')}")
            time.sleep(1)
        raise TimeoutError(f"Job {job} did not finish.")

    def interact(session, action, *, request_id=None, succeeded=True):
        request_id = request_id or uuid.uuid4().hex
        started = time.monotonic()
        result = request("POST", f"/v1/sessions/{session}/interact", {
            "requestId": request_id, "input": action,
        })
        if result["status"] not in ("succeeded", "failed"):
            result = wait(result["jobId"], allow_failure=not succeeded)
        evidence["actions"].append({"action": action["action"], "jobId": result["jobId"],
                                    "elapsedMs": round((time.monotonic() - started) * 1000),
                                    "timing": result.get("simulatorTiming")})
        if succeeded and result["status"] != "succeeded":
            raise RuntimeError(f"{action['action']} failed: {result.get('error')}")
        return result

    health = request("GET", "/v1/health")
    if (not health.get("simulatorInteract") or health.get("securityBoundary") != "macOS-vm"
            or health.get("signingAPIEnabled") or health.get("usbAPIEnabled")):
        raise RuntimeError("The isolated simulator interface is unavailable.")
    lease = request("POST", "/v1/leases", {"name": "Simulator interface acceptance"})["leaseId"]
    stop = threading.Event()
    def renew():
        while not stop.wait(45):
            request("POST", f"/v1/leases/{lease}/renew", {})
    threading.Thread(target=renew, daemon=True).start()
    try:
        fixture = ROOT / "fixtures/SwiftProbe"
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w:gz") as archive:
            for path in fixture.iterdir():
                archive.add(path, arcname=path.name)
        upload = request("POST", "/v1/sources", source.getvalue())
        wait(upload["jobId"])
        build = {"revisionId": upload["revisionId"], "leaseId": lease, "scheme": "SwiftProbe"}
        wait(request("POST", "/v1/preparations", {**build, "recipe": "swift-ios"})["jobId"])
        wait(request("POST", "/v1/builds", {**build, "bootSimulator": False, "forTesting": False})["jobId"])
        launch = request("POST", "/v1/sessions", {key: build[key] for key in ("revisionId", "leaseId")})
        wait(launch["jobId"])
        session = launch["sessionId"]
        capture = interact(session, {"action": "snapshot"})["simulatorUI"]["capture"]
        row = next(row for row in capture["rows"] if row.split("|")[3:4] == ["Email"])
        typed = {"action": "typeInto", "snapshotId": capture["snapshotID"], "ref": row.split("|")[0],
                 "focus": True, "text": "simulator+test@example.test"}
        request_id = uuid.uuid4().hex
        first = interact(session, typed, request_id=request_id)
        repeated = interact(session, typed, request_id=request_id)
        assert first["jobId"] == repeated["jobId"]
        assert "capture" not in first["simulatorUI"]
        result = interact(session, {"action": "tapMatching", "identifier": "probe.continue"})
        assert any("Email entry verified" in row for row in result["simulatorUI"]["capture"]["rows"])
        stale = interact(session, {"action": "tapElement", "snapshotId": capture["snapshotID"],
                                  "ref": row.split("|")[0]}, succeeded=False)
        assert stale["status"] == "failed" and stale["error"] in {
            "screenChanged", "snapshotExpired", "snapshotMissing", "contextChanged",
        }
        frame = interact(session, {"action": "preview"})["simulatorPreview"]
        (args.output / "preview.jpg").write_bytes(base64.b64decode(frame["jpegBase64"], validate=True))
        interact(session, {"action": "button", "button": "home"})
        interact(session, {"action": "button", "button": "lock"})
        shot = wait(request("POST", f"/v1/sessions/{session}/screenshot", {})["jobId"])
        status, png = call(args.url, token, "GET", f"/v1/artifacts/{shot['artifactId']}")
        assert status == 200 and png.startswith(b"\x89PNG\r\n\x1a\n")
        (args.output / "lock-screen.png").write_bytes(png)
        evidence["passed"] = True
    finally:
        stop.set()
        (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        request("POST", f"/v1/leases/{lease}/release", {})


if __name__ == "__main__":
    main()
