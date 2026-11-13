#!/usr/bin/env python3
"""Call the ios-worker API.

The bearer token is read from an owner-only file. Pass the file path, not the
token. The token is never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

# Also support the installed, owner-controlled CLI under python3 -I.
_CODE_ROOT = str(Path(__file__).resolve().parent)
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)


DEFAULT_URL = "http://100.114.181.78:8741"


def read_secret(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SystemExit("token file is missing") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit("token file must not be a symlink")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit("token file must be readable only by its owner")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        text = os.read(fd, 256).decode("utf-8").strip()
    finally:
        os.close(fd)
    if len(text) < 16 or "\n" in text or "\x00" in text:
        raise SystemExit("token file is missing or too short")
    return text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a bearer credential to a redirect target.


def call(url: str, token: str, method: str, path: str, body: bytes | None = None, content_type: str = "application/json"):
    request = urllib.request.Request(url.rstrip("/") + path, data=body, method=method)
    request.add_header("Authorization", "Bearer " + token)
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=120) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def print_json(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        sys.stdout.write(raw.decode("utf-8", "replace")[:2000] + "\n")
        return {}
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return payload if isinstance(payload, dict) else {}


def wait_job(url: str, token: str, job_id: str, timeout: float = 3600, *, show_result=True) -> dict:
    deadline = time.monotonic() + timeout
    last_renewal = 0.0
    while time.monotonic() < deadline:
        status, raw = call(url, token, "GET", "/v1/jobs/" + job_id)
        if status != 200:
            print_json(raw)
            raise SystemExit(status)
        payload = json.loads(raw.decode("utf-8"))
        lease_id=payload.get('leaseId')
        if lease_id and time.monotonic()-last_renewal>=60 and payload.get('status') not in {'succeeded','failed'}:
            renewal_status, renewal=call(url,token,'POST',f'/v1/leases/{lease_id}/renew',b'{}')
            if renewal_status!=200:
                print_json(renewal)
                raise SystemExit('Lease renewal failed; the VM will stop at expiry.')
            last_renewal=time.monotonic()
        if payload.get("status") in {"succeeded", "failed", "waiting_for_approval"}:
            if show_result:
                print_json(raw)
            if payload.get("status") == "failed":
                log_status, log_raw = call(url, token, "GET", "/v1/jobs/" + job_id + "/logs")
                if log_status == 200:
                    log = json.loads(log_raw.decode("utf-8")).get("log", "")
                    if log:
                        sys.stdout.write(log[-8000:] + "\n")
            return payload
        time.sleep(1)
    raise SystemExit("Job wait timed out; job may still be running. Check status before retrying.")


def save_preview(job, output):
    frame = job.get("simulatorPreview")
    if job.get("status") != "succeeded" or not isinstance(frame, dict):
        print(json.dumps(job))
        return 1
    if frame.get("changed"):
        raw = base64.b64decode(frame["jpegBase64"], validate=True)
        if len(raw) > 512 * 1024 or not (raw.startswith(b"\xff\xd8\xff") and raw.endswith(b"\xff\xd9")):
            raise SystemExit("Invalid JPEG preview.")
        with output.open("xb") as stream:
            stream.write(raw)
    print(json.dumps({"frameId": frame["id"], "changed": frame["changed"]}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Call the ios-worker API without putting the token on the command line.")
    parser.add_argument("--url", default=os.environ.get("IOS_WORKER_URL", DEFAULT_URL))
    parser.add_argument("--token-file", default=os.environ.get("IOS_WORKER_TOKEN_FILE", ""))
    parser.add_argument("--operator-token-file", default=os.environ.get("IOS_WORKER_OPERATOR_TOKEN_FILE", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    lease=sub.add_parser("lease")
    lease.add_argument('--simulator',action='store_true')
    lease.add_argument('--device',help='Worker simulator ID')
    lease.add_argument('--name',help='Name shown in the Mac menu')
    lease.add_argument('--project',help='Stable project ID for the host cache')
    lease.add_argument('--resume',help='Resume ID returned by a cached build')
    renew=sub.add_parser('renew')
    renew.add_argument('lease')
    release = sub.add_parser("release")
    release.add_argument("lease")
    source = sub.add_parser("source")
    source.add_argument("archive")
    build = sub.add_parser("build")
    build.add_argument("--revision", required=True)
    build.add_argument("--lease", required=True)
    build.add_argument("--scheme")
    build.add_argument("--device", help="Worker simulator ID")
    build.add_argument("--no-boot", action="store_true")
    build.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    build.add_argument("--build-only", action="store_true", help="Use build rather than build-for-testing (apps without XCTest targets).")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--lease", required=True)
    prepare.add_argument("--recipe", choices=["expo-ios", "flutter-ios", "swift-ios"], required=True)
    prepare.add_argument("--scheme")
    prepare.add_argument("--public-env-file", help="JSON object containing only EXPO_PUBLIC_ variables; these are not secrets.")
    launch = sub.add_parser("launch")
    launch.add_argument("--revision", required=True)
    launch.add_argument("--lease", required=True)
    launch.add_argument("--device", help="Worker simulator ID")
    launch.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    test = sub.add_parser("test")
    test.add_argument("--revision", required=True)
    test.add_argument("--lease", required=True)
    test.add_argument("--scheme")
    test.add_argument("--device", help="Worker simulator ID")
    test.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    shot = sub.add_parser("screenshot")
    shot.add_argument("session")
    shot.add_argument("--output", required=True)
    simulator = sub.add_parser("input", help="Send a JSON simulator action to a leased iOS session")
    simulator.add_argument("session")
    simulator.add_argument("action", help='JSON action, or - to read JSON from standard input')
    simulator.add_argument("--request-id", help="Reuse this ID to recover an interaction after a disconnect.")
    simulator.add_argument("--output", type=Path, help="Save a preview as JPEG.")
    status = sub.add_parser("status")
    status.add_argument("job")
    logs = sub.add_parser("logs")
    logs.add_argument("job")
    approve = sub.add_parser("approve")
    approve.add_argument("job")
    wait = sub.add_parser("wait")
    wait.add_argument("job")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    operator_command = args.command == "approve"
    file_name = args.operator_token_file if operator_command else args.token_file
    if not file_name:
        raise SystemExit("pass --token-file or --operator-token-file. The token itself is not an argument.")
    token = read_secret(Path(file_name))
    if args.command == "health":
        status, raw = call(args.url, token, "GET", "/v1/health")
    elif args.command == "lease":
        body = {'bootSimulator': args.simulator, 'deviceId': args.device, 'name': args.name, 'project':args.project, 'resumeId':args.resume}
        status, raw = call(args.url, token, "POST", "/v1/leases", json.dumps(body).encode())
    elif args.command == "release":
        status, raw = call(args.url, token, "POST", f"/v1/leases/{args.lease}/release", b"{}")
    elif args.command == 'renew':
        status,raw=call(args.url,token,'POST',f'/v1/leases/{args.lease}/renew',b'{}')
    elif args.command == "source":
        archive = Path(args.archive)
        status, raw = call(args.url, token, "POST", "/v1/sources", archive.read_bytes(), "application/gzip")
        payload = print_json(raw)
        if status != 202:
            return status
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command == "prepare":
        from policy import require_public_env
        public_env = require_public_env(json.loads(Path(args.public_env_file).read_text()) if args.public_env_file else {})
        body = {"revisionId": args.revision, "leaseId": args.lease, "recipe": args.recipe, "publicEnv": public_env}
        if args.scheme:
            body["scheme"] = args.scheme
        status, raw = call(args.url, token, "POST", "/v1/preparations", json.dumps(body).encode())
        payload = print_json(raw)
        if status != 202:
            return 1
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command == "build":
        body = {"revisionId": args.revision, "leaseId": args.lease, "bootSimulator": not args.no_boot,
                "configuration": args.configuration, "forTesting": not args.build_only, "deviceId": args.device}
        if args.scheme:
            body["scheme"] = args.scheme
        status, raw = call(args.url, token, "POST", "/v1/builds", json.dumps(body).encode())
        payload = print_json(raw)
        if status != 202:
            return status
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command in {"launch", "test"}:
        body = {"revisionId": args.revision, "leaseId": args.lease, "configuration": args.configuration,
                "deviceId": args.device}
        if args.command == "test" and args.scheme:
            body["scheme"] = args.scheme
        route = "/v1/sessions" if args.command == "launch" else "/v1/tests"
        status, raw = call(args.url, token, "POST", route, json.dumps(body).encode())
        payload = print_json(raw)
        if status != 202:
            return 1
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command == "input":
        if args.action == "-":
            action = sys.stdin.buffer.read(1024 * 1024 + 1)
            if len(action) > 1024 * 1024:
                raise SystemExit("Simulator input JSON exceeds 1 MiB.")
        else:
            action = args.action.encode()
        request_id = args.request_id or uuid.uuid4().hex
        try:
            data = {"requestId": request_id, "input": json.loads(action)}
        except ValueError:
            raise SystemExit("Simulator input must be valid JSON.") from None
        if args.output and (not isinstance(data["input"], dict) or data["input"].get("action") != "preview"):
            raise SystemExit("--output requires the preview action.")
        try:
            status, raw = call(args.url, token, "POST", f"/v1/sessions/{args.session}/interact", json.dumps(data).encode())
        except (OSError, TimeoutError):
            raise SystemExit(f"Interaction connection lost. Recover with --request-id {request_id}.") from None
        if status == 200:
            if args.output:
                return save_preview(json.loads(raw), args.output)
            job = print_json(raw)
            if "simulatorUI" in job or "simulatorPreview" in job or not job.get("jobId"):
                return 0 if job.get("status") == "succeeded" else 1
            status, raw = call(args.url, token, "GET", f"/v1/jobs/{job['jobId']}/logs")
            if status == 200:
                log = json.loads(raw).get("log")
                if log:
                    print(log)
            return 0 if job.get("status") == "succeeded" else 1
        if status == 404 and args.request_id is None:
            health_status, health_raw = call(args.url, token, "GET", "/v1/health")
            if health_status == 200 and "simulatorInteract" not in json.loads(health_raw):
                status, raw = call(args.url, token, "POST", f"/v1/sessions/{args.session}/input", action)
        payload = print_json(raw)
        if status != 202:
            return 1
        job = wait_job(args.url, token, payload["jobId"], show_result=not args.output)
        if args.output:
            return save_preview(job, args.output)
        if "simulatorUI" in job:
            return 0 if job.get("status") == "succeeded" else 1
        status, raw = call(args.url, token, "GET", f"/v1/jobs/{payload['jobId']}/logs")
        if status == 200:
            print(json.loads(raw).get("log", ""))
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command == "screenshot":
        status, raw = call(args.url, token, "POST", f"/v1/sessions/{args.session}/screenshot", b"{}")
        payload = print_json(raw)
        if status != 202:
            return 1
        job = wait_job(args.url, token, payload["jobId"])
        if job.get("status") != "succeeded":
            return 1
        status, raw = call(args.url, token, "GET", "/v1/artifacts/" + job["artifactId"])
        if status != 200:
            print_json(raw)
            return 1
        if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            raise SystemExit("Artifact is not a PNG screenshot.")
        # Refuse overwriting an existing file or following an output symlink.
        with Path(args.output).open("xb") as destination:
            destination.write(raw)
        print("Screenshot saved to " + args.output)
        return 0
    elif args.command == "status":
        status, raw = call(args.url, token, "GET", "/v1/jobs/" + args.job)
    elif args.command == "logs":
        status, raw = call(args.url, token, "GET", "/v1/jobs/" + args.job + "/logs")
    elif args.command == "approve":
        status, raw = call(args.url, token, "POST", "/v1/jobs/" + args.job + "/approve", b"{}")
    elif args.command == "wait":
        job = wait_job(args.url, token, args.job)
        return 0 if job.get("status") == "succeeded" else 1
    else:
        raise SystemExit("unknown command")
    print_json(raw)
    return 0 if status < 300 else status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
