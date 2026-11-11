#!/usr/bin/env python3
"""Call the ios-worker API.

The bearer token is read from an owner-only file. Pass the file path, not the
token. The token is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


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


def call(url: str, token: str, method: str, path: str, body: bytes | None = None, content_type: str = "application/json"):
    request = urllib.request.Request(url.rstrip("/") + path, data=body, method=method)
    request.add_header("Authorization", "Bearer " + token)
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
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


def wait_job(url: str, token: str, job_id: str) -> dict:
    while True:
        status, raw = call(url, token, "GET", "/v1/jobs/" + job_id)
        if status != 200:
            print_json(raw)
            raise SystemExit(status)
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("status") in {"succeeded", "failed"}:
            print_json(raw)
            if payload.get("status") == "failed":
                log_status, log_raw = call(url, token, "GET", "/v1/jobs/" + job_id + "/logs")
                if log_status == 200:
                    log = json.loads(log_raw.decode("utf-8")).get("log", "")
                    if log:
                        sys.stdout.write(log[-8000:] + "\n")
            return payload
        time.sleep(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Call the ios-worker API without putting the token on the command line.")
    parser.add_argument("--url", default=os.environ.get("IOS_WORKER_URL", DEFAULT_URL))
    parser.add_argument("--token-file", default=os.environ.get("IOS_WORKER_TOKEN_FILE", ""))
    parser.add_argument("--operator-token-file", default=os.environ.get("IOS_WORKER_OPERATOR_TOKEN_FILE", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    sub.add_parser("lease")
    release = sub.add_parser("release")
    release.add_argument("lease")
    source = sub.add_parser("source")
    source.add_argument("archive")
    build = sub.add_parser("build")
    build.add_argument("--revision", required=True)
    build.add_argument("--lease", required=True)
    build.add_argument("--scheme")
    build.add_argument("--no-boot", action="store_true")
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
        status, raw = call(args.url, token, "POST", "/v1/leases", b"{}")
    elif args.command == "release":
        status, raw = call(args.url, token, "POST", f"/v1/leases/{args.lease}/release", b"{}")
    elif args.command == "source":
        archive = Path(args.archive)
        status, raw = call(args.url, token, "POST", "/v1/sources", archive.read_bytes(), "application/gzip")
        payload = print_json(raw)
        if status != 202:
            return status
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
    elif args.command == "build":
        body = {"revisionId": args.revision, "leaseId": args.lease, "bootSimulator": not args.no_boot}
        if args.scheme:
            body["scheme"] = args.scheme
        status, raw = call(args.url, token, "POST", "/v1/builds", json.dumps(body).encode())
        payload = print_json(raw)
        if status != 202:
            return status
        job = wait_job(args.url, token, payload["jobId"])
        return 0 if job.get("status") == "succeeded" else 1
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
