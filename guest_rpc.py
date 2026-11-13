"""Guest entry point for bounded source/artifact transfer and fixed worker ops."""
from __future__ import annotations
import base64
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

_CODE = '/Library/ios-worker'
# Tart's setup session starts in its private admin home. The non-admin job
# account cannot traverse it; enter a fixed guest-local directory before imports
# inspect cwd. All operation workspaces are selected explicitly afterwards.
os.chdir('/private/tmp')
sys.path.insert(0, _CODE)
from execution_policy import require_worker_execution, require_protected_file
from config import load_worker_config
from containment import apply_rlimits, MAX_ARTIFACT_BYTES, LOG_CAP
from policy import PolicyError, require_id, require_under
from worker_exec import perform, Commands
from memory import sample_system

INPUT_REQUEST_LIMIT = 128 * 1024
INPUT_RESULT_LIMIT = 2 * 1024 * 1024


def worker():
    os.umask(0o077)
    require_worker_execution()
    config = Path(_CODE) / 'worker.json'
    require_protected_file(config)
    cfg = load_worker_config(config)
    apply_rlimits()
    return cfg, Commands(cfg.developer_dir, [cfg.workspace_root, cfg.spool_root, cfg.artifact_root], cfg.disk_budget)


def main():
    cfg, commands = worker()
    line = sys.stdin.buffer.readline(96 * 1024 * 1024 + 1)
    if len(line) > 96 * 1024 * 1024:
        raise PolicyError('invalid_body', 'request exceeds transfer limit')
    request = json.loads(line)
    source = request.pop('source_base64', None)
    if source is not None:
        revision = require_id(request.get('revision_id'), 'revision')
        raw = base64.b64decode(source, validate=True)
        if len(raw) > cfg.max_upload_bytes:
            raise PolicyError('invalid_archive', 'source exceeds upload limit')
        archive = cfg.spool_root / (revision + '.tar.gz')
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
            perform({'op': 'ingest', 'archive': str(archive), 'revision_id': revision}, cfg, commands, sample_system)
        finally:
            archive.unlink(missing_ok=True)
    result = perform(request, cfg, commands, sample_system)
    path = result.pop('artifact_path', None)
    if path is not None:
        path = require_under(Path(path), cfg.artifact_root)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_ARTIFACT_BYTES:
                raise PolicyError('path_escape', 'invalid guest artifact')
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
            if len(raw) > MAX_ARTIFACT_BYTES:
                raise PolicyError('storage_limit', 'artifact exceeds transfer limit')
            result['artifact_base64'] = base64.b64encode(raw).decode()
        except Exception:
            # fd is owned by fdopen once constructed; process exit closes any remainder.
            raise
    print(json.dumps(result))


def input_loop():
    cfg, commands = worker()
    stream = sys.stdin.buffer
    while line := stream.readline(INPUT_REQUEST_LIMIT + 1):
        if not line.endswith(b'\n') or len(line) > INPUT_REQUEST_LIMIT:
            raise ValueError('invalid simulator request framing')
        request = json.loads(line)
        if (not isinstance(request, dict) or set(request) != {'op', 'job_id', 'device_id', 'input_action'}
                or request['op'] != 'input'):
            raise ValueError('invalid simulator request')
        job = require_id(request['job_id'], 'job')
        started = time.monotonic()
        try:
            result = perform(request, cfg, commands, sample_system)
        except Exception as exc:
            result = failure(exc)
        result['job_id'] = job
        result['guestMs'] = round(1000 * (time.monotonic() - started))
        reply = json.dumps(result, separators=(',', ':'))
        if len(reply) > INPUT_RESULT_LIMIT - 1:
            raise ValueError('simulator reply exceeds transfer cap')
        print(reply, flush=True)


def failure(exc):
    timed_out = isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) or getattr(exc, 'exit_code', None) == 124
    return {'ok': False, 'error': 'job_timeout' if timed_out else getattr(exc, 'code', 'worker_failed'),
            'message': str(exc)[-LOG_CAP:], 'exitCode': 124 if timed_out else getattr(exc, 'exit_code', 1)}


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--input-loop']:
            input_loop()
        elif not sys.argv[1:]:
            main()
        else:
            raise ValueError('unsupported guest operation')
    except Exception as exc:
        print(json.dumps(failure(exc)))
        sys.exit(1)
