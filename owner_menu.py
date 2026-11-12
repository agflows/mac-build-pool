"""Local owner UI channel. Authentication uses the connecting macOS UID."""
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from execution_policy import require_protected_file
from policy import PolicyError

LIBRARY = Path('/Library/ios-worker')


def usage(disk_paths):
    """Resident memory for this role and allocated bytes for its data roots."""
    uid = os.geteuid()
    listing = subprocess.check_output(['/bin/ps', '-axo', 'uid=,rss='], text=True, timeout=5)
    resident = sum(int(rss) for line in listing.splitlines()
                   for owner, rss in [line.split()] if int(owner) == uid) * 1024
    disk = subprocess.check_output(['/usr/bin/du', '-sk', *map(str, disk_paths)], text=True, timeout=10)
    allocated = sum(int(line.split(maxsplit=1)[0]) for line in disk.splitlines()) * 1024
    return {'memoryBytes': resident, 'diskBytes': allocated}


def peer_uid(connection):
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        raise OSError(ctypes.get_errno(), 'Could not identify local peer')
    return uid.value


def snapshot(scheduler):
    with scheduler._lock:
        lease = scheduler.lease or {}
        active = lease.get('status') == 'active'
        active_jobs = [scheduler.jobs[key] for key in scheduler.running_ids]
        job_labels = (job.scheme or job.result.get('bundle_id') for job in reversed(scheduler.jobs.values())
                      if job.lease_id == lease.get('id'))
        label = lease.get('name') or next((name for name in job_labels if name), None)
        status = {
            'state': 'In use' if active else ('Stopping' if active_jobs else 'Idle'),
            'sessionName': (label or f'Session {lease["id"][:8]}') if active else None,
            'leaseId': lease.get('id') if active else None,
        }
    try:
        meter = usage((LIBRARY, Path('/Users/iosbroker/.ios-worker')))
        vm = scheduler.runner._call({'op': 'usage'}, timeout=15)
        for key in ('memoryBytes', 'diskBytes'):
            status[key] = meter[key] + vm[key]
    except (OSError, ValueError, KeyError, RuntimeError, PolicyError, subprocess.SubprocessError):
        return status
    if vm.get('state') == 'ending':
        status['state'] = 'Stopping'
    return status


def start(scheduler, *, validation):
    config = LIBRARY / 'owner.json'
    if not config.exists():
        return
    require_protected_file(config)
    owner = json.loads(config.read_text())['uid']
    if type(owner) is not int or owner <= 0 or owner == os.geteuid():
        raise ValueError('Invalid local menu owner')
    path = LIBRARY / 'owner' / ('validation.sock' if validation else 'public.sock')
    parent = path.parent
    info = parent.lstat()
    if parent.is_symlink() or not parent.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Unsafe local menu socket directory')
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_socket() or path.lstat().st_uid != os.geteuid():
            raise ValueError('Unexpected local menu socket')
        path.unlink()
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    path.chmod(0o666)
    server.listen(4)

    def serve():
        meter_time, last_status = 0, None
        with server:
            while True:
                connection, _ = server.accept()
                try:
                    with connection:
                        if peer_uid(connection) != owner:
                            continue
                        connection.settimeout(3)
                        with connection.makefile('rb') as input_stream:
                            frame = input_stream.readline(1025)
                        if not frame.endswith(b'\n') or len(frame) > 1024:
                            continue
                        request = json.loads(frame)
                        if request == {'op': 'status'}:
                            if last_status is None or time.monotonic() - meter_time >= 2:
                                last_status = snapshot(scheduler)
                                meter_time = time.monotonic()
                            response = {'ok': True, **last_status}
                        elif isinstance(request, dict) and set(request) == {'op', 'leaseId'} and request['op'] == 'release':
                            scheduler.release_lease(request['leaseId'])
                            last_status = None
                            response = {'ok': True}
                        else:
                            response = {'ok': False}
                        connection.sendall(json.dumps(response).encode() + b'\n')
                except (OSError, ValueError, KeyError, RuntimeError, PolicyError, subprocess.SubprocessError):
                    continue

    threading.Thread(target=serve, daemon=True).start()
