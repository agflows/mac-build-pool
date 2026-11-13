"""Local owner UI channel. Authentication uses the connecting macOS UID."""
import ctypes
import errno
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
RUSAGE_INFO_V0 = 0


class RUsageInfoV0(ctypes.Structure):
    """Darwin's rusage_info_v0 from sys/resource.h."""
    _fields_ = [
        ('uuid', ctypes.c_ubyte * 16),
        ('user_time', ctypes.c_uint64),
        ('system_time', ctypes.c_uint64),
        ('package_idle_wakeups', ctypes.c_uint64),
        ('interrupt_wakeups', ctypes.c_uint64),
        ('pageins', ctypes.c_uint64),
        ('wired_size', ctypes.c_uint64),
        ('resident_size', ctypes.c_uint64),
        ('physical_footprint', ctypes.c_uint64),
        ('start_time', ctypes.c_uint64),
        ('exit_time', ctypes.c_uint64),
    ]


def role_memory_footprint():
    """Use the same per-process footprint counter as Activity Monitor."""
    read_usage = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True).proc_pid_rusage
    read_usage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(RUsageInfoV0)]
    read_usage.restype = ctypes.c_int
    uid = os.geteuid()
    listing = subprocess.check_output(['/bin/ps', '-axo', 'uid=,pid='], text=True, timeout=5)
    total = 0
    for line in listing.splitlines():
        owner, pid = map(int, line.split())
        if owner != uid:
            continue
        counters = RUsageInfoV0()
        if read_usage(pid, RUSAGE_INFO_V0, ctypes.byref(counters)):
            error = ctypes.get_errno()
            if error == errno.ESRCH:
                continue
            raise OSError(error, os.strerror(error))
        total += counters.physical_footprint
    return total


def usage(disk_paths):
    """Memory footprint for this role and allocated bytes for its data roots."""
    paths = [str(path) for path in disk_paths if path.exists()]
    disk = subprocess.check_output(['/usr/bin/du', '-sk', *paths], text=True, timeout=10) if paths else ''
    allocated = sum(int(line.split(maxsplit=1)[0]) for line in disk.splitlines()) * 1024
    return {'memoryBytes': role_memory_footprint(), 'memoryMetric': 'footprint', 'diskBytes': allocated}


def broker_disk_paths():
    data = LIBRARY / 'data'
    # Retired native builds can have their own private directories beneath
    # work/tmp. Measure the installed isolated worker's actual storage roots.
    return [*(path for path in LIBRARY.iterdir() if path.is_file()), LIBRARY / 'tart.app',
            data / 'artifacts', data / 'spool', data / 'export', Path('/Users/iosbroker/.ios-worker')]


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
        if active:
            waiting = next((job for job in scheduler.jobs.values()
                            if job.lease_id == lease['id'] and job.status == 'waiting_for_approval'), None)
            if waiting is not None:
                status['waitingJobId'] = waiting.id
                status['waitingJobKind'] = waiting.kind
    try:
        meter = usage(broker_disk_paths())
        vm = scheduler.runner._call({'op': 'usage'}, timeout=15)
        status['diskBytes'] = meter['diskBytes'] + vm['diskBytes']
        if vm.get('memoryMetric') == meter['memoryMetric']:
            status['memoryBytes'] = meter['memoryBytes'] + vm['memoryBytes']
            status['memoryMetric'] = meter['memoryMetric']
    except (OSError, ValueError, KeyError, RuntimeError, PolicyError, subprocess.SubprocessError):
        return status
    if vm.get('state') == 'ending':
        status['state'] = 'Stopping'
    return status


def start(scheduler, *, validation, instructions):
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
                        elif request == {'op': 'agent_instructions'}:
                            try:
                                response = {'ok': True, 'instructions': instructions()}
                            except (OSError, ValueError, KeyError, RuntimeError, PolicyError, SystemExit):
                                response = {'ok': False}
                        elif isinstance(request, dict) and set(request) == {'op', 'leaseId'} and request['op'] == 'release':
                            scheduler.release_lease(request['leaseId'])
                            last_status = None
                            response = {'ok': True}
                        elif isinstance(request, dict) and set(request) == {'op', 'leaseId', 'jobId'} and request['op'] == 'approve':
                            try:
                                scheduler.approve_waiting_job(request['leaseId'], request['jobId'])
                            except (KeyError, PolicyError):
                                response = {'ok': False}
                            else:
                                response = {'ok': True}
                            last_status = None
                        else:
                            response = {'ok': False}
                        connection.sendall(json.dumps(response).encode() + b'\n')
                except (OSError, ValueError, KeyError, RuntimeError, PolicyError, subprocess.SubprocessError):
                    continue

    threading.Thread(target=serve, daemon=True).start()
