"""Lease lifecycle and offline Tart backend for the private VM controller.

An offline network attachment drops every Ethernet frame. Control uses Tart's
host/guest agent channel, with no host filesystem shares. The VM service layers a host-validated package relay over the control channel.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path


class LeaseError(RuntimeError):
    pass


class LeaseController:
    """One expiring lease, one disposable guest, no job-completion shutdown.

    The backend must implement start(name), stop(name) and delete(name).
    Stop must verify termination. Failed cleanup blocks replacement leases.
    """
    def __init__(self, backend, *, clock=time.monotonic, max_ttl=300, max_lifetime=3600):
        self.backend = backend
        self.clock = clock
        self.max_ttl = max_ttl
        self.max_lifetime = max_lifetime
        self.lock = threading.RLock()
        self.cleanup_lock = threading.Lock()
        self.lease = None

    def _ttl(self, ttl):
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= self.max_ttl:
            raise LeaseError('invalid lease duration')
        return ttl

    def acquire(self, ttl=60):
        lease_id = secrets.token_hex(16)
        self.reserve(lease_id, ttl)
        return self.start(lease_id)

    def reserve(self, lease_id, ttl=60):
        ttl = self._ttl(ttl)
        if not isinstance(lease_id, str) or not re.fullmatch(r'[0-9a-f]{16,32}', lease_id):
            raise LeaseError('invalid lease id')
        with self.lock:
            if self.lease is not None:
                raise LeaseError('session busy or cleanup pending')
            now = self.clock()
            lease = {'id': lease_id, 'vm': 'lease-' + secrets.token_hex(8),
                     'expires': now + ttl, 'hard_deadline': now + self.max_lifetime, 'state': 'reserved'}
            self.lease = lease
            return {'leaseId': lease['id'], 'expiresIn': ttl}

    def start(self, lease_id):
        with self.lock:
            lease = self._authorized(lease_id)
            if lease['state'] == 'active':
                return {'leaseId': lease['id'], 'vm': lease['vm'], 'expiresIn': max(0, lease['expires'] - self.clock())}
            if lease['state'] != 'reserved' or self.clock() >= lease['expires']:
                raise LeaseError('lease expired or inactive')
            lease['state'] = 'starting'
        try:
            # No lock during boot: expiry/release must be able to cancel startup.
            self.backend.start(lease['vm'])
            with self.lock:
                if self.lease is not lease or lease['state'] != 'starting' or self.clock() >= lease['expires']:
                    raise LeaseError('lease ended during startup')
                lease['state'] = 'active'
                return {'leaseId': lease['id'], 'vm': lease['vm'], 'expiresIn': max(0, lease['expires'] - self.clock())}
        except Exception:
            with self.lock:
                if self.lease is lease:
                    lease['state'] = 'ending'
            self._cleanup(lease)
            raise

    def _authorized(self, lease_id):
        lease = self.lease
        if not lease or not isinstance(lease_id, str) or not hmac.compare_digest(lease['id'], lease_id):
            raise LeaseError('unknown lease')
        return lease

    def renew(self, lease_id, ttl=60):
        ttl = self._ttl(ttl)
        with self.lock:
            lease = self._authorized(lease_id)
            now = self.clock()
            if lease['state'] not in ('active', 'starting', 'reserved') or now >= lease['expires']:
                raise LeaseError('lease expired or inactive')
            lease['expires'] = min(now + ttl, lease['hard_deadline'])
            return {'expiresIn': max(0, lease['expires'] - now)}

    def status(self):
        with self.lock:
            if not self.lease:
                return {'state': 'idle', 'vm': None}
            return {'state': self.lease['state'], 'vm': self.lease['vm'],
                    'expiresIn': max(0, self.lease['expires'] - self.clock())}

    def require_active(self, lease_id):
        with self.lock:
            lease = self._authorized(lease_id)
            if lease['state'] != 'active' or self.clock() >= lease['expires']:
                raise LeaseError('lease expired or inactive')
            return lease['vm']

    def release(self, lease_id):
        with self.lock:
            lease = self._authorized(lease_id)
            lease['state'] = 'ending'
        self._cleanup(lease)

    def tick(self):
        with self.lock:
            lease = self.lease
            if not lease or (self.clock() < lease['expires'] and lease['state'] != 'ending'):
                return
            lease['state'] = 'ending'
        self._cleanup(lease)

    def close(self):
        with self.lock:
            lease = self.lease
            if lease:
                lease['state'] = 'ending'
        if lease:
            self._cleanup(lease)

    def _cleanup(self, lease):
        # Backend serializes start/stop/delete and records cancellation even if
        # start has not launched yet. Stop errors must never lead to deletion.
        with self.cleanup_lock:
            with self.lock:
                if self.lease is not lease:
                    return
            self.backend.stop(lease['vm'])
            self.backend.delete(lease['vm'])
            with self.lock:
                self.lease = None


class OfflineTart:
    """Trusted local trial backend. No uploaded commands, network or mounts."""
    def __init__(self, binary: Path, home: Path, base: str, log_root: Path, memory_mb=6144):
        self.binary = str(binary.resolve())
        self.home = home.resolve()
        self.base = base
        self.log_root = log_root
        self.memory_mb = memory_mb
        self.lock = threading.RLock()
        self.cancelled = set()
        self.processes = {}
        self.logs = {}
        self.drains = {}
        self.log_root.mkdir(parents=True, exist_ok=True)
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path.home()),
                    'TART_HOME': str(self.home), 'TART_NO_AUTO_PRUNE': '1', 'DO_NOT_TRACK': '1'}

    def call(self, *args, timeout=120):
        return subprocess.run([self.binary, *args], env=self.env, cwd='/private/tmp',
                              capture_output=True, text=True, timeout=timeout, check=True)

    def start(self, name):
        self._start(name,clone=True)

    def resume_provisioning(self,name):
        """Owner setup only; the public lease service always calls start()."""
        self._start(name,clone=False)

    def _start(self,name,*,clone):
        with self.lock:
            if name in self.cancelled:
                raise LeaseError('startup cancelled')
            if clone:
                self.call('clone', self.base, name, timeout=300)
            if name in self.cancelled:
                raise LeaseError('startup cancelled')
            self.call('set', name, '--cpu', '4', '--memory', str(self.memory_mb), '--display', '1024x768')
            # The only network attachment is a local socketpair with no uplink.
            # Read and discard all outbound frames; never inject inbound frames.
            host, guest = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            host.settimeout(0.25)
            stop = threading.Event()
            def discard():
                try:
                    while not stop.is_set():
                        try:
                            host.recv(65536)
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                finally:
                    host.close()
            thread = threading.Thread(target=discard, daemon=True)
            thread.start()
            self.drains[name] = (stop, thread)
            log = (self.log_root / (name + '.log')).open('ab', buffering=0)
            self.logs[name] = log
            try:
                process = subprocess.Popen([self.binary, 'run', name, '--no-graphics', '--no-audio',
                    '--no-clipboard', '--no-usb-accessories', '--no-keyboard', '--no-pointer', '--no-trackpad',
                    '--net-fd', str(guest.fileno())], env=self.env, cwd='/private/tmp',
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    pass_fds=(guest.fileno(),), start_new_session=True)
                self.processes[name] = process
            finally:
                guest.close()
        # Probe readiness without extending the lease or holding the backend lock.
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if name in self.cancelled or process.poll() is not None:
                raise LeaseError('VM stopped during startup; inspect trial log')
            try:
                self.call('exec', name, '/usr/bin/true', timeout=10)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(1)
        raise LeaseError('guest agent startup timed out')

    def stop(self, name):
        with self.lock:
            self.cancelled.add(name)
            process = self.processes.get(name)
            vm_path = self.home / 'vms' / name
            owned_process_running = process is not None and process.poll() is None
            stop_error = None
            if owned_process_running or (vm_path.exists() and self._running(name)):
                try:
                    self.call('stop', name, '--timeout', '15', timeout=30)
                except subprocess.SubprocessError as exc:
                    stop_error = exc
            if owned_process_running:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
            # Check actual Tart state too, so orphaned processes aren't ignored.
            if vm_path.exists() and self._running(name):
                raise LeaseError('VM termination not verified') from stop_error
            if name in self.drains:
                stop, thread = self.drains.pop(name)
                stop.set()
                thread.join(timeout=2)
            if name in self.logs:
                self.logs.pop(name).close()

    def _running(self, name):
        info = json.loads(self.call('get', name, '--format', 'json', timeout=10).stdout)
        if type(info.get('Running')) is not bool or info.get('State') not in {'running', 'stopped', 'suspended'}:
            raise LeaseError('Tart returned an unrecognized VM state')
        return info['Running'] or info['State'] == 'running'

    def delete(self, name):
        with self.lock:
            if (self.home / 'vms' / name).exists():
                self.call('delete', name)
            self.processes.pop(name, None)
