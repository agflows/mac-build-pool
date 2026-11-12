"""Private lease-scoped Tart controller. Never runs uploaded code on the host."""
from __future__ import annotations
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import sys
import time
import hashlib
import shutil

_CODE_ROOT=str(Path(__file__).resolve().parent)
if _CODE_ROOT not in sys.path:
    sys.path.insert(0,_CODE_ROOT)

from egress_policy import PACKAGE_HOSTS
from execution_policy import require_protected_file
from host_egress import Relay
from policy import require_id, check_device, PolicyError
from tart_lease import OfflineTart, LeaseController, LeaseError
from vm_transport import communicate, read_frame

ALLOWED_OPS = frozenset({'vm_start','prepare','build','launch','uitest','screenshot','logs','reset','boot','booted','shutdown'})
PERSONAL = '4D015300-4BAE-4E6D-89C9-BC4D454E4216'
FIELDS = frozenset({'op','lease_id','ttl','job_id','revision_id','session_id','device_id','scheme','recipe',
                    'public_env','configuration','for_testing','artifact_id','source_base64','approved'})


class BuildTart(OfflineTart):
    def __init__(self, *args, allowed=PACKAGE_HOSTS, base_identity=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed = allowed
        self.relays = {}
        self.base_identity=base_identity

    def check_base(self):
        if self.base_identity is None:
            return
        root=self.home/'vms'/self.base
        disk=root/'disk.img'
        if disk.is_symlink() or not disk.is_file():
            raise LeaseError('reviewed base image is missing or unsafe')
        info=disk.stat()
        if (info.st_size!=self.base_identity['size'] or info.st_mtime_ns!=self.base_identity['mtimeNs']
                or hashlib.sha256((root/'config.json').read_bytes()).hexdigest()!=self.base_identity['configSHA256']):
            raise LeaseError('base image changed; owner review and validation are required')

    def start(self, name):
        self.check_base()
        super().start(name)
        self.prepare_relay_certificate(name)
        with self.lock:
            if name in self.cancelled:
                raise LeaseError('startup cancelled')
            process = subprocess.Popen([self.binary,'exec','-i',name,'/usr/bin/sudo','-n',
                '/usr/bin/python3','-I','/Library/ios-worker/guest_proxy.py'], env=self.env,
                cwd='/private/tmp',stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=self.logs[name], start_new_session=True)
            relay = Relay(process, allowed=self.allowed)
            self.relays[name] = relay
            threading.Thread(target=relay.run, daemon=True).start()
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if name in self.cancelled or process.poll() is not None:
                raise LeaseError('guest package relay stopped during startup')
            try:
                self.call('exec',name,'/usr/bin/python3','-c',
                    "import socket;s=socket.create_connection(('127.0.0.1',18741),2);s.close()",timeout=10)
                return
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
                time.sleep(0.25)
        raise LeaseError('guest package relay startup timed out')

    def prepare_relay_certificate(self, name):
        # The base CA and its key stay inside the guest. Issue a leaf for the
        # owner-controlled destinations before any project enters the clone.
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        domain = re.compile(rf'{label}(?:\.{label})+')
        if any(not domain.fullmatch(host) for host in self.allowed):
            raise LeaseError('invalid configured relay hostname')
        san = ','.join(f'DNS:{host}' for host in sorted(self.allowed))
        extensions = (
            'basicConstraints=critical,CA:false\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth\n'
            f'subjectAltName={san}\n'
        ).encode('ascii')
        root = '/Library/ios-worker'
        command = [self.binary, 'exec', '-i', name, '/usr/bin/sudo', '-n', '/usr/bin/openssl',
                   'x509', '-req', '-in', f'{root}/proxy-leaf.csr', '-CA', f'{root}/proxy-ca.pem',
                   '-CAkey', f'{root}/proxy-ca.key', '-CAcreateserial', '-days', '365', '-sha256',
                   '-extfile', '/dev/stdin', '-out', f'{root}/proxy-leaf.pem']
        code, _, error = communicate(command, extensions, env=self.env, timeout=30, cap=1024 * 1024)
        if code:
            raise LeaseError('guest relay certificate setup failed: ' + error.decode(errors='replace')[-500:])

    def stop(self, name):
        with self.lock:
            relay = self.relays.pop(name, None)
            if relay:
                relay.close()
            super().stop(name)

    def operation(self, name, request):
        timeout = {'prepare':2700,'build':1860,'uitest':1380,'launch':600,'boot':420,
                   'screenshot':480,'reset':300}.get(request['op'],120)
        code, stdout, stderr = communicate([self.binary,'exec','-i',name,'/usr/bin/sudo','-n','-u','iosagent',
            '/usr/bin/python3','-I','/Library/ios-worker/guest_rpc.py'],json.dumps(request).encode()+b'\n',
            env=self.env, timeout=timeout)
        try:
            result = json.loads(stdout)
        except ValueError as exc:
            raise LeaseError('guest returned invalid result: '+stderr.decode(errors='replace')[-300:]) from exc
        if not isinstance(result,dict) or code != 0 or result.get('ok') is not True:
            if isinstance(result,dict):
                return result
            raise LeaseError('guest operation failed')
        return result


class Service:
    def __init__(self, backend, *, logical_device, guest_device):
        check_device(logical_device,{logical_device},{PERSONAL})
        check_device(guest_device,{guest_device},{PERSONAL})
        self.backend = backend
        self.controller = LeaseController(backend,max_ttl=300,max_lifetime=7200)
        self.logical_device = logical_device
        self.guest_device = guest_device
        self.job_lock = threading.Lock()
        self.loaded = set()
        self.last_stop_reason=None
        self.last_lease=None

    def dispatch(self, request):
        if not isinstance(request,dict) or set(request)-FIELDS:
            raise LeaseError('invalid controller request')
        op = request.get('op')
        if op == 'capabilities':
            self.backend.check_base()
            return {'ok':True,'version':1,'backend':'tart','network':'disconnected-ethernet+allowlisted-connect',
                    'filesystem':'no-host-shares','signing':False,'usb':False}
        if op == 'status':
            return {'ok':True,**self.controller.status(),'lastStopReason':self.last_stop_reason}
        lease = request.get('lease_id')
        if op == 'reserve':
            result = self.controller.reserve(lease,request.get('ttl',300))
            self.loaded.clear()
            self.last_stop_reason=None
            self.last_lease=lease
            return {'ok':True,**result}
        if op == 'renew':
            return {'ok':True,**self.controller.renew(lease,request.get('ttl',300))}
        if op == 'release':
            if self.controller.lease is None and lease==self.last_lease:
                return {'ok':True,'released':True}
            self.controller.release(lease)
            self.loaded.clear()
            return {'ok':True,'released':True}
        if op not in ALLOWED_OPS:
            raise LeaseError('unsupported operation')
        if request.get('device_id'):
            check_device(request['device_id'],{self.logical_device},{PERSONAL})
        with self.job_lock:
            if op in {'booted','shutdown'} and self.controller.status()['state']!='active':
                return {'ok':True,'booted':False} if op=='booted' else {'ok':True,'log':'simulator is off'}
            # Boot admission is performed by the broker. A direct private
            # controller caller remains the trusted broker account, not a job.
            self.controller.start(lease)
            vm = self.controller.require_active(lease)
            if op=='vm_start':
                return {'ok':True,'log':'leased VM ready; simulator remains off'}
            payload = dict(request)
            payload.pop('lease_id',None)
            payload.pop('ttl',None)
            if payload.get('device_id'):
                payload['device_id'] = self.guest_device
            source = payload.get('source_base64')
            revision = payload.get('revision_id')
            if revision and op in {'prepare','build','launch','uitest'}:
                require_id(revision,'revision')
                if revision in self.loaded:
                    payload.pop('source_base64',None)
                elif not isinstance(source,str):
                    raise LeaseError('source must be staged into the leased guest')
            try:
                result = self.backend.operation(vm,payload)
            except Exception:
                if self.controller.lease and self.controller.lease['id']==lease:
                    self.controller.release(lease)
                raise
            self.controller.require_active(lease)
            if result.get('ok') is not True and result.get('error') in {'job_timeout','storage_limit'}:
                self.last_stop_reason='guest '+result['error']
                self.controller.release(lease)
                self.loaded.clear()
                return result
            if result.get('ok') is True and revision:
                if op=='reset':
                    self.loaded.discard(revision)
                elif op in {'prepare','build','launch','uitest'}:
                    self.loaded.add(revision)
            return result


def serve(service, path: Path, stop, mode=0o600):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (path.parent/'vm.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Reap only this controller's namespace after restart, before readiness.
        for vm in (service.backend.home/'vms').glob('lease-*'):
            if re.fullmatch(r'lease-[0-9a-f]{16}',vm.name):
                service.backend.stop(vm.name)
                service.backend.delete(vm.name)
        if path.exists():
            if not path.is_socket():
                raise LeaseError('unexpected socket path')
            path.unlink()
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(path))
        path.chmod(mode)
        server.listen(8)
        server.settimeout(0.5)
        slots=threading.BoundedSemaphore(8)
        def client(connection):
            try:
                with connection:
                    connection.settimeout(3000)
                    try:
                        request=read_frame(connection)
                        response=service.dispatch(request)
                    except Exception as exc:
                        response={'ok':False,'error':getattr(exc,'code','vm_unavailable'),'message':str(exc)[-65536:]}
                    connection.sendall(json.dumps(response,separators=(',',':')).encode()+b'\n')
            finally:
                slots.release()
        def watchdog():
            last_memory_check=0
            last_failure_log=None
            while not stop.wait(0.25):
                try:
                    service.controller.tick()
                    if service.controller.lease and time.monotonic()-last_memory_check>=5:
                        last_memory_check=time.monotonic()
                        try:
                            level=int(subprocess.check_output(['/usr/sbin/sysctl','-n','kern.memorystatus_vm_pressure_level'],text=True,timeout=5))
                        except (ValueError,OSError,subprocess.SubprocessError):
                            service.last_stop_reason='host memory pressure is unavailable'
                            service.controller.close()
                            continue
                        if level>=4:
                            service.last_stop_reason='urgent host memory pressure'
                            service.controller.close()
                        elif shutil.disk_usage(service.backend.home).free<2*1024**3:
                            service.last_stop_reason='host free disk below 2 GiB'
                            service.controller.close()
                except Exception as exc:
                    # Cleanup remains pending; replacement leases are blocked.
                    now=time.monotonic()
                    if last_failure_log is None or now-last_failure_log>=30:
                        print(f'VM watchdog failed: {type(exc).__name__}: {str(exc)[-500:]}',
                              file=sys.stderr, flush=True)
                        last_failure_log=now
        threading.Thread(target=watchdog,daemon=True).start()
        try:
            while not stop.is_set():
                try:
                    connection,_=server.accept()
                except socket.timeout:
                    continue
                if slots.acquire(blocking=False):
                    threading.Thread(target=client,args=(connection,),daemon=True).start()
                else:
                    connection.close()
        finally:
            service.controller.close()
            server.close()
            path.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config',type=Path)
    parser.add_argument('--trial',action='store_true',help='Local validation only; never used by installed broker')
    args=parser.parse_args()
    if not args.trial:
        require_protected_file(args.config)
    cfg=json.loads(args.config.read_text())
    if cfg.get('memory_mb',6144) not in (4096,6144,8192):
        raise LeaseError('VM memory budget must be 4, 6 or 8 GB')
    if not args.trial:
        if not isinstance(cfg.get('base_identity'),dict):
            raise LeaseError('reviewed base image identity is required')
        if (Path(cfg['tart'])!=Path('/Library/ios-worker/tart.app/Contents/MacOS/tart')
                or Path(cfg['home'])!=Path('/Users/iosvm/.tart') or cfg['base']!='worker-base'
                or Path(cfg['socket'])!=Path('/Library/ios-worker/control/vm.sock')):
            raise LeaseError('installed controller paths are fixed')
        require_protected_file(Path(cfg['tart']),executable=True)
    backend=BuildTart(Path(cfg['tart']),Path(cfg['home']),cfg['base'],Path(cfg['logs']),
                      cfg.get('memory_mb',6144),allowed=frozenset(cfg.get('allowed_hosts',PACKAGE_HOSTS)),
                      base_identity=cfg.get('base_identity'))
    service=Service(backend,logical_device=cfg['logical_device'],guest_device=cfg['guest_device'])
    stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,lambda *_:stop.set())
    serve(service,Path(cfg['socket']),stop,mode=0o600 if args.trial else 0o660)


if __name__=='__main__':
    main()
