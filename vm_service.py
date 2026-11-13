"""Private lease-scoped Tart controller. Never runs uploaded code on the host."""
from __future__ import annotations
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import threading
import sys
import time
import hashlib
import io
import shutil
import tarfile
import sqlite3

_CODE_ROOT=str(Path(__file__).resolve().parent)
if _CODE_ROOT not in sys.path:
    sys.path.insert(0,_CODE_ROOT)

from containment import BUILD_TIMEOUT
from egress_policy import PACKAGE_HOSTS
from execution_policy import require_protected_file
from host_egress import Relay
from owner_menu import usage
from policy import require_id, check_device, PolicyError
from tart_lease import OfflineTart, LeaseController, LeaseError
from vm_transport import InputPipe, communicate, read_frame
from worker_cache import CacheFull, HEX, MAX_ARCHIVE, WorkerCache

ALLOWED_OPS = frozenset({'vm_start','prepare','build','launch','uitest','screenshot','logs','reset','boot','booted','shutdown','input'})
PERSONAL = '4D015300-4BAE-4E6D-89C9-BC4D454E4216'
FIELDS = frozenset({'op','lease_id','ttl','job_id','revision_id','session_id','device_id','scheme','recipe',
                    'public_env','configuration','for_testing','artifact_id','source_base64','approved','input_action','project','resume_id'})
GUEST_PAYLOAD = ('containment.py', 'policy.py', 'worker_exec.py', 'guest_rpc.py')

STOP_GUEST_SIMULATORS = b"""
import json
import os
import subprocess
import time

os.chdir('/private/tmp')
simctl = ['/usr/bin/xcrun', 'simctl']

def all_stopped(timeout):
    listing = json.loads(subprocess.check_output(simctl + ['list', 'devices', '-j'], timeout=timeout))
    return all(device['state'] == 'Shutdown'
               for devices in listing['devices'].values() for device in devices)

if not all_stopped(90):
    subprocess.run(simctl + ['shutdown', 'all'], check=True, timeout=60)
    deadline = time.monotonic() + 60
    while (remaining := deadline - time.monotonic()) > 0:
        if all_stopped(remaining):
            break
        time.sleep(min(0.5, remaining))
    else:
        raise SystemExit('simulators did not reach Shutdown')
"""


class BuildTart(OfflineTart):
    def __init__(self, *args, allowed=PACKAGE_HOSTS, base_identity=None, cache=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed = allowed
        self.relays = {}
        self.inputs = {}
        self.base_identity=base_identity
        self.cache = cache
        self.cache_projects = {}

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
        self.install_guest_payload(name)
        self.prepare_relay_certificate(name)
        with self.lock:
            if name in self.cancelled:
                raise LeaseError('startup cancelled')
            process = subprocess.Popen([self.binary,'exec','-i',name,'/usr/bin/sudo','-n',
                '/usr/bin/python3','-I','/Library/ios-worker/guest_proxy.py'], env=self.env,
                cwd='/private/tmp',stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=self.logs[name], start_new_session=True)
            relay = Relay(process, allowed=self.allowed, cache=self.cache,
                          project=self.cache_projects.get(name))
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

    def install_guest_payload(self, name):
        # Only the controller's reviewed modules are sent. A lease has not
        # received source or started its simulator at this point.
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as output:
            for filename in GUEST_PAYLOAD:
                path = Path(__file__).with_name(filename)
                if self.base_identity is not None:
                    require_protected_file(path)
                data = path.read_bytes()
                member = tarfile.TarInfo(filename)
                member.size = len(data)
                member.mode = 0o644
                output.addfile(member, io.BytesIO(data))
        with self.lock:
            if name in self.cancelled:
                raise LeaseError('startup cancelled')
        argv = [self.binary, 'exec', '-i', name, '/usr/bin/sudo', '-n', '/usr/bin/tar',
                '-xf', '-', '-C', '/Library/ios-worker']
        code, _, error = communicate(argv, archive.getvalue(), env=self.env, timeout=45, cap=65536)
        if code:
            raise LeaseError('reviewed guest payload failed to install: ' + error.decode(errors='replace')[-500:])

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
            self.cache_projects.pop(name, None)
            self.close_input(name)
            relay = self.relays.pop(name, None)
            if relay:
                relay.close()
            super().stop(name)

    def stop_simulators(self, name):
        self.close_input(name)
        command = [self.binary, 'exec', '-i', name, '/usr/bin/sudo', '-n', '-u', 'iosagent',
                   '/usr/bin/python3', '-I', '-']
        code, _, error = communicate(command, STOP_GUEST_SIMULATORS, env=self.env,
                                     timeout=225, cap=1024 * 1024)
        if code:
            raise LeaseError('guest simulators failed to shut down before build: '
                             + error.decode(errors='replace')[-500:])

    def close_input(self, name):
        with self.lock:
            channel = self.inputs.pop(name, None)
            if channel:
                channel.close()

    def transfer_app(self, vm, operation, device, *args, source=b'', sink=None):
        # The installed controller owns this fixed script. Only simulator IDs and
        # validated build selectors enter argv. The guest runs it as iosagent.
        helper = Path(__file__).with_name('guest_cache.py')
        if self.base_identity:
            require_protected_file(helper)
        return communicate([self.binary, 'exec', '-i', vm, '/usr/bin/sudo', '-n', '-u', 'iosagent',
                            '/usr/bin/python3', '-I', '-c', helper.read_text(),
                            operation, device, *args], source, env=self.env,
                           timeout=420 if operation == 'export' else 1260,
                           cap=MAX_ARCHIVE if sink else 1024 * 1024, sink=sink)

    def save_app(self, vm, project, resume_id, logical, payload):
        if not self.cache:
            return False
        try:
            with self.cache.stage(MAX_ARCHIVE, project, incremental=True) as (entry, stream):
                code, _, _ = self.transfer_app(vm, 'export', payload['device_id'],
                                               payload['revision_id'], payload['configuration'], sink=stream)
                if code or not stream.tell():
                    return False
                stream.flush()
                os.fsync(stream.fileno())
                digest = hashlib.sha256()
                with open(stream.name, 'rb') as staged:
                    for block in iter(lambda: staged.read(1024 * 1024), b''):
                        digest.update(block)
                return self.cache.publish(entry, 'binary', project, digest.hexdigest(),
                                          resume=resume_id, device=logical,
                                          base=self.base_identity['diskSHA256'])
        except (CacheFull, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
            return False

    def operation(self, name, request):
        if request['op'] == 'input':
            return self.input_operation(name, request)
        if request['op'] in {'shutdown', 'reset'}:
            self.close_input(name)
        timeout = {'prepare':2700,'build':BUILD_TIMEOUT+60,'uitest':2160,'launch':1320,'boot':1200,
                   'screenshot':1260,'reset':360}.get(request['op'],120)
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

    def input_operation(self, name, request):
        started = time.monotonic()
        payload = {key: request[key] for key in ('op', 'job_id', 'device_id', 'input_action')}
        with self.lock:
            if name in self.cancelled or name not in self.processes or self.processes[name].poll() is not None:
                raise LeaseError('simulator lease has stopped')
            channel = self.inputs.get(name)
            if channel is None:
                argv = [self.binary, 'exec', '-i', name, '/usr/bin/sudo', '-n', '-u', 'iosagent',
                        '/usr/bin/python3', '-I', '/Library/ios-worker/guest_rpc.py', '--input-loop']
                channel = self.inputs[name] = InputPipe(argv, self.env)
        try:
            reply = channel.exchange(payload, timeout=110)
        except (EOFError, ValueError, OSError, TimeoutError):
            with self.lock:
                if self.inputs.get(name) is channel:
                    self.inputs.pop(name)
                    channel.close()
            return {'ok': True, 'exitCode': 1, 'simulatorUI': {'schemaVersion': 1,
                    'error': {'code': 'actionOutcomeUnknown'}},
                    'simulatorTiming': {'controllerMs': round(1000 * (time.monotonic() - started))}}
        reply.pop('job_id')
        controller_ms = round(1000 * (time.monotonic() - started))
        guest_ms = reply.pop('guestMs', None)
        guest_command_ms = reply.pop('guestCommandMs', None)
        reply['simulatorTiming'] = {'controllerMs': controller_ms}
        if type(guest_ms) is int and 0 <= guest_ms <= 110000:
            reply['simulatorTiming']['guestMs'] = guest_ms
            if type(guest_command_ms) is int and 0 <= guest_command_ms <= guest_ms:
                reply['simulatorTiming']['guestCommandMs'] = guest_command_ms
        return reply


class Service:
    def __init__(self, backend, *, logical_device, guest_device, watch_devices=None, cache=None):
        logical_device = check_device(logical_device, {logical_device}, {PERSONAL})
        guest_device = check_device(guest_device, {guest_device}, {PERSONAL})
        self.devices = {logical_device: guest_device}
        if watch_devices is not None:
            watch_logical, watch_guest = watch_devices
            watch_logical = check_device(watch_logical, {watch_logical}, {PERSONAL})
            watch_guest = check_device(watch_guest, {watch_guest}, {PERSONAL})
            if watch_logical == logical_device or watch_guest == guest_device:
                raise LeaseError('iPhone and Watch mappings must be distinct')
            self.devices[watch_logical] = watch_guest
        self.backend = backend
        self.cache = cache
        self.controller = LeaseController(backend,max_ttl=300,max_lifetime=7200)
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
            return {'ok':True,'version':1,'cacheEnabled':self.cache is not None,'backend':'tart','network':'disconnected-ethernet+allowlisted-connect',
                    'filesystem':'no-host-shares','signing':False,'usb':False}
        if op == 'status':
            return {'ok':True,**self.controller.status(),'lastStopReason':self.last_stop_reason}
        if op == 'usage':
            roots = (self.backend.home, self.backend.log_root, self.backend.home.parent/'controller.log')
            if self.cache:
                roots += (self.cache.root,)
            return {'ok':True, **self.controller.status(), **usage(roots)}
        lease = request.get('lease_id')
        if op == 'reserve':
            project = request.get('project')
            resume = request.get('resume_id')
            if project is not None and (not self.cache or not isinstance(project, str) or not HEX.fullmatch(project)):
                raise LeaseError('Invalid cache project')
            if resume is not None and (not project or not isinstance(resume, str) or not HEX.fullmatch(resume)):
                raise LeaseError('Invalid cache resume ID')
            new_resume = request.get('session_id')
            if project and (not isinstance(new_resume, str) or not HEX.fullmatch(new_resume)):
                raise LeaseError('Invalid new cache resume ID')
            device = None
            if resume:
                metadata = self.cache.lookup_resume(resume, project)
                if not metadata or metadata[1] != self.backend.base_identity['diskSHA256']:
                    return {'ok': True, 'cacheMiss': True}
                device = check_device(metadata[0], self.devices.keys(), {PERSONAL})
                if request.get('device_id') and request['device_id'] != device:
                    raise LeaseError('Cached build targets another simulator')
            with self.controller.lock:
                result = self.controller.reserve(lease,request.get('ttl',300))
                active = self.controller.lease
                active['project'] = project
                active['resume_id'] = resume
                active['new_resume_id'] = new_resume
                if project:
                    self.backend.cache_projects[active['vm']] = project
            if device:
                result['deviceId'] = device
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
        if op not in ALLOWED_OPS and op != 'restore':
            raise LeaseError('unsupported operation')
        if op == 'input' and not request.get('device_id'):
            raise LeaseError('simulator input requires a mapped device')
        if request.get('device_id'):
            check_device(request['device_id'],self.devices.keys(),{PERSONAL})
        with self.job_lock:
            if op in {'booted','shutdown'} and self.controller.status()['state']!='active':
                return {'ok':True,'booted':False} if op=='booted' else {'ok':True,'log':'simulator is off'}
            # Boot admission is performed by the broker. A direct private
            # controller caller remains the trusted broker account, not a job.
            if op != 'input':
                self.controller.start(lease)
            vm = self.controller.require_active(lease)
            with self.controller.lock:
                active = self.controller._authorized(lease)
                project = active['project']
                resume = active['resume_id']
                new_resume = active['new_resume_id']
            if op == 'restore':
                if not self.cache or not project or not resume:
                    raise LeaseError('Lease does not have a cached app')
                with self.cache.read('binary', resume, project=project) as cached:
                    if not cached or cached[-1] != self.backend.base_identity['diskSHA256'] or cached[-2] != request['device_id']:
                        raise LeaseError('Cached app was evicted or is incompatible')
                    code, output, error = self.backend.transfer_app(vm, 'restore', self.devices[request['device_id']],
                                                                     source=cached[0])
                    if code:
                        raise LeaseError('Cached app restore failed: '+error.decode(errors='replace')[-500:])
                    self.controller.require_active(lease)
                    return json.loads(output)
            if op=='vm_start':
                return {'ok':True,'log':'leased VM ready; simulator remains off'}
            payload = dict(request)
            payload.pop('lease_id',None)
            payload.pop('ttl',None)
            if payload.get('device_id'):
                payload['device_id'] = self.devices[check_device(payload['device_id'],self.devices.keys(),{PERSONAL})]
            source = payload.get('source_base64')
            revision = payload.get('revision_id')
            if revision and op in {'prepare','build','launch','uitest'}:
                require_id(revision,'revision')
                if revision in self.loaded:
                    payload.pop('source_base64',None)
                elif not isinstance(source,str):
                    raise LeaseError('source must be staged into the leased guest')
            try:
                if op in {'prepare', 'build'}:
                    self.backend.stop_simulators(vm)
                    self.controller.require_active(lease)
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
            if result.get('ok') is True and op == 'build' and project and new_resume:
                if payload.get('device_id') and self.backend.save_app(vm, project, new_resume, request['device_id'], payload):
                    result['resumeId'] = new_resume
                    with self.controller.lock:
                        active['new_resume_id'] = secrets.token_hex(32)
                else:
                    result['cacheStored'] = False
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
                    connection.settimeout(3450)
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
    cache = None
    if not args.trial:
        try:
            cache = WorkerCache(Path(cfg['home']).parent / 'cache')
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(f'Worker cache unavailable: {type(exc).__name__}', file=sys.stderr, flush=True)
    backend=BuildTart(Path(cfg['tart']),Path(cfg['home']),cfg['base'],Path(cfg['logs']),
                      cfg.get('memory_mb',6144),allowed=frozenset(cfg.get('allowed_hosts',PACKAGE_HOSTS)),
                      base_identity=cfg.get('base_identity'),cache=cache)
    service=Service(backend,logical_device=cfg['logical_device'],guest_device=cfg['guest_device'],
                    watch_devices=cfg.get('watch_devices'),cache=cache)
    stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,lambda *_:stop.set())
    serve(service,Path(cfg['socket']),stop,mode=0o600 if args.trial else 0o660)


if __name__=='__main__':
    main()
