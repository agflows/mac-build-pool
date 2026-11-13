#!/usr/bin/env python3
"""Stage a protected Tart controller, validate privately, then activate explicitly.

Root only. The staged validation broker listens only on physical-host loopback
with a new private token. Public build execution remains off until a real
acceptance report is checked by --activate.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import tempfile
import re
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import install_system as install
from containment import CODE_FILES,launch_path_problems
from egress_policy import PACKAGE_HOSTS

LIB=Path('/Library/ios-worker')
VMHOME=Path('/Users/iosvm')
VMPLIST=Path('/Library/LaunchDaemons/com.iosworker.vmcontroller.plist')
TESTPLIST=Path('/Library/LaunchDaemons/com.iosworker.validation.plist')
BROKER=Path('/Users/iosbroker/.ios-worker')
HOST_PYTHON=Path('/Applications/Xcode.app/Contents/Developer/usr/bin/python3')


def run(argv,check=True):
    result=subprocess.run(argv,check=False,capture_output=True,text=True)
    if check and result.returncode:
        detail=(result.stdout+result.stderr)[-1200:]
        for value in argv:
            if re.fullmatch(r'[0-9a-fA-F]{32,}',value):detail=detail.replace(value,'[redacted]')
        # CalledProcessError includes argv, which can contain generated account
        # passwords. Never expose the privileged argument list in a traceback.
        raise SystemExit('Setup failed in '+Path(argv[0]).name+': '+detail)
    return result


def code_hash():
    digest=hashlib.sha256()
    for name in sorted(CODE_FILES):digest.update(name.encode()+b'\0'+(LIB/name).read_bytes())
    return digest.hexdigest()


def request(url,token,method,path,body=None):
    from cli import call
    return call(url,token,method,path,body)


def idle(url,token,label='com.iosworker.broker'):
    try:status,raw=request(url,token,'GET','/v1/health')
    except urllib.error.URLError as exc:
        status=run(['/bin/launchctl','print','system/'+label],False)
        if status.returncode!=0:return
        raise SystemExit('Existing broker is unreachable; verify its idle state before maintenance') from exc
    if status!=200:raise SystemExit('Cannot authenticate existing broker for maintenance')
    info=json.loads(raw)
    if info.get('running') or info.get('queued') or info.get('leaseActive'):
        raise SystemExit('Existing broker has work or an active lease; finish/release it first')
    if 'leaseActive' not in info:
        # Legacy lease acquisition has no VM/simulator side effect; verify and
        # immediately release our own probe lease. Never release someone else's.
        status,raw=request(url,token,'POST','/v1/leases',b'{}')
        if status!=201:raise SystemExit('Legacy broker has an active lease; release it before maintenance')
        lease=json.loads(raw)['leaseId']
        status,_=request(url,token,'POST','/v1/leases/'+lease+'/release',b'{}')
        if status!=200:raise SystemExit('Could not release maintenance probe lease')


def root_file(path,data,mode=0o644):
    if path.is_symlink():raise SystemExit('Refusing unexpected installer symlink')
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.vm-install-')
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),mode)
        os.replace(name,path)
        os.chown(path,0,0)
        run(['/bin/chmod','-N',str(path)])
    finally:
        if os.path.exists(name):os.unlink(name)


def ensure_vm_account():
    try:account=pwd.getpwnam('iosvm')
    except KeyError:
        uid=install._next_uid()
        for field,value in [('UserShell','/usr/bin/false'),('RealName','Build VM Controller'),
                            ('UniqueID',str(uid)),('PrimaryGroupID','20'),
                            ('NFSHomeDirectory',str(VMHOME)),('IsHidden','1')]:
            run(['/usr/bin/dscl','.','-create','/Users/iosvm',field,value])
        run(['/usr/bin/dscl','.','-passwd','/Users/iosvm',secrets.token_hex(32)])
        account=pwd.getpwnam('iosvm')
    if account.pw_uid==0 or account.pw_dir!=str(VMHOME) or install._member('iosvm','admin'):
        raise SystemExit('iosvm must be a dedicated non-admin account')
    if VMHOME.is_symlink():raise SystemExit('Unexpected controller-home symlink')
    VMHOME.mkdir(mode=0o700,exist_ok=True)
    os.chown(VMHOME,account.pw_uid,20);VMHOME.chmod(0o700)
    if run(['/usr/bin/dscl','.','-read','/Groups/iosworker-control'],False).returncode:
        run(['/usr/sbin/dseditgroup','-o','create','iosworker-control'])
    for user in ('iosvm','iosbroker'):
        run(['/usr/sbin/dseditgroup','-o','edit','-a',user,'-t','user','iosworker-control'])
    import grp
    return account.pw_uid,grp.getgrnam('iosworker-control').gr_gid


def launch(plist,label,data):
    root_file(plist,plistlib.dumps(data))
    run(['/usr/bin/plutil','-lint',str(plist)])
    run(['/bin/launchctl','bootout','system/'+label],False)
    run(['/bin/launchctl','bootstrap','system',str(plist)])
    run(['/bin/launchctl','enable','system/'+label],False)


def clone_base(base, target):
    """Require a same-volume copy-on-write clone of the large disk."""
    disk = base / 'disk.img'
    if disk.is_symlink() or not disk.is_file():
        raise SystemExit('Reviewed base disk is missing or unsafe')
    target.mkdir(mode=0o700)
    try:
        clonefile = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True).clonefile
        clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        clonefile.restype = ctypes.c_int
        if clonefile(os.fsencode(disk), os.fsencode(target / 'disk.img'), 0):
            reason = os.strerror(ctypes.get_errno())
            raise SystemExit(f'Cannot clone the worker disk ({reason}). Keep the base and worker on the same APFS volume.')
        for name in ('config.json', 'nvram.bin'):
            item = base / name
            if item.is_symlink() or not item.is_file():
                raise SystemExit(f'Reviewed base is missing a regular {name}')
            shutil.copy2(item, target / name)
    except BaseException:
        shutil.rmtree(target)
        raise


def install_base(base, target, *, replace):
    if target.is_symlink():
        raise SystemExit('Unexpected controller base symlink')
    if not target.exists():
        clone_base(base,target)
        return
    if any(path.is_symlink() or not path.is_file()
           for path in (target/'disk.img',target/'config.json')):
        raise SystemExit('Existing controller base is incomplete or unsafe')
    if ((target/'disk.img').stat().st_size==(base/'disk.img').stat().st_size
            and (target/'disk.img').stat().st_mtime_ns==(base/'disk.img').stat().st_mtime_ns
            and (target/'config.json').read_bytes()==(base/'config.json').read_bytes()):
        return
    if not replace:
        raise SystemExit('Existing base differs from the pristine image; review it before using --replace-base')
    if any(target.parent.glob('lease-*')) or run(
            ['/bin/launchctl','print','system/com.iosworker.vmcontroller'],False).returncode==0:
        raise SystemExit('Stop the idle controller and resolve any remaining lease guests before replacing its base')
    staging=Path(tempfile.mkdtemp(prefix='.base-stage-',dir=target.parent))
    candidate=staging/'candidate'
    previous=staging/'previous'
    promoted=False
    try:
        clone_base(base,candidate)
        target.rename(previous)
        try:
            candidate.rename(target)
            promoted=True
        except OSError:
            try:
                previous.rename(target)
            except OSError as exc:
                raise SystemExit(f'Base rollback needs maintenance. The previous base is at {previous}') from exc
            raise
    finally:
        if promoted or not previous.exists():
            shutil.rmtree(staging)


def stage(args):
    runtime=args.trial_root
    base=runtime/'state/vms/worker-base'
    if (base.is_symlink() or any(path.is_symlink() or not path.is_file()
                                for path in (base/'disk.img',base/'config.json'))):
        raise SystemExit('Provision the powered-off reviewed worker-base first')
    if not HOST_PYTHON.is_file() or not os.access(HOST_PYTHON,os.X_OK):
        raise SystemExit('The approved Xcode Python interpreter is missing')
    if not (runtime/'provisioning/guest-device.txt').is_file():raise SystemExit('Missing guest simulator provision evidence')
    from broker import tailscale_ipv4
    from cli import read_secret
    from vm_transport import rpc
    if run(['/bin/launchctl','print','system/com.iosworker.broker'],False).returncode==0:
        url='http://'+tailscale_ipv4()+':8741'
        idle(url,read_secret(BROKER/'token'))
    if run(['/bin/launchctl','print','system/com.iosworker.validation'],False).returncode==0:
        idle('http://127.0.0.1:8742',read_secret(BROKER/'validation-token'),'com.iosworker.validation')
    if run(['/bin/launchctl','print','system/com.iosworker.vmcontroller'],False).returncode==0:
        control_socket=LIB/'control/vm.sock'
        if control_socket.exists():
            state=rpc(control_socket,{'op':'status'},timeout=5)
            if state.get('ok') is not True or state.get('state')!='idle':
                raise SystemExit('Private controller has an active or pending lease')
        elif any((VMHOME/'.tart/vms').glob('lease-*')):
            raise SystemExit('Private controller is unreachable with a remaining guest')
        run(['/bin/launchctl','bootout','system/com.iosworker.validation'],False)
        run(['/bin/launchctl','bootout','system/com.iosworker.vmcontroller'],False)
    # All preparations above are read-only; only the confirmed-idle named broker
    # is stopped here. Never kill arbitrary processes using a port.
    run(['/bin/launchctl','bootout','system/com.iosworker.broker'],False)
    install._ensure_user()
    install._install_code(ROOT)
    install._install_data()
    install._retire_native_host_launcher()
    install._write_execution_policy(False)
    install._install_daemon(ROOT)
    public_plist=plistlib.loads(install.PLIST_DST.read_bytes())
    public_plist['ProgramArguments'][0]=str(HOST_PYTHON)
    root_file(install.PLIST_DST,plistlib.dumps(public_plist))
    uid,gid=ensure_vm_account()
    destination=LIB/'tart.app'
    if destination.is_symlink():raise SystemExit('Unexpected Tart runtime symlink')
    if destination.exists():
        installed=(destination/'Contents/MacOS/tart').read_bytes()
        approved=(runtime/'tart.app/Contents/MacOS/tart').read_bytes()
        if hashlib.sha256(installed).digest()!=hashlib.sha256(approved).digest():
            raise SystemExit('Installed Tart differs from the reviewed runtime; review before replacing it')
    else:
        shutil.copytree(runtime/'tart.app',destination,symlinks=True)
        for directory,dirs,files in os.walk(destination,followlinks=False):
            os.chown(directory,0,0)
            os.chmod(directory,0o755)
            for name in files:
                path=Path(directory)/name
                if not path.is_symlink():
                    os.chown(path,0,0)
                    path.chmod(0o755 if os.access(path,os.X_OK) else 0o644)
    # Existing signed bundles may be protected by macOS App Management.
    # Audit their ownership and modes without rewriting the same permissions.
    for directory,dirs,files in os.walk(destination,followlinks=False):
        paths=[Path(directory),*(Path(directory)/name for name in files)]
        for path in paths:
            info=path.lstat()
            if info.st_uid!=0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode&0o022):
                raise SystemExit('Installed Tart bundle is not root-controlled')
    run(['/usr/bin/codesign','--verify','--deep','--strict',str(destination)])
    tart_home=VMHOME/'.tart'
    target=tart_home/'vms/worker-base'
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    install_base(base,target,replace=args.replace_base)
    for directory,dirs,files in os.walk(tart_home,followlinks=False):
        os.chown(directory,uid,20)
        for name in files:os.chown(Path(directory)/name,uid,20,follow_symlinks=False)
    control=LIB/'control'
    if control.is_symlink():raise SystemExit('Unexpected control-directory symlink')
    control.mkdir(mode=0o750,exist_ok=True);os.chown(control,uid,gid);control.chmod(0o750)
    run(['/bin/chmod','-N',str(control)])
    public=json.loads(args.public_env.read_text())
    import urllib.parse
    backend=urllib.parse.urlsplit(public['EXPO_PUBLIC_SUPABASE_URL'])
    if backend.scheme!='https' or not backend.hostname:raise SystemExit('Public backend must use HTTPS')
    cfg={'tart':str(destination/'Contents/MacOS/tart'),'home':str(tart_home),'base':'worker-base',
         'socket':str(control/'vm.sock'),'logs':str(VMHOME/'logs'),'memory_mb':args.memory_mib,
         'logical_device':install.WORKER_DEVICE,'guest_device':(runtime/'provisioning/guest-device.txt').read_text().strip(),
         'allowed_hosts':sorted(PACKAGE_HOSTS|{backend.hostname})}
    watch_evidence=runtime/'provisioning/guest-watch-device.txt'
    worker_path=LIB/'worker.json'
    worker=json.loads(worker_path.read_text())
    worker['device_allowlist']=[install.WORKER_DEVICE]
    worker['device_platforms']={}
    if watch_evidence.is_file():
        from policy import normalize_udid
        cfg['watch_devices']=[install.WATCH_DEVICE,normalize_udid(watch_evidence.read_text().strip())]
        worker['device_allowlist'].append(install.WATCH_DEVICE)
        worker['device_platforms'][install.WATCH_DEVICE]='watchOS'
    root_file(worker_path,json.dumps(worker,indent=2).encode()+b'\n')
    disk=target/'disk.img'
    cfg['base_identity']={'size':disk.stat().st_size,'mtimeNs':disk.stat().st_mtime_ns,
                          'configSHA256':hashlib.sha256((target/'config.json').read_bytes()).hexdigest(),
                          'diskSHA256':(runtime/'provisioning/base-sha256.txt').read_text().strip()}
    root_file(LIB/'vm.json',json.dumps(cfg,indent=2).encode()+b'\n')
    keydir=VMHOME/'Library/Keychains';keydir.mkdir(mode=0o700,parents=True,exist_ok=True)
    preferences=VMHOME/'Library/Preferences'
    preferences.mkdir(mode=0o700,exist_ok=True)
    for path in (VMHOME/'Library',keydir,preferences):os.chown(path,uid,20);path.chmod(0o700)
    # Create the VM identity keychain in the same launchd security session
    # that will run Tart. An account switch inside the installer is a different
    # session and can fail to initialize macOS Security services.
    data={'Label':'com.iosworker.vmcontroller','UserName':'iosvm','GroupName':'iosworker-control',
          'ProgramArguments':[str(HOST_PYTHON),'-I',str(LIB/'vm_launch.py'),str(LIB/'vm.json')],
          'WorkingDirectory':'/private/tmp','RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':10,
          'ProcessType':'Standard','Nice':5,'SessionCreate':True,
          'EnvironmentVariables':{'HOME':str(VMHOME),'USER':'iosvm','LOGNAME':'iosvm',
                                  'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','PYTHONDONTWRITEBYTECODE':'1'},
          'StandardOutPath':str(VMHOME/'controller.log'),'StandardErrorPath':str(VMHOME/'controller.log')}
    launch(VMPLIST,'com.iosworker.vmcontroller',data)
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        try:
            capabilities=rpc(control/'vm.sock',{'op':'capabilities'},timeout=3)
            if capabilities.get('ok') is True and capabilities.get('backend')=='tart':
                break
        except (OSError,ValueError):
            pass
        time.sleep(1)
    else:
        diagnostics=VMHOME/'controller.log'
        detail=diagnostics.read_text(errors='replace')[-1600:] if diagnostics.is_file() else ''
        raise SystemExit('Private controller did not become ready. '+detail)
    # Private validation credentials never replace the existing agent credentials.
    private_token=BROKER/'validation-token';private_operator=BROKER/'validation-operator-token'
    broker_uid=pwd.getpwnam('iosbroker').pw_uid
    owner_uid=runtime.stat().st_uid
    if owner_uid in (0,uid,broker_uid):
        raise SystemExit('The trial directory must belong to the local Mac owner')
    owner_socket_dir=LIB/'owner'
    if owner_socket_dir.is_symlink():
        raise SystemExit('Unexpected owner socket directory symlink')
    owner_socket_dir.mkdir(mode=0o755,exist_ok=True)
    os.chown(owner_socket_dir,broker_uid,20)
    owner_socket_dir.chmod(0o755)
    root_file(LIB/'owner.json',json.dumps({'uid':owner_uid}).encode()+b'\n')
    for path in (private_token,private_operator):
        root_file(path,(secrets.token_hex(32)+'\n').encode(),0o600);os.chown(path,broker_uid,20)
    validation={'worker_config':str(LIB/'worker.json'),'listen_host':'127.0.0.1','listen_port':8742,
                'token_file':str(private_token),'operator_token_file':str(private_operator),
                'allow_loopback':True,'max_running_jobs':1,'max_build_jobs':2,'simulator_idle_seconds':600}
    root_file(BROKER/'validation.json',json.dumps(validation).encode(),0o600);os.chown(BROKER/'validation.json',broker_uid,20)
    validation_plist=plistlib.loads((ROOT/'com.iosworker.broker.plist').read_bytes())
    validation_plist['Label']='com.iosworker.validation'
    validation_plist['ProgramArguments']=[str(HOST_PYTHON),'-I',str(LIB/'broker.py'),str(BROKER/'validation.json')]
    validation_plist['StandardOutPath']=str(BROKER/'validation.log')
    validation_plist['StandardErrorPath']=str(BROKER/'validation.log')
    launch(TESTPLIST,'com.iosworker.validation',validation_plist)
    problems=launch_path_problems(LIB)
    if problems:raise SystemExit('Installed launch path failed permission audit')
    print('Protected controller and private localhost validation broker staged. Public execution remains off.')


def activate(args):
    from cli import read_secret
    idle('http://127.0.0.1:8742',read_secret(BROKER/'validation-token'),'com.iosworker.validation')
    report=json.loads(args.report.read_text())
    required=('appBuildPassed','securityNegativesPassed','leaseExpiryPassed')
    if any(report.get(key) is not True for key in required):raise SystemExit('Acceptance evidence is incomplete')
    screenshot=Path(report['screenshot'])
    if not screenshot.read_bytes().startswith(b'\x89PNG\r\n\x1a\n') or hashlib.sha256(screenshot.read_bytes()).hexdigest()!=report['screenshotSHA256']:
        raise SystemExit('Screenshot acceptance artifact does not match report')
    if report.get('codeSHA256')!=code_hash():raise SystemExit('Acceptance was run against different code')
    config = (LIB/'vm.json').read_bytes()
    if report.get('vmConfigSHA256')!=hashlib.sha256(config).hexdigest():
        raise SystemExit('Acceptance was run against a different VM configuration')
    if json.loads(config).get('watch_devices'):
        if report.get('watchBuildPassed') is not True:
            raise SystemExit('A configured Watch requires successful watchOS acceptance')
        watch = Path(report['watchScreenshot']).read_bytes()
        if not watch.startswith(b'\x89PNG\r\n\x1a\n') or hashlib.sha256(watch).hexdigest()!=report['watchScreenshotSHA256']:
            raise SystemExit('Watch screenshot acceptance artifact does not match report')
    root_file(LIB/'vm-validated.json',json.dumps(report,indent=2).encode()+b'\n')
    run(['/bin/launchctl','bootout','system/com.iosworker.validation'],False)
    run(['/bin/launchctl','bootstrap','system',str(install.PLIST_DST)])
    run(['/bin/launchctl','enable','system/com.iosworker.broker'],False)
    print('Validated isolated broker activated on its existing Tailscale endpoint. Signing and USB remain disabled.')


def main():
    if os.geteuid()!=0:raise SystemExit('Run this reviewed installer as root')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial-root',type=Path,required=True)
    parser.add_argument('--public-env',type=Path,required=True)
    parser.add_argument('--memory-mib',type=int,choices=(4096,6144,8192),default=4096)
    parser.add_argument('--replace-base',action='store_true',help='Replace the stopped controller base with the reviewed pristine image')
    parser.add_argument('--activate',action='store_true')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if args.activate:
        if args.report is None:parser.error('--activate requires --report')
        activate(args)
    else:stage(args)

if __name__=='__main__':main()
