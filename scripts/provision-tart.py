#!/usr/bin/env python3
"""Owner-invoked offline Tart image provisioning. Never runs uploaded projects."""
from __future__ import annotations
import argparse
import base64
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
import hashlib
import shutil
import re

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tart_lease import OfflineTart
from host_egress import Relay
from egress_policy import PACKAGE_HOSTS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tart',type=Path,required=True)
    p.add_argument('--home',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--node',type=Path,required=True)
    p.add_argument('--bun',type=Path,required=True)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--watch-runtime',type=Path,help='Apple watchOS 26.5 arm64 simulator runtime export')
    p.add_argument('--flutter',type=Path,help='Verified official arm64 Flutter SDK archive')
    p.add_argument('--keep-failed',action='store_true',help='Keep only a stopped trusted provisioning guest for diagnosis/resume')
    p.add_argument('--resume',help='Resume the last trusted provisioning guest; never accepts a project lease guest')
    args=p.parse_args()
    source=Path(__file__).resolve().parents[1]
    pins=json.loads(Path(__file__).with_name('toolchain-pins.json').read_text())
    for name in ('node','bun','flutter'):
        artifact=getattr(args,name)
        if artifact is None:continue
        digest=hashlib.sha256()
        with artifact.open('rb') as stream:
            for chunk in iter(lambda:stream.read(8*1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=pins[name]['sha256']:
            raise RuntimeError('Pinned '+name+' download checksum mismatch')
    args.output.mkdir(mode=0o700,parents=True,exist_ok=True)
    (args.output/'toolchain-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
    backend=OfflineTart(args.tart,args.home,'trial-macos-base',args.output/'logs',4096)
    print('Waiting for pinned macOS base download',flush=True)
    while not (args.home/'vms/trial-macos-base/config.json').is_file():
        time.sleep(10)
    # The local toolchain is reviewed/copied as data. No project code is built
    # or executed by this host-side script.
    backend.call('set','trial-macos-base','--disk-size','100',timeout=120)
    checkpoint=args.output/'trusted-provisioning.json'
    progress={}
    if args.resume:
        progress=json.loads(checkpoint.read_text())
        if (not re.fullmatch(r'trial-[0-9a-f]{16}',args.resume) or progress.get('vm')!=args.resume
                or progress.get('pins')!=pins or not (args.home/'vms'/args.resume).is_dir()):
            raise RuntimeError('Only the last trusted provisioning guest can be resumed')
    vm=args.resume or 'trial-'+secrets.token_hex(8)
    progress.update(vm=vm,pins=pins)
    def save_progress(stage):
        progress[stage]=True
        checkpoint.write_text(json.dumps(progress,indent=2)+'\n');checkpoint.chmod(0o600)
    save_progress('created')
    completed=False
    relay=None
    bad_pressure=threading.Event()
    finished=threading.Event()
    log=(args.output/'provision.log').open('ab',buffering=0)
    def guard():
        while not finished.wait(5):
            try:
                level=int(subprocess.check_output(['/usr/sbin/sysctl','-n','kern.memorystatus_vm_pressure_level'],text=True))
                if level>=4:
                    bad_pressure.set()
                    print('Stopping provisioning: urgent host memory pressure',flush=True)
                    backend.stop(vm)
                    return
                if shutil.disk_usage(args.home).free<2*1024**3:
                    bad_pressure.set()
                    print('Stopping provisioning: host free disk below 2 GiB',flush=True)
                    backend.stop(vm)
                    return
            except Exception:
                bad_pressure.set()
                backend.stop(vm)
                return
    def guest(argv,*,data=None,timeout=600):
        if bad_pressure.is_set():raise RuntimeError('host memory admission stopped the guest')
        result=subprocess.run([backend.binary,'exec',*(['-i'] if data is not None else []),vm,*argv],
             env=backend.env,cwd='/private/tmp',input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        log.write(result.stdout);log.write(result.stderr)
        if result.returncode:
            raise RuntimeError('Guest setup command failed: '+str(argv[:3])+' '+result.stderr.decode(errors='replace')[-500:])
        return result.stdout
    def upload_file(source,destination):
        # Tart 2.41.1 eagerly buffers regular-file stdin in AsyncThrowingStream
        # before its sender runs. Never redirect a multi-GB file into tart exec.
        # Each separate invocation has at most 32 MiB of trusted payload.
        guest(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-c',
               "import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600);os.close(fd)",destination])
        offset=0
        with source.open('rb') as stream:
            while True:
                chunk=stream.read(32*1024*1024)
                if not chunk:break
                guest(['/usr/bin/sudo','-n','/bin/dd','of='+destination,'bs=1048576',
                       'seek='+str(offset//1048576),'conv=notrunc'],data=chunk,timeout=120)
                offset+=len(chunk)
                if offset%(256*1024*1024)==0 or offset==source.stat().st_size:
                    print('Transferred '+source.name+': '+str(offset//1048576)+' MiB',flush=True)
    try:
        print('Booting 4 GB offline provisioning guest',flush=True)
        threading.Thread(target=guard,daemon=True).start()
        if args.resume:
            backend.resume_provisioning(vm)
            guest(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-c',"from pathlib import Path;p=Path('/Library/ios-worker/data/work');assert not p.exists() or not any(p.iterdir()),'cannot resume an image containing project work'"])
        else:
            backend.start(vm)
        if not progress.get('credentials'):
            print('Replacing public image credentials before toolchain transfer',flush=True)
            guest(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-'],data=(source/'scripts/harden-guest-admin.py').read_bytes())
            save_progress('credentials')
        if not progress.get('xcode'):
            print('Copying independent local Xcode toolchain into guest',flush=True)
            producer=subprocess.Popen(['/usr/bin/tar','-C','/Applications','-cf','-','Xcode.app'],stdout=subprocess.PIPE,stderr=log)
            consumer=subprocess.Popen([backend.binary,'exec','-i',vm,'/usr/bin/sudo','-n','/usr/bin/tar','-xf','-','-C','/Applications'],
                 env=backend.env,cwd='/private/tmp',stdin=producer.stdout,stdout=log,stderr=log)
            producer.stdout.close()
            if consumer.wait(timeout=1800) or producer.wait(timeout=30):raise RuntimeError('Xcode transfer failed')
            guest(['/usr/bin/codesign','--verify','--deep','--strict','/Applications/Xcode.app'],timeout=300)
            save_progress('xcode')
        guest(['/usr/bin/sudo','-n','/usr/bin/xcode-select','-s','/Applications/Xcode.app/Contents/Developer'])
        guest(['/usr/bin/sudo','-n','/usr/bin/xcodebuild','-license','accept'])
        if not progress.get('first_launch'):
            guest(['/usr/bin/sudo','-n','/usr/bin/xcodebuild','-runFirstLaunch'],timeout=900)
            save_progress('first_launch')
        print('Installing reviewed guest worker payload',flush=True)
        names=['policy.py','config.py','memory.py','tarsafe.py','containment.py','workspace.py','worker_exec.py',
               'guest_guard.py','execution_policy.py','guest_rpc.py','guest_proxy.py']
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as tar:
            for name in names:tar.add(source/name,arcname=name,recursive=False)
            tar.add(source/'scripts/guest-negative-probe.py',arcname='negative_probe.py',recursive=False)
            tar.add(source/'scripts/harden-guest-admin.py',arcname='harden_guest_admin.py',recursive=False)
            tar.add(source/'scripts/provision-proxy-tls.sh',arcname='provision_proxy_tls.sh',recursive=False)
        guest(['/usr/bin/sudo','-n','/bin/mkdir','-p','/Library/ios-worker/toolchains/node'])
        guest(['/usr/bin/sudo','-n','/usr/bin/tar','-xf','-','-C','/Library/ios-worker'],data=archive.getvalue())
        cfg={'workspace_root':'/Library/ios-worker/data/work','spool_root':'/Library/ios-worker/data/spool',
             'artifact_root':'/Library/ios-worker/data/artifacts','developer_dir':'/Applications/Xcode.app/Contents/Developer',
             'device_allowlist':['3C8BB98E-6383-446B-AF87-1E1282762A13'],
             'device_denylist':['4D015300-4BAE-4E6D-89C9-BC4D454E4216'],
             'sandbox_builds':False,'allow_dependency_install':True,'package_proxy':True,
             'toolchain':{'node':'/Library/ios-worker/toolchains/node/bin/node',
                          'bun':'/Library/ios-worker/toolchains/bun','pod':'/opt/homebrew/bin/pod',
                          'ruby_bin':'/opt/homebrew/opt/ruby/bin'}}
        guest(['/usr/bin/sudo','-n','/usr/bin/tee','/Library/ios-worker/worker.json'],data=json.dumps(cfg).encode())
        guest(['/usr/bin/sudo','-n','/bin/sh','-s','--',secrets.token_hex(24)],data=(source/'scripts/provision-guest.sh').read_bytes())
        guest(['/usr/bin/sudo','-n','/bin/sh','/Library/ios-worker/provision_proxy_tls.sh'])
        # Expand the root APFS container after enlarging its sparse virtual disk.
        guest(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-c',
               "import plistlib,subprocess;d=plistlib.loads(subprocess.check_output(['/usr/sbin/diskutil','info','-plist','/']));r=subprocess.run(['/usr/sbin/diskutil','apfs','resizeContainer',d['APFSContainerReference'],'0'],capture_output=True,text=True);assert r.returncode==0 or '-69743' in r.stdout+r.stderr,r.stdout+r.stderr"])
        if not progress.get('tools'):
            print('Installing pinned Node and Bun',flush=True)
            with args.node.open('rb') as node:
                r=subprocess.run([backend.binary,'exec','-i',vm,'/usr/bin/sudo','-n','/usr/bin/tar','-xzf','-',
                    '--strip-components','1','-C','/Library/ios-worker/toolchains/node'],env=backend.env,cwd='/private/tmp',stdin=node,stdout=log,stderr=log,timeout=300)
                if r.returncode:raise RuntimeError('Node installation failed')
            guest(['/usr/bin/sudo','-n','/usr/sbin/chown','-R','root:wheel','/Library/ios-worker/toolchains/node'])
            with zipfile.ZipFile(args.bun) as bun:
                guest(['/usr/bin/sudo','-n','/bin/dd','of=/Library/ios-worker/toolchains/bun','bs=1048576'],data=bun.read('bun-darwin-aarch64/bun'))
            guest(['/usr/bin/sudo','-n','/bin/chmod','755','/Library/ios-worker/toolchains/bun'])
            save_progress('tools')
        if args.flutter:
            cfg['toolchain']['flutter_sdk']='/Library/ios-worker/toolchains/flutter'
            if not progress.get('flutter'):
                print('Installing verified Flutter SDK as immutable guest toolchain',flush=True)
                upload_file(args.flutter,'/private/tmp/worker-flutter.zip')
                guest(['/usr/bin/sudo','-n','/usr/bin/ditto','-x','-k','/private/tmp/worker-flutter.zip',
                       '/Library/ios-worker/toolchains'],timeout=600)
                guest(['/usr/bin/sudo','-n','/bin/rm','/private/tmp/worker-flutter.zip'])
                guest(['/usr/bin/sudo','-n','/usr/sbin/chown','-R','root:wheel','/Library/ios-worker/toolchains/flutter'])
                save_progress('flutter')
            # The SDK includes cached assets with owner-only archive modes.
            # The worker must be able to read them into its private SDK copy.
            guest(['/usr/bin/sudo','-n','/usr/bin/find','-P','/Library/ios-worker/toolchains/flutter',
                   '!','-type','l','-exec','/bin/chmod','a+rX,go-w','{}','+'],timeout=180)
        print('Starting allowlisted package relay over guest control channel',flush=True)
        relay_process=subprocess.Popen([backend.binary,'exec','-i',vm,'/usr/bin/sudo','-n',
             '/usr/bin/python3','-I','/Library/ios-worker/guest_proxy.py'],env=backend.env,cwd='/private/tmp',
             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,start_new_session=True)
        relay=Relay(relay_process,allowed=PACKAGE_HOSTS|{'ghcr.io','pkg-containers.githubusercontent.com','formulae.brew.sh','api.github.com'})
        threading.Thread(target=relay.run,daemon=True).start()
        # Trusted image maintenance only; package projects never execute as admin.
        if not progress.get('pods'):
            print('Provisioning CocoaPods in the guest',flush=True)
            guest(['/usr/bin/env','HOMEBREW_NO_AUTO_UPDATE=1','HOMEBREW_NO_ANALYTICS=1','HOMEBREW_NO_INSTALL_CLEANUP=1',
                   'HTTPS_PROXY=http://127.0.0.1:18741','https_proxy=http://127.0.0.1:18741',
                   'SSL_CERT_FILE=/Library/ios-worker/proxy-ca-bundle.pem','CURL_CA_BUNDLE=/Library/ios-worker/proxy-ca-bundle.pem',
                   'GIT_SSL_CAINFO=/Library/ios-worker/proxy-ca-bundle.pem',
                   '/opt/homebrew/bin/brew','install','cocoapods'],timeout=1800)
            save_progress('pods')
        if not progress.get('runtime'):
            print('Importing independent local iOS simulator runtime',flush=True)
            upload_file(args.runtime,'/private/tmp/worker-ios-runtime.dmg')
            guest(['/usr/bin/sudo','-n','/bin/chmod','644','/private/tmp/worker-ios-runtime.dmg'])
            guest(['/usr/bin/sudo','-n','/usr/bin/xcrun','simctl','runtime','add','/private/tmp/worker-ios-runtime.dmg','--move'],timeout=900)
            save_progress('runtime')
            guest(['/usr/bin/sudo','-n','/bin/rm','-f','/private/tmp/worker-ios-runtime.dmg'])
        if args.watch_runtime and not progress.get('watch_runtime'):
            print('Importing the Apple watchOS simulator runtime',flush=True)
            staging=Path('/private/tmp/worker-watch.exportedBundle')
            if args.watch_runtime.is_symlink() or not args.watch_runtime.is_dir():
                raise RuntimeError('Provide the complete Apple .exportedBundle for watchOS')
            for source_file in sorted(args.watch_runtime.rglob('*')):
                if source_file.is_symlink():
                    raise RuntimeError('Unexpected symlink in the exported runtime')
                if source_file.is_file():
                    destination=staging/source_file.relative_to(args.watch_runtime)
                    guest(['/usr/bin/sudo','-n','/bin/mkdir','-p',str(destination.parent)])
                    upload_file(source_file,str(destination))
                    guest(['/usr/bin/sudo','-n','/bin/chmod','644',str(destination)])
            guest(['/usr/bin/sudo','-n','/usr/bin/xcodebuild','-importPlatform',str(staging)],timeout=900)
            save_progress('watch_runtime')
            guest(['/usr/bin/sudo','-n','/bin/rm','-rf',str(staging)])
        # Configure an active but disconnected interface so CFNetwork can use
        # the local CONNECT proxy. All Ethernet frames are dropped externally.
        guest(['/usr/bin/sudo','-n','/usr/sbin/networksetup','-setmanual','Ethernet','192.0.2.2','255.255.255.0','192.0.2.1'])
        guest(['/usr/bin/sudo','-n','/usr/sbin/networksetup','-setsecurewebproxy','Ethernet','127.0.0.1','18741'])
        device=guest(['/usr/bin/sudo','-n','-u','iosagent','/usr/bin/python3','-I','-c',
            "import os;os.chdir('/private/tmp');import json,subprocess;d=json.loads(subprocess.check_output(['/usr/bin/xcrun','simctl','list','-j']));r=next(x['identifier'] for x in d['runtimes'] if x.get('isAvailable') and x['name'].startswith('iOS'));t=next(x['identifier'] for x in d['devicetypes'] if x['name'].startswith('iPhone'));print(subprocess.check_output(['/usr/bin/xcrun','simctl','create','Worker iPhone',t,r],text=True).strip())"]).decode().strip()
        cfg['device_allowlist']=[device]
        if args.watch_runtime:
            watch=guest(['/usr/bin/sudo','-n','-u','iosagent','/usr/bin/python3','-I','-',device],
                        data=(source/'scripts/guest-provision-watch.py').read_bytes(),timeout=180).decode().strip()
            cfg['device_allowlist'].append(watch)
            cfg['device_platforms']={watch:'watchOS'}
            (args.output/'guest-watch-device.txt').write_text(watch+'\n')
        guest(['/usr/bin/sudo','-n','/usr/bin/tee','/Library/ios-worker/worker.json'],data=json.dumps(cfg).encode())
        guest(['/usr/bin/sudo','-n','/bin/chmod','644','/Library/ios-worker/worker.json'])
        for device_id in cfg['device_allowlist']:
            simctl=['/usr/bin/sudo','-n','-u','iosagent','/usr/bin/xcrun','simctl']
            print('Preparing the empty simulator for cold leases',flush=True)
            guest([*simctl,'boot',device_id],timeout=180)
            guest([*simctl,'bootstatus',device_id,'-b'],timeout=360)
            guest([*simctl,'shutdown',device_id],timeout=180)
        versions=guest(['/usr/bin/python3','-I','-c',
            "import json,subprocess;print(json.dumps({x:subprocess.check_output(c,text=True).strip() for x,c in {'macOS':['/usr/bin/sw_vers','-productVersion'],'Xcode':['/usr/bin/xcodebuild','-version'],'Node':['/Library/ios-worker/toolchains/node/bin/node','--version'],'Bun':['/Library/ios-worker/toolchains/bun','--version'],'CocoaPods':['/opt/homebrew/bin/pod','--version'],'Ruby':['/opt/homebrew/opt/ruby/bin/ruby','--version']}.items()}))"]).decode()
        (args.output/'toolchain.json').write_text(versions)
        (args.output/'guest-device.txt').write_text(device+'\n')
        if relay:relay.close();relay=None
        # Produce a clean pristine image, never a post-project VM snapshot.
        # The agent may disconnect as shutdown begins; only the verified stopped
        # Tart process below determines whether the image can be promoted.
        try:
            guest(['/usr/bin/sudo','-n','/sbin/shutdown','-h','now'])
        except RuntimeError:
            pass
        deadline=time.monotonic()+60
        while backend.processes[vm].poll() is None and time.monotonic()<deadline:
            time.sleep(1)
        backend.stop(vm)
        backend.call('rename',vm,'worker-base')
        print('Fingerprinting powered-off base image',flush=True)
        digest=hashlib.sha256()
        with (args.home/'vms/worker-base/disk.img').open('rb') as stream:
            for chunk in iter(lambda:stream.read(8*1024*1024),b''):digest.update(chunk)
        (args.output/'base-sha256.txt').write_text(digest.hexdigest()+'\n')
        completed=True
        checkpoint.unlink(missing_ok=True)
        print('Prepared powered-off worker-base; no project was executed in this base',flush=True)
    finally:
        finished.set()
        if relay:relay.close()
        try:backend.stop(vm)
        finally:
            if completed or not args.keep_failed:
                backend.delete(vm)
            else:
                print('Stopped trusted provisioning guest retained for diagnosis: '+vm,flush=True)
        log.close()


if __name__=='__main__':
    main()
