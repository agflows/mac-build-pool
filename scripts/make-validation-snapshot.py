#!/usr/bin/env python3
"""Create owner-side acceptance snapshots as data, never execute project code.

The Expo snapshot is the committed mobile-app tree plus a clearly identified
security-test overlay: a protected-probe postinstall hook. No app UI/native
code is changed. The supplied public runtime configuration is transferred
separately by the build client, never stored in this source snapshot.
"""
import argparse,hashlib,io,json,shlex,subprocess,tarfile
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--kind',choices=['expo','swift'],required=True)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--host-ip',action='append',default=[])
p.add_argument('--canary-path',action='append',default=[])
a=p.parse_args()
if a.output.exists():p.error('Output must be a new file')
root=Path(__file__).resolve().parents[1]
args=[]
for ip in a.host_ip:args+=['--host-ip',ip]
for path in a.canary_path:args+=['--canary-path',path]
files={}
commit=None
if a.kind=='expo':
    commit=subprocess.check_output(['git','-C',str(a.source),'rev-parse','HEAD'],text=True).strip()
    raw=subprocess.check_output(['git','-C',str(a.source),'archive','HEAD:mobile-app'])
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive:
            if member.isdir():continue
            if not member.isfile() or any(part.startswith('.env') for part in Path(member.name).parts):
                raise SystemExit('Refusing linked, special or environment files in validation source')
            files[member.name]=(archive.extractfile(member).read(),member.mode)
    package=json.loads(files['package.json'][0])
    scripts=package.setdefault('scripts',{})
    if scripts.get('postinstall'):raise SystemExit('Review the existing postinstall hook before composing a test overlay')
    call=['/usr/bin/python3','-I','/Library/ios-worker/negative_probe.py',*args]
    # JSON quoting is JavaScript source here, never shell interpolation.
    scripts['postinstall']='node -e '+shlex.quote("require('node:child_process').execFileSync("+json.dumps(call[0])+','+json.dumps(call[1:])+",{stdio:'inherit'})")
    files['package.json']=(json.dumps(package,indent=2).encode()+b'\n',0o644)
else:
    for file in a.source.rglob('*'):
        if file.is_symlink():raise SystemExit('Unexpected fixture symlink')
        if file.is_file():files[str(file.relative_to(a.source))]=(file.read_bytes(),0o644)
    # The Xcode build phase runs in the guest as iosagent, including its children.
    project='SwiftProbe.xcodeproj/project.pbxproj'
    raw=files[project][0].decode()
    shell='/usr/bin/python3 -I /Library/ios-worker/negative_probe.py '+shlex.join(args)
    phase='000000000000000000000045'
    raw=raw.replace('buildPhases=(000000000000000000000007,',f'buildPhases=({phase},000000000000000000000007,')
    raw=raw.replace('};rootObject=',phase+'={isa=PBXShellScriptBuildPhase;buildActionMask=2147483647;files=();inputPaths=();outputPaths=();runOnlyForDeploymentPostprocessing=0;shellPath=/bin/sh;shellScript='+json.dumps(shell)+';alwaysOutOfDate=1;};\n};rootObject=')
    files[project]=(raw.encode(),0o644)
total=sum(len(value[0]) for value in files.values())
if total>64*1024*1024:raise SystemExit('Validation snapshot exceeds source limit')
with a.output.open('xb') as stream:
    with tarfile.open(fileobj=stream,mode='w:gz') as tar:
        for name,(data,mode) in sorted(files.items()):
            member=tarfile.TarInfo(name);member.size=len(data);member.mode=mode
            tar.addfile(member,io.BytesIO(data))
print(json.dumps({'kind':a.kind,'baseCommit':commit,'securityOverlay':True,'archiveSHA256':hashlib.sha256(a.output.read_bytes()).hexdigest(),'uncompressedBytes':total},indent=2))
