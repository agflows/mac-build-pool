"""Owner-side private acceptance client. Never executes uploaded project code."""
import argparse,hashlib,json,os,re,sys,threading,time
from pathlib import Path
sys.path.insert(0,'/Library/ios-worker')
from cli import call,read_secret
if os.geteuid()!=0:raise SystemExit('Owner-side private acceptance only; run through the reviewed local maintenance action')
p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('--recipe',required=True);p.add_argument('--scheme',required=True);p.add_argument('--configuration',default='Release');p.add_argument('--output',type=Path,required=True);p.add_argument('--public-env',type=Path);p.add_argument('--test',action='store_true');p.add_argument('--keep-lease',action='store_true');p.add_argument('--check-boundary',action='store_true');p.add_argument('--device');args=p.parse_args()
args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
url='http://127.0.0.1:8742'
token=read_secret(Path('/Users/iosbroker/.ios-worker/validation-token'))
operator=read_secret(Path('/Users/iosbroker/.ios-worker/validation-operator-token'))
report={'recipe':args.recipe,'scheme':args.scheme,'configuration':args.configuration,'jobs':[],'sourceSHA256':hashlib.sha256(args.archive.read_bytes()).hexdigest()}
lease=None;done=threading.Event()
def request(method,path,data=None,op=False,raw=False):
    body=data if raw else (json.dumps(data).encode() if data is not None else None)
    status,reply=call(url,operator if op else token,method,path,body,'application/gzip' if raw else 'application/json')
    if status not in (200,201,202):raise RuntimeError('API request failed '+str(status)+' '+reply.decode(errors='replace')[:1000])
    return json.loads(reply)
def renewer():
    while not done.wait(45):
        try:request('POST','/v1/leases/'+lease+'/renew',{})
        except Exception as exc:print('Lease renewal failed: '+str(exc),flush=True);return

def wait(job_id):
    deadline=time.monotonic()+3000
    approved=False
    while time.monotonic()<deadline:
        result=request('GET','/v1/jobs/'+job_id)
        state=result['status']
        if state=='waiting_for_approval' and not approved:
            # This owner-side acceptance command has explicit resource approval.
            # The operator credential is never returned or sent to remote agents.
            request('POST','/v1/jobs/'+job_id+'/approve',{},op=True);approved=True
        if state in ('succeeded','failed'):
            report['jobs'].append(result)
            log=request('GET','/v1/jobs/'+job_id+'/logs')
            (args.output/(job_id+'.log')).write_text(log.get('log',''))
            (args.output/'jobs.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps({'jobId':job_id,'kind':result.get('kind'),'status':state,'error':result.get('error')}),flush=True)
            if state!='succeeded':raise RuntimeError('Job failed; inspect private acceptance log '+job_id)
            return result
        time.sleep(2)
    raise TimeoutError('Job did not finish')
try:
    acquired=request('POST','/v1/leases',{'name':args.scheme,'deviceId':args.device})
    lease=acquired['leaseId'];report['leaseId']=lease
    threading.Thread(target=renewer,daemon=True).start()
    wait(acquired['startJobId'])
    if args.check_boundary:
        from vm_transport import rpc,communicate
        state=rpc(Path('/Library/ios-worker/control/vm.sock'),{'op':'status'})
        vm=state.get('vm','')
        if not re.fullmatch(r'lease-[0-9a-f]{16}',vm):raise RuntimeError('No current leased guest')
        probe=(Path(__file__).resolve().parent/'guest-negative-probe.py').read_bytes()
        command=['/usr/bin/sudo','-H','-u','iosvm','/usr/bin/env','HOME=/Users/iosvm',
                 'TART_HOME=/Users/iosvm/.tart','DO_NOT_TRACK=1','TART_NO_AUTO_PRUNE=1',
                 '/Library/ios-worker/tart.app/Contents/MacOS/tart','exec','-i',vm,
                 '/usr/bin/sudo','-n','-u','iosagent','/usr/bin/python3','-I','-']
        probe_options=['--host-ip','192.168.0.142','--canary-path',
                       '/Users/leolurch/Library/Application Support/mac-build-pool/vm-trial/host-canary.txt']
        if args.recipe == 'expo-ios':
            probe_options.append('--check-react-native')
        code,output,error=communicate(command+probe_options,probe,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},timeout=180,cap=1024*1024)
        (args.output/'guest-preflight.json').write_bytes(output)
        if code or json.loads(output).get('passed') is not True:
            raise RuntimeError('Guest security preflight failed: '+error.decode(errors='replace')[-1000:])
        report['guestPreflightPassed']=True
    uploaded=request('POST','/v1/sources',args.archive.read_bytes(),raw=True)
    report['revisionId']=uploaded['revisionId']
    wait(uploaded['jobId'])
    base={'revisionId':uploaded['revisionId'],'leaseId':lease}
    prep=request('POST','/v1/preparations',{**base,'recipe':args.recipe,'scheme':args.scheme,'publicEnv':json.loads(args.public_env.read_text()) if args.public_env else {}})
    wait(prep['jobId'])
    target={'deviceId':args.device}
    build=request('POST','/v1/builds',{**base,**target,'scheme':args.scheme,'configuration':args.configuration,'forTesting':args.test,'bootSimulator':False})
    wait(build['jobId'])
    launch=request('POST','/v1/sessions',{**base,**target,'configuration':args.configuration})
    wait(launch['jobId']);report['sessionId']=launch['sessionId']
    time.sleep(15)
    screenshot=request('POST','/v1/sessions/'+launch['sessionId']+'/screenshot',{})
    captured=wait(screenshot['jobId'])
    status,png=call(url,token,'GET','/v1/artifacts/'+captured['artifactId'])
    if status!=200 or not png.startswith(b'\x89PNG\r\n\x1a\n'):raise RuntimeError('Screenshot transfer failed')
    path=args.output/'simulator.png';path.write_bytes(png)
    report['screenshot']=str(path);report['screenshotSHA256']=hashlib.sha256(png).hexdigest()
    if args.test:
        test=request('POST','/v1/tests',{**base,**target,'scheme':args.scheme,'configuration':args.configuration});wait(test['jobId'])
    report['appBuildPassed']=True
    if args.recipe == 'expo-ios' and args.check_boundary:
        quality_script = Path(__file__).with_name('guest-check-expo.py').read_bytes()
        quality_command = command + [uploaded['revisionId']]
        code, output, error = communicate(quality_command, quality_script,
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=420, cap=1024*1024)
        if code:
            (args.output/'quality-error.log').write_bytes(error)
            report['qualityChecks'] = {'error':'Guest check did not complete'}
        else:
            quality = json.loads(output)
            (args.output/'quality.json').write_text(json.dumps(quality, indent=2)+'\n')
            report['qualityChecks'] = {name: check['exitCode'] for name, check in quality.items()}
        print('App quality checks:',report['qualityChecks'],flush=True)
finally:
    done.set()
    try:
        if lease and not args.keep_lease:
            request('POST','/v1/leases/'+lease+'/release',{})
    finally:
        (args.output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
