#!/usr/bin/env python3
"""Harmless acceptance probes, executable only as the non-admin macOS guest user.

Invoke from dependency/build hooks too. Output contains pass/fail labels only;
never reads real host documents, credentials or keychains.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys

sys.path.insert(0,'/Library/ios-worker')
from execution_policy import require_worker_execution
require_worker_execution()

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--host-ip',action='append',default=[])
p.add_argument('--canary-path',action='append',default=[])
args=p.parse_args()
results={}

def record(name,passed):
    results[name]=bool(passed)

record('guest-account',pwd.getpwuid(os.getuid()).pw_name=='iosagent')
# macOS can supply an empty agent in the guest's own launchd session. Check
# that no identities are reachable without emitting public key fingerprints.
agent = subprocess.run(['/usr/bin/ssh-add', '-l'], capture_output=True, timeout=5)
record('no-ssh-identities', agent.returncode == 2 or (
    agent.returncode == 1 and b'The agent has no identities.' in agent.stdout + agent.stderr
))
record('no-sudo',subprocess.run(['/usr/bin/sudo','-n','/usr/bin/true'],capture_output=True).returncode!=0)
record('vendor-admin-password-disabled',subprocess.run(['/usr/bin/dscl','.','-authonly','admin','admin'],capture_output=True).returncode!=0)
for index,path in enumerate(args.canary_path):
    record('host-canary-inaccessible-'+str(index),not os.access(path,os.R_OK))
for name,path in [('worker-code','/Library/ios-worker/guest_rpc.py'),
                  ('worker-config','/Library/ios-worker/worker.json'),
                  ('node','/Library/ios-worker/toolchains/node/bin/node'),
                  ('bun','/Library/ios-worker/toolchains/bun'),
                  ('xcode','/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild')]:
    record('immutable-'+name,not os.access(path,os.W_OK) and not os.access(str(Path(path).parent),os.W_OK))

def blocked(address,port):
    family=socket.AF_INET6 if ':' in address else socket.AF_INET
    connection=socket.socket(family,socket.SOCK_STREAM)
    connection.settimeout(1.5)
    try:
        connection.connect((address,port))
        return False
    except OSError:
        return True
    finally:connection.close()

for index,address in enumerate(['192.0.2.1','169.254.169.254','100.114.181.78','1.1.1.1',
                                 '2606:4700:4700::1111',*args.host_ip]):
    record('direct-network-blocked-'+str(index),blocked(address,443))

proxy=['/usr/bin/curl','--silent','--show-error','--max-time','25','--proxy','http://127.0.0.1:18741',
       '--noproxy','','--cacert','/Library/ios-worker/proxy-ca.pem','--output','/dev/null','--write-out','%{http_code}']
for index,url in enumerate(['https://127.0.0.1/','https://192.168.1.1/','https://100.114.181.78/',
                            'https://[::1]/','https://example.com/','https://registry.npmjs.org:8443/']):
    result=subprocess.run([*proxy,url],capture_output=True,text=True)
    record('proxy-denied-'+str(index),result.returncode!=0 and '403' in result.stderr)
result=subprocess.run([*proxy,'https://registry.npmjs.org/expo/58.0.23'],capture_output=True,text=True)
record('approved-package-fetch',result.returncode==0 and result.stdout=='200')
result=subprocess.run([*proxy,'--header','Host: example.com','https://registry.npmjs.org/expo/58.0.23'],capture_output=True,text=True)
record('host-fronting-blocked',result.stdout=='403')
print(json.dumps({'passed':all(results.values()),'checks':results},sort_keys=True))
raise SystemExit(0 if all(results.values()) else 1)
