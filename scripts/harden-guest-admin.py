"""Replace public base-image credentials. Run as root inside the VM only."""
import os
from pathlib import Path
import re
import secrets
import subprocess

if os.geteuid()!=0 or not re.fullmatch(r'VirtualMac[0-9]+,[0-9]+',subprocess.check_output(['/usr/sbin/sysctl','-n','hw.model'],text=True).strip()):
    raise SystemExit('guest root account required')
password=secrets.token_hex(32)
def run(argv,required=True,label='account setup'):
    result=subprocess.run(argv,capture_output=True,text=True)
    if required and result.returncode:
        # Never include argv: it contains this disposable guest's password.
        detail=(result.stdout+result.stderr).replace(password,'[redacted]')[-500:]
        raise SystemExit('guest account hardening failed at '+label+': '+detail)
    return result
run(['/usr/bin/dscl','.','-passwd','/Users/admin','admin',password],label='password replacement')
run(['/usr/sbin/sysadminctl','-autologin','set','-userName','admin','-password',password,
     '-adminUser','admin','-adminPassword',password],label='private auto-login')
# There are no personal credentials in this public image. Remove its empty
# vendor login keychain; macOS can recreate it at the next private auto-login.
# Changing it through securityd in the old login session races that session's
# cached login credentials. Project code never runs as this setup account.
keychain='/Users/admin/Library/Keychains/login.keychain-db'
security=['/usr/bin/sudo','-n','-u','admin','/usr/bin/env','HOME=/Users/admin','/usr/bin/security']
run(security+['delete-keychain',keychain],required=False)
run(['/bin/chmod','700','/Users/admin'],label='setup home protection')
run(['/bin/chmod','600','/private/etc/kcpassword'],label='auto-login file protection')
run(['/usr/bin/dscl','.','-authonly','admin',password],label='new login verification')
if run(['/usr/bin/dscl','.','-authonly','admin','admin'],required=False).returncode==0:
    raise SystemExit('public image password still authenticates')
print('Public image admin password replaced; setup home and auto-login credentials protected')
