"""launchd entry for the dedicated VM-control account, never the personal user."""
import os
from pathlib import Path
import pwd
import subprocess
import sys

root=str(Path(__file__).resolve().parent)
if root not in sys.path:sys.path.insert(0,root)
from execution_policy import require_protected_file

account=pwd.getpwnam('iosvm')
if os.getuid()!=account.pw_uid or os.geteuid()!=account.pw_uid or account.pw_uid==0:
    raise SystemExit('VM controller must run as iosvm')
require_protected_file(Path('/Library/ios-worker/vm.json'))
# This empty, dedicated host keychain holds only Virtualization identity data.
# No developer signing identity or personal keychain is imported or unlocked.
keychain = Path(account.pw_dir) / 'Library/Keychains/login.keychain'
if keychain.parent.is_symlink() or any(
    path.is_symlink() for path in (keychain, keychain.with_suffix('.keychain-db'))
):
    raise SystemExit('Unexpected symlink in dedicated VM identity keychain')


def security(*args, required=True):
    result = subprocess.run(['/usr/bin/security', *args], capture_output=True, text=True, timeout=20)
    if result.returncode and required:
        detail = (result.stderr or result.stdout).strip()[-500:]
        raise SystemExit(f'Dedicated VM keychain {args[0]} failed ({result.returncode}) {detail}')
    return result


if not keychain.exists() and not keychain.with_suffix('.keychain-db').exists():
    security('create-keychain', '-p', '', str(keychain))
database = keychain.with_suffix('.keychain-db')
selected = str(database if database.exists() else keychain)
security('unlock-keychain', '-p', '', selected)
security('list-keychains', '-d', 'user', '-s', selected)
security('default-keychain', '-d', 'user', '-s', selected)
# Some system launchd sessions have no mutable login preference. A real
# Tart boot is the readiness test for that session's dedicated keychain.
security('login-keychain', '-d', 'user', '-s', selected, required=False)
from vm_service import main
main()
