"""Finish first-boot migration on the empty simulators in a provisioning guest."""

from __future__ import annotations

import json
import os
import pwd
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID

SIMCTL = ['/usr/bin/xcrun', 'simctl']
DATA_ROOT = Path('/Library/ios-worker/data')


def device_states(devices):
    listing = json.loads(subprocess.check_output([*SIMCTL, 'list', 'devices', '-j'], timeout=90))
    return {item['udid']: item['state'] for group in listing['devices'].values()
            for item in group if item['udid'] in devices and item.get('isAvailable')}


def main():
    os.chdir('/private/tmp')
    model = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'hw.model'], text=True, timeout=5)
    if not model.startswith('VirtualMac') or pwd.getpwuid(os.geteuid()).pw_name != 'iosagent':
        raise SystemExit('Run simulator warmup as iosagent inside the provisioning guest.')
    devices = [str(UUID(argument)).upper() for argument in sys.argv[1:]]
    if not 1 <= len(devices) <= 2 or len(set(devices)) != len(devices):
        raise SystemExit('Pass the provisioned iPhone and, optionally, its paired Watch.')
    for directory in ('work', 'spool', 'artifacts'):
        path = DATA_ROOT / directory
        if path.exists() and any(path.iterdir()):
            raise SystemExit('Simulator warmup requires a project-free provisioning guest.')
    states = device_states(devices)
    if set(states) != set(devices):
        raise SystemExit('A provisioned simulator is unavailable.')
    started = time.monotonic()
    for device in devices:
        print(f'Warming simulator {device}', flush=True)
        # Also wait for migration if the paired iPhone launched this device.
        subprocess.run([*SIMCTL, 'bootstatus', device, '-b'], check=True, timeout=1200)
        print(f'Simulator {device} is ready after {time.monotonic() - started:.0f} seconds', flush=True)
    for device in reversed(devices):
        if device_states(devices).get(device) != 'Shutdown':
            subprocess.run([*SIMCTL, 'shutdown', device], check=True, timeout=90)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if device_states(devices) == dict.fromkeys(devices, 'Shutdown'):
            return
        time.sleep(1)
    raise SystemExit('The warmed simulators did not shut down.')


if __name__ == '__main__':
    main()
