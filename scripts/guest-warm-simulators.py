"""Finish first-boot migration on the empty simulators in a provisioning guest."""

from __future__ import annotations

import os
import pwd
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID

SIMCTL = ['/usr/bin/xcrun', 'simctl']
DATA_ROOT = Path('/Library/ios-worker/data')


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
    started = time.monotonic()
    for device in devices:
        print(f'Warming simulator {device}', flush=True)
        # Also wait for migration if the paired iPhone launched this device.
        subprocess.run([*SIMCTL, 'bootstatus', device, '-b'], check=True, timeout=1200)
        print(f'Simulator {device} is ready after {time.monotonic() - started:.0f} seconds', flush=True)
    # Both migrations completed. Ask CoreSimulator to shut down the devices;
    # the caller then requires a clean macOS shutdown before keeping the image.
    try:
        subprocess.run([*SIMCTL, 'shutdown', 'all'], check=True, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print('CoreSimulator shutdown did not finish. The provisioning guest must shut down cleanly.',
              file=sys.stderr, flush=True)



if __name__ == '__main__':
    main()
