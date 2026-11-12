"""Create an approved Apple Watch and pair it with the dedicated worker iPhone."""
import json
import os
import subprocess
import sys

os.chdir('/private/tmp')
simctl = ['/usr/bin/xcrun', 'simctl']
listing = json.loads(subprocess.check_output([*simctl, 'list', '-j']))
runtime = next(item for item in listing['runtimes'] if item.get('isAvailable')
               and item['identifier'].endswith('.watchOS-26-5'))
supported = runtime.get('supportedDeviceTypes') or listing['devicetypes']
device_type = next(item['identifier'] for item in supported
                   if item['name'].startswith('Apple Watch Series'))
watch = subprocess.check_output(
    [*simctl, 'create', 'Worker Apple Watch', device_type, runtime['identifier']], text=True).strip()
try:
    subprocess.run([*simctl, 'pair', watch, sys.argv[1]], check=True, stdout=sys.stderr)
except subprocess.CalledProcessError:
    subprocess.run([*simctl, 'delete', watch], check=True, stdout=sys.stderr)
    raise
print(watch)
