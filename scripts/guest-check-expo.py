"""Run CoupleApp's repository checks inside an existing disposable guest."""
import json
import os
from pathlib import Path
import subprocess
import sys

os.chdir('/private/tmp')
sys.path.insert(0, '/Library/ios-worker')
from config import load_worker_config
from execution_policy import require_protected_file, require_worker_execution
from policy import require_id, require_under
from workspace import load_prepared_env

require_worker_execution()
config = Path('/Library/ios-worker/worker.json')
require_protected_file(config)
worker = load_worker_config(config)
revision = require_under(worker.workspace_root / require_id(sys.argv[1], 'revision'), worker.workspace_root)
env = load_prepared_env(revision, worker)
node = worker.toolchain['node']
checks = {
    'typecheck': [node, str(revision / 'node_modules/typescript/bin/tsc'), '--noEmit'],
    'lint': [node, str(revision / 'node_modules/expo/bin/cli'), 'lint'],
}
results = {}
for name, command in checks.items():
    try:
        result = subprocess.run(command, cwd=revision, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=180)
        results[name] = {'exitCode': result.returncode, 'log': (result.stdout + result.stderr)[-10000:]}
    except subprocess.TimeoutExpired:
        results[name] = {'exitCode': 124, 'log': 'Check exceeded three minutes'}
print(json.dumps(results))
