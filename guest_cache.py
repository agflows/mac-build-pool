"""Transfer simulator app bundles only inside the isolated guest."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

ROOT = '/Library/ios-worker'
MAX_BYTES = 512 * 1024 * 1024


def restore(stream, root):
    """Read a bounded tar stream and resolve every link within the app."""
    total = 0
    count = 0
    seen = set()
    links = []
    with tarfile.open(fileobj=stream, mode='r|gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (not path.parts or path.parts[0] != 'Cached.app' or path.is_absolute()
                    or '..' in path.parts or path in seen):
                raise ValueError('Invalid cached app member')
            seen.add(path)
            count += 1
            total += member.size
            if count > 30000 or total > 2 * MAX_BYTES:
                raise ValueError('Cached app exceeds extraction limits')
            dest = root.joinpath(*path.parts)
            if not dest.parent.resolve().is_relative_to(root):
                raise ValueError('Cached app path escapes extraction root')
            dest.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                if dest.is_symlink():
                    raise ValueError('Cached app directory is a symlink')
                dest.mkdir(exist_ok=True)
            elif member.isfile():
                with dest.open('xb') as file:
                    payload = archive.extractfile(member)
                    while block := payload.read(1024 * 1024):
                        file.write(block)
                dest.chmod(0o700 if member.mode & 0o111 else 0o600)
            elif member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or not (dest.parent / link).resolve().is_relative_to(root / 'Cached.app'):
                    raise ValueError('Cached app link escapes bundle')
                dest.symlink_to(member.linkname)
                links.append(dest)
            else:
                raise ValueError('Unsupported cached app member')
    app = root / 'Cached.app'
    if app.is_symlink() or not app.is_dir():
        raise ValueError('Cached app is missing')
    if any(not path.resolve().is_relative_to(app) for path in links):
        raise ValueError('Cached app link escapes bundle')
    return app


def main():
    os.chdir('/private/tmp')
    os.umask(0o077)
    sys.path.insert(0, ROOT)
    from execution_policy import require_worker_execution, require_protected_file
    from config import load_worker_config
    from containment import apply_rlimits
    from memory import sample_system
    from policy import require_configuration, require_id, require_under
    from worker_exec import Commands, _bundle_id, _device, _find_app, _check, ensure_booted

    require_worker_execution()
    require_protected_file(Path(ROOT) / 'worker.json')
    cfg = load_worker_config(Path(ROOT) / 'worker.json')
    apply_rlimits()
    command, target, *extra = sys.argv[1:]
    device = _device({'device_id': target}, cfg)
    if command == 'export':
        revision, configuration = extra
        derived = require_under(cfg.workspace_root / require_id(revision, 'revision') / 'DerivedData',
                                cfg.workspace_root)
        app = _find_app(derived, require_configuration(configuration), cfg.device_platforms.get(device, 'iOS'))
        require_under(app, derived)
        _bundle_id(app)
        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz', compresslevel=3) as archive:
            archive.add(app, arcname='Cached.app')
    elif command == 'restore':
        with tempfile.TemporaryDirectory(dir=cfg.workspace_root) as temporary:
            app = restore(sys.stdin.buffer, Path(temporary))
            commands = Commands(cfg.developer_dir, [cfg.workspace_root], cfg.disk_budget)
            bundle = _bundle_id(app)
            ensure_booted(device, True, cfg, commands, sample_system)
            _check(commands.run([commands.xcrun, 'simctl', 'install', device, str(app)], 180), 'install failed')
            log = _check(commands.run([commands.xcrun, 'simctl', 'launch', device, bundle], 60), 'launch failed')
            print(json.dumps({'ok': True, 'log': log, 'bundle_id': bundle, 'exitCode': 0}))
    else:
        raise ValueError('Unsupported cache operation')


if __name__ == '__main__':
    main()
