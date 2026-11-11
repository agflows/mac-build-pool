"""Preparation-only tests. No sudo, account changes, builds or simulator access."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from execution_policy import (ISOLATED, NATIVE, NATIVE_ACK, execution_mode, parse_policy,
                              require_protected_file, require_worker_account,
                              require_worker_execution, require_native_config)
from install_system import parse_args, _install_native_data_access, DATA, _write_execution_policy
from native_runner import NativeUserRunner
from policy import PolicyError
from scheduler import Job

WORKER = '3C8BB98E-6383-446B-AF87-1E1282762A13'
PERSONAL = '4D015300-4BAE-4E6D-89C9-BC4D454E4216'


class NativePolicyTest(unittest.TestCase):
    def test_missing_policy_is_isolated_despite_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('execution_policy.POLICY_PATH', Path(directory) / 'missing'), patch.dict(os.environ, {
                'IOS_WORKER_DEV': '1', 'EXECUTION_MODE': NATIVE, 'NATIVE_ACK': NATIVE_ACK
            }):
                self.assertEqual(execution_mode(), ISOLATED)

    def test_native_requires_exact_owner_acknowledgement(self):
        self.assertEqual(parse_policy({'mode': NATIVE, 'acknowledgement': NATIVE_ACK}), NATIVE)
        self.assertEqual(parse_policy({'mode': ISOLATED}), ISOLATED)
        for data in ({'mode': NATIVE}, {'mode': NATIVE, 'acknowledgement': True},
                     {'mode': 'auto'}, {'mode': ISOLATED, 'fallback': NATIVE}, [], None):
            with self.subTest(data=data), self.assertRaises(PolicyError):
                parse_policy(data)

    def test_unprotected_file_and_symlink_cannot_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy'
            path.write_text(json.dumps({'mode': NATIVE, 'acknowledgement': NATIVE_ACK}))
            path.chmod(0o666)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            for candidate in (path, link):
                with patch('execution_policy.POLICY_PATH', candidate), self.assertRaises(PolicyError):
                    execution_mode()

    def test_acl_write_from_any_identity_is_rejected(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with patch.object(Path, 'lstat', return_value=info), patch('execution_policy.subprocess.run',
                return_value=SimpleNamespace(returncode=0, stdout='file\n 0: user:unexpected allow write,append\n')):
            with self.assertRaises(PolicyError):
                require_protected_file(Path('/Library/ios-worker/execution.json'))

    def test_unreadable_acl_fails_closed(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with patch.object(Path, 'lstat', return_value=info), patch('execution_policy.subprocess.run',
                return_value=SimpleNamespace(returncode=1, stdout='')):
            with self.assertRaises(PolicyError):
                require_protected_file(Path('/Library/ios-worker/execution.json'))

    def test_mode_guard_does_not_weaken_default_guest_guard(self):
        with patch('execution_policy.require_worker_account'), patch('execution_policy.execution_mode', return_value=ISOLATED), \
                patch('guest_guard.require_macos_guest', side_effect=PolicyError('isolation_required', 'physical Mac')) as guest:
            with self.assertRaises(PolicyError):
                require_worker_execution()
            guest.assert_called_once()
        with patch('execution_policy.require_worker_account') as account, patch('execution_policy.execution_mode', return_value=NATIVE), \
                patch('guest_guard.require_macos_guest') as guest:
            self.assertEqual(require_worker_execution(), NATIVE)
            account.assert_called_once()
            guest.assert_not_called()

    def test_personal_root_admin_and_wrong_home_are_rejected(self):
        account = SimpleNamespace(pw_name='iosagent', pw_uid=504, pw_gid=20, pw_dir='/Users/iosagent')
        with patch('pwd.getpwnam', return_value=account), patch('grp.getgrnam', return_value=SimpleNamespace(gr_gid=80)), \
                patch('execution_policy.os.getgrouplist', return_value=[20]) as groups, \
                patch('execution_policy.os.getgroups', return_value=[20]), \
                patch('execution_policy.os.getuid', return_value=504), \
                patch('execution_policy.os.geteuid', return_value=504) as euid:
            require_worker_account()
            for uid in (0, 501):
                euid.return_value = uid
                with self.assertRaises(PolicyError):
                    require_worker_account()
            euid.return_value = 504
            groups.return_value = [20, 80]
            with self.assertRaises(PolicyError):
                require_worker_account()
            groups.return_value = [20]
            account.pw_dir = '/Users/owner'
            with self.assertRaises(PolicyError):
                require_worker_account()

    def test_native_roots_cannot_point_at_personal_files(self):
        cfg = SimpleNamespace(workspace_root=DATA / 'work', spool_root=DATA / 'spool', artifact_root=DATA / 'artifacts')
        require_native_config(cfg)
        cfg.workspace_root = Path('/Users/owner/Documents')
        with self.assertRaises(PolicyError):
            require_native_config(cfg)


class NativeRunnerTest(unittest.TestCase):
    def test_revoked_native_policy_never_launches_or_falls_back(self):
        runner = NativeUserRunner({WORKER}, set())
        with patch('native_runner.execution_mode', return_value=ISOLATED), patch('runner.subprocess.Popen') as process:
            self.assertFalse(runner.installed())
            for op in (lambda: runner.run(Job(id='test', kind='build', device_id=WORKER)),
                       lambda: runner.is_booted(WORKER), lambda: runner.shutdown(WORKER)):
                with self.assertRaises(PolicyError):
                    op()
            process.assert_not_called()

    def test_missing_helper_never_launches(self):
        runner = NativeUserRunner({WORKER}, set())
        with patch('native_runner.execution_mode', return_value=NATIVE), \
                patch('native_runner.require_protected_file', side_effect=FileNotFoundError), patch('runner.subprocess.Popen') as start:
            self.assertFalse(runner.installed())
            with self.assertRaises(FileNotFoundError):
                runner.run(Job(id='test', kind='build', device_id=WORKER))
            start.assert_not_called()

    def test_native_transport_still_refuses_personal_simulator(self):
        runner = NativeUserRunner({WORKER, PERSONAL}, set())
        with patch.object(runner, '_require_native'), patch('runner.subprocess.Popen') as start:
            with self.assertRaises(PolicyError):
                runner.run(Job(id='test', kind='build', device_id=PERSONAL))
            start.assert_not_called()

    def test_worker_success_is_required_not_just_json(self):
        runner = NativeUserRunner({WORKER}, set())
        with patch.object(runner, '_require_native'), patch('runner.subprocess.Popen', return_value=Mock(returncode=0)), \
                patch('runner._read_capped', return_value=(b'{"ok": false}', b'')):
            with self.assertRaises(RuntimeError):
                runner.run(Job(id='test', kind='build', device_id=WORKER))


class NativeInstallPreparationTest(unittest.TestCase):
    def test_default_install_stays_isolated_and_native_needs_second_flag(self):
        self.assertEqual(parse_args([]).execution_mode, ISOLATED)
        self.assertEqual(parse_args(['--execution-mode', NATIVE, '--accept-native-risk']).execution_mode, NATIVE)
        for argv in (['--execution-mode', NATIVE], ['--accept-native-risk'], ['--execution-mode', 'auto']):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                parse_args(argv)

    def test_data_acl_plan_does_not_grant_tokens_or_exports(self):
        with patch('install_system.subprocess.run') as run:
            _install_native_data_access()
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(calls[0][-2:], ['iosagent allow search', str(DATA)])
        self.assertFalse(any('/export' in cmd[-1] or '/Users/' in cmd[-1] for cmd in calls))
        spool = [cmd for cmd in calls if cmd[-1].endswith('/spool')]
        self.assertEqual(len(spool), 1)
        self.assertNotIn('write', spool[0][-2])
        self.assertNotIn('delete', spool[0][-2])

    def test_policy_write_is_atomic_and_only_contains_owner_choice(self):
        with tempfile.TemporaryDirectory() as directory, patch('install_system.LIBRARY', Path(directory)):
            _write_execution_policy(True)
            self.assertEqual(json.loads((Path(directory) / 'execution.json').read_text()),
                             {'mode': NATIVE, 'acknowledgement': NATIVE_ACK})
            _write_execution_policy(False)
            self.assertEqual(json.loads((Path(directory) / 'execution.json').read_text()), {'mode': ISOLATED})
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['execution.json'])


if __name__ == '__main__':
    unittest.main()
