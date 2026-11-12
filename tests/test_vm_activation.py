"""Acceptance proof must match the VM configuration that runs jobs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from policy import PolicyError
from vm_runner import TartRunner


class ActivationTest(unittest.TestCase):
    def setUp(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/install-tart-controller.py'
        spec = importlib.util.spec_from_file_location('install_tart_controller', script)
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)

    def test_activation_rejects_a_report_for_another_configuration(self):
        installer = self.installer
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'vm.json').write_text('{"memory_mb":4096}')
            png = b'\x89PNG\r\n\x1a\n'
            screenshot = root / 'simulator.png'
            screenshot.write_bytes(png)
            report = root / 'report.json'
            report.write_text(json.dumps({
                'appBuildPassed': True, 'securityNegativesPassed': True,
                'leaseExpiryPassed': True, 'codeSHA256': 'installed-code',
                'vmConfigSHA256': hashlib.sha256(b'{"memory_mb":8192}').hexdigest(),
                'screenshot': str(screenshot), 'screenshotSHA256': hashlib.sha256(png).hexdigest(),
            }))
            with patch('cli.read_secret', return_value='fixture'), patch.object(installer, 'LIB', root), \
                 patch.object(installer, 'idle'), patch.object(installer, 'code_hash', return_value='installed-code'), \
                 patch.object(installer, 'root_file') as root_file, patch.object(installer, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'different VM configuration'):
                    installer.activate(SimpleNamespace(report=report))
                root_file.assert_not_called()
                run.assert_not_called()

    def test_replacing_base_requires_explicit_idle_maintenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            new = root / 'reviewed'
            target = root / 'vms/worker-base'
            for path, disk in ((new, b'new image'), (target, b'old')):
                path.mkdir(parents=True)
                (path / 'disk.img').write_bytes(disk)
                (path / 'config.json').write_text('{}')
            with self.assertRaisesRegex(SystemExit, 'review it'):
                self.installer.install_base(new, target, replace=False)
            lease = target.parent / 'lease-0123456789abcdef'
            lease.mkdir()
            with self.assertRaisesRegex(SystemExit, 'remaining lease'):
                self.installer.install_base(new, target, replace=True)
            lease.rmdir()

            def command(argv, check=True):
                if argv[0] == '/bin/cp':
                    shutil.copytree(argv[-2], argv[-1])
                return SimpleNamespace(returncode=int(argv[0] == '/bin/launchctl'))

            with patch.object(self.installer, 'run', side_effect=command):
                self.installer.install_base(new, target, replace=True)
            self.assertEqual((target / 'disk.img').read_bytes(), b'new image')
            self.assertEqual(list(target.parent.iterdir()), [target])

    def test_public_job_rechecks_proof_after_submission(self):
        runner = TartRunner(set(), set(), None)
        runner.verified = Mock(return_value=False)
        runner._call = Mock()
        with self.assertRaises(PolicyError) as error:
            runner.run(SimpleNamespace(kind='vm_start'))
        self.assertEqual(error.exception.code, 'isolation_required')
        runner._call.assert_not_called()
