"""Acceptance proof must match the VM configuration that runs jobs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from policy import PolicyError
from vm_runner import TartRunner


class ActivationTest(unittest.TestCase):
    def test_activation_rejects_a_report_for_another_configuration(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/install-tart-controller.py'
        spec = importlib.util.spec_from_file_location('install_tart_controller', script)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
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

    def test_public_job_rechecks_proof_after_submission(self):
        runner = TartRunner(set(), set(), None)
        runner.verified = Mock(return_value=False)
        runner._call = Mock()
        with self.assertRaises(PolicyError) as error:
            runner.run(SimpleNamespace(kind='vm_start'))
        self.assertEqual(error.exception.code, 'isolation_required')
        runner._call.assert_not_called()
