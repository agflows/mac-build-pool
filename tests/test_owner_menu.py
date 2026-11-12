import ctypes
import errno
import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from broker import agent_instructions, load_trial_peer, start_peer_trial
from owner_menu import RUsageInfoV0, broker_disk_paths, peer_uid, role_memory_footprint, snapshot


class OwnerMenuTest(unittest.TestCase):
    def test_instructions_from_validation_use_the_public_agent_token(self):
        validation = SimpleNamespace(token="validation-token", operator_token="validation-operator")
        public = SimpleNamespace(token_file=Path("/test/agent-token"), listen_port=8741)
        runner = SimpleNamespace(validation_mode=True, installed=Mock())
        with patch("broker.load_broker_config", return_value=public), \
             patch("broker._read_secret", return_value="public-agent-token") as read, \
             patch("broker.listen_host", return_value="100.64.0.9"):
            instructions = agent_instructions(None, validation, runner)
        read.assert_called_once_with(public.token_file, "agent token")
        runner.installed.assert_not_called()
        self.assertIn("http://100.64.0.9:8741", instructions)
        self.assertIn("public-agent-token", instructions)
        self.assertIn("Remote jobs are disabled.", instructions)
        self.assertNotIn("validation-token", instructions)
        self.assertNotIn("validation-operator", instructions)

    def test_instructions_report_verified_public_readiness(self):
        app = SimpleNamespace(token="public-agent-token", operator_token="operator-token")
        config = SimpleNamespace(listen_port=8741)
        runner = SimpleNamespace(validation_mode=False, installed=lambda: True)
        with patch("broker.listen_host", return_value="100.64.0.9"):
            instructions = agent_instructions(config, app, runner)
        self.assertIn("Remote jobs are enabled.", instructions)
        self.assertNotIn("operator-token", instructions)

    def test_instructions_report_the_active_trial_at_the_regular_address(self):
        app = SimpleNamespace(token="validation-token", operator_token="validation-operator")
        config = SimpleNamespace(token_file=Path("/test/agent-token"), listen_port=8741)
        runner = SimpleNamespace(validation_mode=True, installed=lambda: True)
        with patch("broker.load_broker_config", return_value=config), \
             patch("broker._read_secret", return_value="public-agent-token"), \
             patch("broker.listen_host", return_value="100.64.0.9"):
            instructions = agent_instructions(None, app, runner, trial_peer="100.78.73.28")
        self.assertIn("http://100.64.0.9:8741", instructions)
        self.assertIn("public-agent-token", instructions)
        self.assertIn("Remote trial jobs are enabled for 100.78.73.28.", instructions)
        self.assertNotIn("validation-token", instructions)

    def test_trial_peer_requires_a_protected_config_and_tailscale_address(self):
        path = Mock(spec=Path)
        path.read_text.return_value = '{"peer":"100.78.73.28"}'
        with patch("broker.require_protected_file") as protected:
            self.assertEqual(load_trial_peer(path), "100.78.73.28")
            protected.assert_called_once_with(path)
            path.read_text.return_value = '{"peer":"192.0.2.1"}'
            with self.assertRaisesRegex(SystemExit, "Tailscale"):
                load_trial_peer(path)

    def test_trial_refuses_an_unisolated_runner(self):
        with self.assertRaisesRegex(SystemExit, "isolated validation worker"):
            start_peer_trial(None, SimpleNamespace(runner=object()), "100.78.73.28")

    def test_local_peer_identity_comes_from_kernel(self):
        first, second = socket.socketpair()
        with first, second:
            self.assertEqual(peer_uid(first), os.getuid())

    def test_named_lease_and_combined_usage(self):
        runner = SimpleNamespace(_call=Mock(return_value={
            'state': 'active', 'memoryBytes': 100, 'memoryMetric': 'footprint', 'diskBytes': 300,
        }))
        scheduler = SimpleNamespace(
            _lock=threading.Lock(), lease={'id': 'a' * 16, 'status': 'active', 'name': 'Watch QA'},
            jobs={}, running_ids=set(), runner=runner,
        )
        with patch('owner_menu.broker_disk_paths', return_value=[]), \
             patch('owner_menu.usage', return_value={
                 'memoryBytes': 30, 'memoryMetric': 'footprint', 'diskBytes': 50,
             }):
            state = snapshot(scheduler)
        self.assertEqual(state['state'], 'In use')
        self.assertEqual(state['sessionName'], 'Watch QA')
        self.assertEqual((state['memoryBytes'], state['diskBytes']), (130, 350))
        self.assertEqual(state['memoryMetric'], 'footprint')

    def test_role_footprint_counts_same_uid_and_skips_exited_process(self):
        def read(pid, version, buffer):
            self.assertEqual(version, 0)
            if pid == 12:
                ctypes.set_errno(errno.ESRCH)
                return -1
            counters = ctypes.cast(buffer, ctypes.POINTER(RUsageInfoV0)).contents
            counters.resident_size = 5
            counters.physical_footprint = {10: 100, 11: 900}[pid]
            return 0

        libproc = SimpleNamespace(proc_pid_rusage=Mock(side_effect=read))
        with patch('owner_menu.ctypes.CDLL', return_value=libproc), \
             patch('owner_menu.os.geteuid', return_value=501), \
             patch('owner_menu.subprocess.check_output', return_value='501 10\n501 11\n501 12\n502 20\n'):
            self.assertEqual(role_memory_footprint(), 1000)

    def test_broker_measurement_skips_retired_native_workspace_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'broker.py').touch()
            (root / 'data/work').mkdir(parents=True)
            (root / 'data/tmp').mkdir()
            with patch('owner_menu.LIBRARY', root):
                measured = broker_disk_paths()
            self.assertIn(root / 'broker.py', measured)
            self.assertIn(root / 'data/export', measured)
            self.assertNotIn(root / 'data/work', measured)
            self.assertNotIn(root / 'data/tmp', measured)
