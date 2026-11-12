import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from broker import agent_instructions
from owner_menu import broker_disk_paths, peer_uid, snapshot


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

    def test_local_peer_identity_comes_from_kernel(self):
        first, second = socket.socketpair()
        with first, second:
            self.assertEqual(peer_uid(first), os.getuid())

    def test_named_lease_and_combined_usage(self):
        runner = SimpleNamespace(_call=Mock(return_value={
            'state': 'active', 'memoryBytes': 100, 'diskBytes': 300,
        }))
        scheduler = SimpleNamespace(
            _lock=threading.Lock(), lease={'id': 'a' * 16, 'status': 'active', 'name': 'Watch QA'},
            jobs={}, running_ids=set(), runner=runner,
        )
        with patch('owner_menu.broker_disk_paths', return_value=[]), \
             patch('owner_menu.usage', return_value={'memoryBytes': 30, 'diskBytes': 50}):
            state = snapshot(scheduler)
        self.assertEqual(state['state'], 'In use')
        self.assertEqual(state['sessionName'], 'Watch QA')
        self.assertEqual((state['memoryBytes'], state['diskBytes']), (130, 350))

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
