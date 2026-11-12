import os
import socket
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from owner_menu import peer_uid, snapshot


class OwnerMenuTest(unittest.TestCase):
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
        with patch('owner_menu.usage', return_value={'memoryBytes': 30, 'diskBytes': 50}):
            state = snapshot(scheduler)
        self.assertEqual(state['state'], 'In use')
        self.assertEqual(state['sessionName'], 'Watch QA')
        self.assertEqual((state['memoryBytes'], state['diskBytes']), (130, 350))
