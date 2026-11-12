"""Deterministic lease lifecycle tests; actual Tart trial is reported separately."""
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock

from tart_lease import LeaseController, LeaseError, OfflineTart


class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.backend = Mock()
        self.controller = LeaseController(self.backend, clock=lambda: self.now, max_ttl=300, max_lifetime=500)

    def test_idle_status_does_not_boot(self):
        self.assertEqual(self.controller.status(), {'state': 'idle', 'vm': None})
        self.controller.tick()
        self.backend.start.assert_not_called()

    def test_lease_is_exclusive_and_stays_up_without_jobs(self):
        lease = self.controller.acquire(60)
        with self.assertRaises(LeaseError):
            self.controller.acquire()
        self.now += 59
        self.controller.tick()
        self.assertEqual(self.controller.require_active(lease['leaseId']), lease['vm'])
        self.backend.stop.assert_not_called()

    def test_expiry_stops_and_deletes_exact_guest(self):
        lease = self.controller.acquire(60)
        self.now += 60
        self.controller.tick()
        self.backend.stop.assert_called_once_with(lease['vm'])
        self.backend.delete.assert_called_once_with(lease['vm'])
        self.assertEqual(self.controller.status()['state'], 'idle')
        with self.assertRaises(LeaseError):
            self.controller.require_active(lease['leaseId'])

    def test_renewal_has_absolute_lifetime_and_cannot_revive_expired_lease(self):
        lease = self.controller.acquire(300)
        self.now += 299
        self.assertEqual(self.controller.renew(lease['leaseId'], 300)['expiresIn'], 201)
        self.now += 201
        with self.assertRaises(LeaseError):
            self.controller.renew(lease['leaseId'])
        self.controller.tick()
        self.assertEqual(self.controller.status()['state'], 'idle')

    def test_wrong_lease_cannot_renew_or_release(self):
        self.controller.acquire()
        for operation in (self.controller.renew, self.controller.release, self.controller.require_active):
            with self.assertRaises(LeaseError):
                operation('wrong')
        self.backend.stop.assert_not_called()

    def test_failed_termination_blocks_delete_and_replacement(self):
        lease = self.controller.acquire()
        self.backend.stop.side_effect = RuntimeError('stop failed')
        with self.assertRaises(RuntimeError):
            self.controller.release(lease['leaseId'])
        self.backend.delete.assert_not_called()
        with self.assertRaises(LeaseError):
            self.controller.acquire()
        self.backend.stop.side_effect = None
        self.controller.tick()
        self.assertEqual(self.controller.status()['state'], 'idle')

    def test_expiry_can_cancel_slow_start(self):
        started, cancelled = threading.Event(), threading.Event()
        self.backend.start.side_effect = lambda name: (started.set(), cancelled.wait(2))
        self.backend.stop.side_effect = lambda name: cancelled.set()
        failures = []
        def acquire():
            try:
                self.controller.acquire(1)
            except LeaseError as error:
                failures.append(str(error))
        thread = threading.Thread(target=acquire)
        thread.start()
        self.assertTrue(started.wait(1))
        self.now += 1
        self.controller.tick()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(failures)
        self.assertEqual(self.controller.status()['state'], 'idle')

    def test_release_and_watchdog_cleanup_once(self):
        lease = self.controller.acquire()
        stopping, finish = threading.Event(), threading.Event()

        def stop(name):
            stopping.set()
            self.assertTrue(finish.wait(2))

        self.backend.stop.side_effect = stop
        release = threading.Thread(target=self.controller.release, args=(lease['leaseId'],))
        release.start()
        self.assertTrue(stopping.wait(1))
        tick = threading.Thread(target=self.controller.tick)
        tick.start()
        finish.set()
        for thread in (release, tick):
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.backend.stop.assert_called_once_with(lease['vm'])
        self.backend.delete.assert_called_once_with(lease['vm'])
        self.assertEqual(self.controller.status()['state'], 'idle')

    def test_bad_duration_never_starts_vm(self):
        for ttl in (True, 0, -1, 301, '60', float('nan')):
            with self.assertRaises(LeaseError):
                self.controller.acquire(ttl)
        self.backend.start.assert_not_called()

    def test_start_failure_and_daemon_exit_cleanup(self):
        self.backend.start.side_effect = RuntimeError('boot failed')
        with self.assertRaises(RuntimeError):
            self.controller.acquire()
        self.assertEqual(self.controller.status()['state'], 'idle')
        self.backend.start.side_effect = None
        lease = self.controller.acquire()
        self.controller.close()
        self.backend.stop.assert_called_with(lease['vm'])
        self.backend.delete.assert_called_with(lease['vm'])


class OfflineTartTest(unittest.TestCase):
    def test_nonzero_graceful_stop_can_still_verify_termination(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            name = 'lease-0123456789abcdef'
            (home / 'vms' / name).mkdir(parents=True)
            backend = OfflineTart(home / 'tart', home, 'base', home / 'logs')
            process = backend.processes[name] = Mock()
            process.poll.return_value = None
            backend.call = Mock(side_effect=[
                subprocess.CalledProcessError(1, 'tart stop'),
                subprocess.CompletedProcess([], 0, stdout='{"Running": false, "State": "stopped"}'),
            ])
            backend.stop(name)
            process.wait.assert_called_once_with(timeout=10)
            self.assertEqual(backend.call.call_args.args[:2], ('get', name))
