from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import subprocess
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, call, patch

from vm_service import BuildTart, Service, STOP_GUEST_SIMULATORS
from vm_runner import TartRunner
from tart_lease import LeaseError
from policy import PolicyError
from worker_cache import WorkerCache

WORKER='3C8BB98E-6383-446B-AF87-1E1282762A13'
PERSONAL='4D015300-4BAE-4E6D-89C9-BC4D454E4216'
GUEST='A1111111-2222-3333-4444-555555555555'
LEASE='a'*16

class VMServiceTest(unittest.TestCase):
    def setUp(self):
        self.backend=Mock()
        self.backend.operation.return_value={'ok':True}
        self.service=Service(self.backend,logical_device=WORKER,guest_device=GUEST)
        self.now=100
        self.service.controller.clock=lambda:self.now

    def reserve(self):
        return self.service.dispatch({'op':'reserve','lease_id':LEASE,'ttl':300})

    def test_restore_reserves_fresh_lease_and_streams_matching_binary(self):
        with tempfile.TemporaryDirectory() as root:
            self.service.cache = WorkerCache(Path(root) / 'cache', capacity=500, free_reserve=0)
            self.addCleanup(self.service.cache.db.close)
            self.backend.base_identity = {'diskSHA256':'reviewed'}
            self.backend.cache_projects = {}
            project, resume = 'a' * 64, 'b' * 64
            data = b'cached simulator bundle'
            with self.service.cache.stage(len(data), project) as (entry, archive):
                archive.write(data)
                archive.flush()
                self.service.cache.publish(entry, 'binary', project, hashlib.sha256(data).hexdigest(),
                                           resume=resume, device=WORKER, base='reviewed')

            def transfer(vm, operation, device, *, source):
                self.assertEqual(operation, 'restore')
                self.assertEqual(device, GUEST)
                self.assertEqual(source.read(), data)
                return 0, b'{"ok":true,"bundle_id":"com.example.fixture"}', b''

            self.backend.transfer_app.side_effect = transfer
            request = {'op':'reserve', 'lease_id':LEASE, 'project':project,
                       'resume_id':resume, 'session_id':'c' * 64}
            self.assertTrue(self.service.dispatch(dict(request, project='d' * 64))['cacheMiss'])
            self.backend.start.assert_not_called()
            self.assertEqual(self.service.dispatch(request)['deviceId'], WORKER)
            result = self.service.dispatch({'op':'restore','lease_id':LEASE,'device_id':WORKER})
            self.assertEqual(result['bundle_id'], 'com.example.fixture')
            self.backend.operation.assert_not_called()

    def test_status_and_reservation_do_not_start_a_vm(self):
        self.assertEqual(self.service.dispatch({'op':'status'})['state'],'idle')
        self.reserve()
        self.backend.start.assert_not_called()

    def test_personal_device_and_unsupported_operation_never_start_guest(self):
        self.reserve()
        for payload in ({'op':'shell','lease_id':LEASE},{'op':'boot','lease_id':LEASE,'device_id':PERSONAL}):
            with self.assertRaises((LeaseError,PolicyError)):
                self.service.dispatch(payload)
        self.backend.start.assert_not_called()

    def test_idle_simulator_queries_and_shutdown_never_start_guest(self):
        self.reserve()
        self.assertFalse(self.service.dispatch({'op':'booted','lease_id':LEASE,'device_id':WORKER})['booted'])
        self.service.dispatch({'op':'shutdown','lease_id':LEASE,'device_id':WORKER})
        self.backend.start.assert_not_called()

    def test_input_requires_an_already_active_vm(self):
        self.reserve()
        with self.assertRaises(LeaseError):
            self.service.dispatch({'op': 'input', 'lease_id': LEASE, 'device_id': WORKER})
        self.backend.start.assert_not_called()

    def test_lease_device_mapping_and_one_ingest_per_revision(self):
        self.reserve()
        payload={'op':'prepare','lease_id':LEASE,'device_id':WORKER,'revision_id':'rev1','source_base64':'eA=='}
        self.service.dispatch(payload)
        request=self.backend.operation.call_args.args[1]
        self.assertEqual(request['device_id'],GUEST)
        self.assertNotIn('lease_id',request)
        self.assertEqual(request['source_base64'],'eA==')
        self.service.dispatch(payload)
        self.assertNotIn('source_base64',self.backend.operation.call_args.args[1])
        self.backend.start.assert_called_once()

    def test_prepare_and_build_stop_simulators_before_guest_work(self):
        self.reserve()
        self.service.dispatch({'op': 'prepare', 'lease_id': LEASE})
        self.service.dispatch({'op': 'build', 'lease_id': LEASE})
        vm = self.backend.start.call_args.args[0]
        self.assertEqual(self.backend.mock_calls[-4:], [
            call.stop_simulators(vm),
            call.operation(vm, {'op': 'prepare'}),
            call.stop_simulators(vm),
            call.operation(vm, {'op': 'build'}),
        ])

    def test_failed_simulator_shutdown_prevents_build_and_reaps_guest(self):
        self.reserve()
        self.backend.stop_simulators.side_effect = LeaseError('guest simulator still running')
        with self.assertRaisesRegex(LeaseError, 'still running'):
            self.service.dispatch({'op': 'build', 'lease_id': LEASE})
        self.backend.operation.assert_not_called()
        self.backend.delete.assert_called_once()

    def test_build_excludes_another_build_and_simulator_boot(self):
        self.reserve()
        building = threading.Event()
        release = threading.Event()
        contenders_ready = threading.Barrier(3)

        def operation(vm, request):
            if request.get('job_id') == 'first':
                building.set()
                if not release.wait(5):
                    raise TimeoutError('test build was not released')
            return {'ok': True}

        def contend(request):
            contenders_ready.wait(timeout=5)
            return self.service.dispatch(request)

        self.backend.operation.side_effect = operation
        with ThreadPoolExecutor(max_workers=3) as pool:
            build = pool.submit(self.service.dispatch, {'op': 'build', 'lease_id': LEASE, 'job_id': 'first'})
            try:
                self.assertTrue(building.wait(5))
                second = pool.submit(contend, {'op': 'build', 'lease_id': LEASE})
                boot = pool.submit(contend, {'op': 'boot', 'lease_id': LEASE, 'device_id': WORKER})
                contenders_ready.wait(timeout=5)
                self.assertFalse(second.done())
                self.assertFalse(boot.done())
                self.backend.operation.assert_called_once()
            finally:
                release.set()
            for result in (build, second, boot):
                self.assertTrue(result.result(timeout=5)['ok'])

    def test_watch_only_accepts_the_public_logical_id(self):
        watch = 'A23FD418-22F2-4BA4-9E87-91E86A9D3F09'
        guest_watch = 'E1111111-2222-3333-4444-555555555555'
        self.service = Service(self.backend, logical_device=WORKER, guest_device=GUEST,
                               watch_devices=(watch, guest_watch))
        self.reserve()
        with self.assertRaises(PolicyError):
            self.service.dispatch({'op': 'boot', 'lease_id': LEASE, 'device_id': guest_watch})
        self.backend.start.assert_not_called()
        self.service.dispatch({'op': 'boot', 'lease_id': LEASE, 'device_id': watch})
        self.assertEqual(self.backend.operation.call_args.args[1]['device_id'], guest_watch)

    def test_watch_mapping_cannot_alias_the_phone(self):
        watch = 'A23FD418-22F2-4BA4-9E87-91E86A9D3F09'
        with self.assertRaises(LeaseError):
            Service(self.backend, logical_device=WORKER, guest_device=GUEST,
                    watch_devices=(watch, GUEST.lower()))

    def test_expiry_destroys_the_whole_guest_without_renewal(self):
        self.reserve()
        self.service.dispatch({'op':'boot','lease_id':LEASE,'device_id':WORKER})
        self.now+=300
        self.service.controller.tick()
        self.backend.stop.assert_called_once()
        self.backend.delete.assert_called_once()
        with self.assertRaises(LeaseError):
            self.service.dispatch({'op':'boot','lease_id':LEASE,'device_id':WORKER})

    def test_transport_timeout_stops_guest_and_does_not_fall_back(self):
        self.reserve()
        self.backend.operation.side_effect=TimeoutError('hung build')
        with self.assertRaises(TimeoutError):
            self.service.dispatch({'op':'boot','lease_id':LEASE,'device_id':WORKER})
        self.backend.stop.assert_called_once()
        self.backend.delete.assert_called_once()

    def test_operation_cannot_report_success_after_lease_expiry(self):
        self.reserve()
        def complete_after_expiry(*args):
            self.now+=300
            self.service.controller.tick()
            return {'ok':True}
        self.backend.operation.side_effect=complete_after_expiry
        with self.assertRaises(LeaseError):
            self.service.dispatch({'op':'boot','lease_id':LEASE,'device_id':WORKER})
        self.assertEqual(self.service.controller.status()['state'],'idle')

    def test_reported_guest_timeout_destroys_guest_and_preserves_failure(self):
        self.reserve()
        self.backend.operation.return_value={'ok':False,'error':'job_timeout','exitCode':124}
        result=self.service.dispatch({'op':'boot','lease_id':LEASE,'device_id':WORKER})
        self.assertEqual(result['exitCode'],124)
        self.backend.stop.assert_called_once()
        self.backend.delete.assert_called_once()
        self.assertEqual(self.service.controller.status()['state'],'idle')

    def test_rejected_second_lease_does_not_forget_staged_revision(self):
        self.reserve()
        self.service.loaded.add('rev1')
        with self.assertRaises(LeaseError):
            self.service.dispatch({'op':'reserve','lease_id':'b'*16})
        self.assertIn('rev1',self.service.loaded)


class GuestSimulatorTest(unittest.TestCase):
    def test_preview_validation_binds_bytes_to_frame_id(self):
        raw = b"\xff\xd8\xffexample\xff\xd9"
        frame_id = hashlib.sha256(raw).hexdigest()
        preview = {"id": frame_id, "changed": True, "jpegBase64": base64.b64encode(raw).decode()}
        self.assertEqual(TartRunner._validate_preview(preview, None), preview)
        self.assertEqual(TartRunner._validate_preview({"id": frame_id, "changed": False}, frame_id),
                         {"id": frame_id, "changed": False})
        with self.assertRaises(PolicyError):
            TartRunner._validate_preview({**preview, "id": "wrong"}, None)

    def test_waits_for_both_phone_and_watch_to_shut_down(self):
        with patch('os.chdir'), patch('time.sleep'), \
                patch.object(subprocess, 'check_output', side_effect=[
                    b'{"devices":{"phone":[{"state":"Booted"}],"watch":[{"state":"Booting"}]}}',
                    b'{"devices":{"phone":[{"state":"Shutdown"}],"watch":[{"state":"Shutting Down"}]}}',
                    b'{"devices":{"phone":[{"state":"Shutdown"}],"watch":[{"state":"Shutdown"}]}}',
                ]) as list_devices, patch.object(subprocess, 'run') as shutdown:
            exec(compile(STOP_GUEST_SIMULATORS, 'guest simulator shutdown', 'exec'), {})
        shutdown.assert_called_once_with(['/usr/bin/xcrun', 'simctl', 'shutdown', 'all'], check=True, timeout=60)
        self.assertEqual(list_devices.call_args_list[0].kwargs['timeout'], 90)
        self.assertEqual(list_devices.call_count, 3)

    def test_broker_allows_the_full_controller_boot_probe_timeout(self):
        runner = TartRunner({WORKER}, set(), None)
        runner.lease = LEASE
        runner._call = Mock(side_effect=[{'state': 'active'}, {'booted': True}])
        self.assertTrue(runner.is_booted(WORKER))

        backend = object.__new__(BuildTart)
        backend.binary = '/trusted/tart'
        backend.env = {}
        with patch('vm_service.communicate', return_value=(0, b'{"ok":true,"booted":true}', b'')) as transport:
            backend.operation('lease-fixture', {'op': 'booted', 'device_id': GUEST})
        self.assertGreater(runner._call.call_args.kwargs['timeout'], transport.call_args.kwargs['timeout'])
