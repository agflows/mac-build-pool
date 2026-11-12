import unittest
from unittest.mock import Mock

from vm_service import Service
from tart_lease import LeaseError
from policy import PolicyError

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
