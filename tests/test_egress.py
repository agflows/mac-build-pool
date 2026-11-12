import socket
import unittest
from egress_policy import destination, EgressDenied

class EgressTest(unittest.TestCase):
    def answer(self, address):
        return lambda *a, **kw: [(socket.AF_INET6 if ':' in address else socket.AF_INET,
                                 socket.SOCK_STREAM, 6, '', (address, 443))]

    def test_only_exact_package_hosts_and_tls_port(self):
        for host,port in [('localhost',443),('registry.npmjs.org.evil.test',443),
                          ('REGISTRY.NPMJS.ORG',443),('registry.npmjs.org.',443),
                          ('registry.npmjs.org',80),('registry.npmjs.org','443')]:
            with self.assertRaises(EgressDenied):
                destination(host,port,resolver=self.answer('1.1.1.1'))
        self.assertEqual(destination('registry.npmjs.org',443,resolver=self.answer('1.1.1.1'))[0][3],('1.1.1.1',443))

    def test_rebinding_and_private_ipv4_ipv6_are_denied(self):
        for address in ('127.0.0.1','192.168.1.1','10.0.0.1','100.114.181.78','169.254.169.254',
                        '0.0.0.0','224.0.0.1','::1','fe80::1','fd00::1','::ffff:127.0.0.1'):
            with self.subTest(address=address), self.assertRaises(EgressDenied):
                destination('registry.npmjs.org',443,resolver=self.answer(address))

    def test_host_public_address_and_mixed_dns_answers_are_denied(self):
        with self.assertRaises(EgressDenied):
            destination('registry.npmjs.org',443,host_addresses=['1.1.1.1'],resolver=self.answer('1.1.1.1'))
        with self.assertRaises(EgressDenied):
            destination('registry.npmjs.org',443,resolver=lambda *a,**k:self.answer('1.1.1.1')()+self.answer('127.0.0.1')())
