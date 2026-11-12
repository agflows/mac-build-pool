import unittest
from egress_policy import EgressDenied
from http_policy import HTTPGate

class HTTPPolicyTest(unittest.TestCase):
    def test_jsdelivr_allows_only_cocoapods_spec_reads(self):
        host = b'\r\nHost: cdn.jsdelivr.net\r\n\r\n'
        spec = b'/cocoa/Specs/a/9/3/SocketRocket/0.7.1/SocketRocket.podspec.json'
        self.assertIn(spec, HTTPGate('cdn.jsdelivr.net').feed(b'GET ' + spec + b' HTTP/1.1' + host))
        for method, path in ((b'POST', spec), (b'GET', b'/npm/expo'),
                             (b'GET', b'/cocoa/Specs/a/9/3/../Other/1/Other.podspec.json'),
                             (b'GET', spec + b'?redirect=example.com')):
            with self.subTest(method=method, path=path), self.assertRaises(EgressDenied):
                HTTPGate('cdn.jsdelivr.net').feed(method + b' ' + path + b' HTTP/1.1' + host)

    def test_canonical_download_and_close_prevent_second_request(self):
        gate=HTTPGate('registry.npmjs.org')
        result=gate.feed(b'GET /expo HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: keep-alive\r\n\r\n')
        self.assertIn(b'Host: registry.npmjs.org\r\nConnection: close',result)
        with self.assertRaises(EgressDenied):gate.feed(b'GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n')

    def test_fronting_absolute_urls_smuggling_and_package_upload_are_denied(self):
        for request in [
          b'GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n',
          b'GET https://evil.test/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n',
          b'GET //evil.test/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n',
          b'GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\nHost: evil.test\r\n\r\n',
          b'POST / HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 0\r\nContent-Length: 3\r\n\r\n',
          b'GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\nTransfer-Encoding: chunked\r\n\r\n',
          b'POST /upload HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n',
          b'GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\nGET / HTTP/1.1\r\nHost: evil.test\r\n\r\n']:
            with self.subTest(request=request), self.assertRaises(EgressDenied):
                HTTPGate('registry.npmjs.org').feed(request)

    def test_backend_json_body_is_bounded_and_cannot_smuggle_a_second_request(self):
        gate=HTTPGate('backend.supabase.co')
        gate.feed(b'POST /auth HTTP/1.1\r\nHost: backend.supabase.co\r\nContent-Length: 2\r\n\r\n')
        self.assertEqual(gate.feed(b'{}'),b'{}')
        with self.assertRaises(EgressDenied):gate.feed(b'GET /evil HTTP/1.1\r\n')

    def test_websocket_only_after_approved_backend_upgrade(self):
        gate=HTTPGate('backend.supabase.co')
        gate.feed(b'GET /realtime HTTP/1.1\r\nHost: backend.supabase.co\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
        with self.assertRaises(EgressDenied):gate.feed(b'before-handshake')
        gate.response(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n')
        self.assertEqual(gate.feed(b'websocket-frame'),b'websocket-frame')
