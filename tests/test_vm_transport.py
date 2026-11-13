import json
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import tempfile
import ssl
import shutil
import unittest
from unittest.mock import patch

from vm_transport import communicate
from host_egress import Relay
from egress_policy import EgressDenied
from worker_cache import WorkerCache

ROOT=Path(__file__).resolve().parents[1]

class TransportTest(unittest.TestCase):
    def test_large_stdin_does_not_deadlock_and_stdout_is_bounded(self):
        data=b'x'*(2*1024*1024)
        code,output,error=communicate([sys.executable,'-c','import sys; d=sys.stdin.buffer.read();sys.stdout.buffer.write(d)'],
                                       data,env={'PATH':'/usr/bin:/bin'},timeout=10,cap=len(data))
        self.assertEqual(code,0)
        self.assertEqual(output,data)
        with self.assertRaises(ValueError):
            communicate([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*1000000)'],
                        b'',env={'PATH':'/usr/bin:/bin'},timeout=10,cap=100)

    def test_file_streams_transfer_without_buffering_on_host(self):
        body = b'hello simulator' * 10240
        destination = io.BytesIO()
        code, output, error = communicate(
            [sys.executable, '-c', 'import shutil,sys;shutil.copyfileobj(sys.stdin.buffer,sys.stdout.buffer)'],
            io.BytesIO(body), env={'PATH':'/usr/bin:/bin'}, timeout=10, cap=len(body), sink=destination)
        self.assertEqual((code, output, error), (0, b'', b''))
        self.assertEqual(destination.getvalue(), body)

    def test_hung_guest_transport_is_terminated(self):
        with self.assertRaises(TimeoutError):
            communicate([sys.executable,'-c','import time;time.sleep(60)'],b'',
                        env={'PATH':'/usr/bin:/bin'},timeout=0.1)

class RelayTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tls=Path(self.temp.name)
        config=self.tls/'openssl.conf'
        config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=backend.example.test\n[ext]\nsubjectAltName=DNS:backend.example.test,DNS:registry.npmjs.org\nbasicConstraints=CA:TRUE\n')
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1',
              '-config',str(config),'-keyout',str(self.tls/'proxy-leaf.key'),'-out',str(self.tls/'proxy-leaf.pem')],
              check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.process=subprocess.Popen([sys.executable,str(ROOT/'guest_proxy.py'),'--tls-dir',str(self.tls)],cwd='/private/tmp',
                         env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self.relay=Relay(self.process, allowed={'registry.npmjs.org', 'backend.example.test'})
        self.addCleanup(self.relay.close)
        # Guest proxy listener starts independently of the host reader.
        import time
        for _ in range(100):
            try:
                connection=socket.create_connection(('127.0.0.1',18741),timeout=0.1)
                connection.close()
                break
            except OSError:
                time.sleep(0.02)

    def request(self,host="registry.npmjs.org"):
        connection=socket.create_connection(('127.0.0.1',18741),timeout=5)
        connection.sendall(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode())
        header=b''
        while not header.endswith(b'\r\n\r\n'):
            data=connection.recv(1)
            if not data:break
            header+=data
        return connection,header

    def test_approved_binary_tunnel_and_connect_header_order(self):
        upstream,echo=socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(echo.close)
        def server():
            try:
                header=b''
                while not header.endswith(b'\r\n\r\n'):header+=echo.recv(1)
                length=int(next(line.split(b':',1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                data=bytearray()
                while len(data)<length:data.extend(echo.recv(length-len(data)))
                echo.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(length).encode()+b'\r\nConnection: close\r\n\r\n'+data)
                echo.shutdown(socket.SHUT_WR)
            except OSError:pass
        threading.Thread(target=server,daemon=True).start()
        with patch('host_egress.connect',return_value=upstream):
            thread=threading.Thread(target=self.relay.run,daemon=True)
            thread.start()
            client,header=self.request('backend.example.test')
            self.assertEqual(header,b'HTTP/1.1 200 Connection Established\r\n\r\n')
            context=ssl.create_default_context(cafile=str(self.tls/'proxy-leaf.pem'))
            with context.wrap_socket(client,server_hostname='backend.example.test') as connection:
                data=bytes(range(256))*500
                connection.sendall(b'POST /test HTTP/1.1\r\nHost: backend.example.test\r\nContent-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data)
                result=bytearray()
                while True:
                    part=connection.recv(32768)
                    if not part:break
                    result.extend(part)
                self.assertEqual(bytes(result).split(b'\r\n\r\n',1)[1],data)

    def test_package_download_is_replayed_without_upstream_connection(self):
        self.relay.cache = WorkerCache(self.tls / 'cache', capacity=10000, free_reserve=0)
        self.addCleanup(self.relay.cache.db.close)
        self.relay.project = 'fixture'
        upstream, origin = socket.socketpair()
        self.addCleanup(upstream.close)
        self.addCleanup(origin.close)
        response = (b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n'
                    b'Cache-Control: public, max-age=300\r\nConnection: close\r\n\r\nfixture')

        def server():
            request = b''
            while not request.endswith(b'\r\n\r\n'):
                part = origin.recv(4096)
                if not part:
                    return
                request += part
            origin.sendall(response)
            origin.shutdown(socket.SHUT_WR)

        threading.Thread(target=server, daemon=True).start()
        threading.Thread(target=self.relay.run, daemon=True).start()
        context = ssl.create_default_context(cafile=str(self.tls/'proxy-leaf.pem'))
        with patch('host_egress.connect', side_effect=[upstream, AssertionError('unexpected cache miss')]) as connect:
            for _ in range(2):
                client, header = self.request()
                self.assertIn(b'200 Connection Established', header)
                with context.wrap_socket(client, server_hostname='registry.npmjs.org') as connection:
                    connection.sendall(b'GET /test/-/test-1.0.0.tgz HTTP/1.1\r\n'
                                       b'Host: registry.npmjs.org\r\n\r\n')
                    output = b''.join(iter(lambda: connection.recv(4096), b''))
                    self.assertEqual(output, response)
            connect.assert_called_once()

    def test_disallowed_tunnel_is_forbidden(self):
        with patch('host_egress.connect',side_effect=EgressDenied('not approved')):
            threading.Thread(target=self.relay.run,daemon=True).start()
            client,header=self.request()
            client.close()
            self.assertIn(b'403 Forbidden',header)
