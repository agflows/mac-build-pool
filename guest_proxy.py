"""Guest-only CONNECT proxy. Its only uplink is a bounded JSON pipe to the host.

Ethernet is disconnected externally. No hostname/address from a project is used
by the host without egress_policy validation. This file runs in the guest only.
"""
import base64
import json
import socket
import sys
import threading
import ssl
import os
import argparse
from pathlib import Path
import queue

connections = {}
lock = threading.RLock()
output_lock = threading.Lock()
next_id = 0
MAX_LINE = 65536
tls_context = None


def send(message):
    with output_lock:
        sys.stdout.write(json.dumps(message, separators=(',', ':')) + '\n')
        sys.stdout.flush()


def close(cid):
    with lock:
        value = connections.pop(cid, None)
    if value:
        value['ready'].set()
        try:
            value['socket'].shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        value['socket'].close()


def client(connection):
    global next_id
    cid = None
    try:
        connection.settimeout(30)
        header = bytearray()
        while b'\r\n\r\n' not in header:
            part = connection.recv(1)
            if not part or len(header) >= 16384:
                raise ValueError('invalid CONNECT')
            header.extend(part)
        first = header.decode('ascii').split('\r\n', 1)[0].split()
        if len(first) != 3 or first[0] != 'CONNECT' or first[2] not in ('HTTP/1.0', 'HTTP/1.1'):
            raise ValueError('only TLS CONNECT is supported')
        host, port = first[1].rsplit(':', 1)
        with lock:
            if len(connections) >= 16:
                raise ValueError('connection limit')
            next_id += 1
            cid = next_id
            value = {'socket': connection, 'ready': threading.Event(), 'approved': False,
                     'incoming':queue.Queue(maxsize=64),'closing':False}
            connections[cid] = value
        send({'op': 'open', 'id': cid, 'host': host, 'port': int(port)})
        if not value['ready'].wait(25) or not value['approved']:
            connection.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
            return
        connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        connection=tls_context.wrap_socket(connection,server_side=True)
        value['socket']=connection
        while True:
            while not value['incoming'].empty():
                connection.settimeout(30)
                connection.sendall(value['incoming'].get_nowait())
            if value['closing']:
                break
            connection.settimeout(0.05)
            try:
                data = connection.recv(32768)
            except socket.timeout:
                continue
            if not data:
                break
            send({'op': 'data', 'id': cid, 'data': base64.b64encode(data).decode()})
    except (ValueError, OSError):
        pass
    finally:
        if cid is not None:
            send({'op': 'close', 'id': cid})
            close(cid)
        else:
            connection.close()


def reader():
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_LINE + 1)
            if not line or len(line) > MAX_LINE:
                return
            message = json.loads(line)
            with lock:
                value = connections.get(message.get('id'))
            if not value:
                continue
            if message['op'] == 'opened':
                value['approved'] = True
                value['ready'].set()
            elif message['op'] == 'data':
                data = base64.b64decode(message['data'], validate=True)
                try:
                    value['incoming'].put(data, timeout=5)
                except queue.Full:
                    # A stalled client must not tear down unrelated downloads.
                    send({'op':'close','id':message['id']})
                    close(message['id'])
            elif message['op'] == 'close':
                if not value['ready'].is_set():
                    # Let the waiting CONNECT handler send its 403 response
                    # before closing the client socket.
                    value['ready'].set()
                else:
                    value['closing']=True
    finally:
        with lock:
            ids = list(connections)
        for cid in ids:
            close(cid)
        # Losing the controlled uplink must close every guest connection.
        import os
        os._exit(0)


def main():
    global tls_context
    parser=argparse.ArgumentParser()
    parser.add_argument('--tls-dir',type=Path,default=Path('/Library/ios-worker'))
    args=parser.parse_args()
    tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version=ssl.TLSVersion.TLSv1_2
    tls_context.set_alpn_protocols(['http/1.1'])
    tls_context.load_cert_chain(str(args.tls_dir/'proxy-leaf.pem'),str(args.tls_dir/'proxy-leaf.key'))
    if os.geteuid()==0:
        import pwd
        account=pwd.getpwnam('iosagent')
        os.initgroups(account.pw_name,account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    threading.Thread(target=reader, daemon=True).start()
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 18741))
    server.listen(16)
    while True:
        connection, _ = server.accept()
        threading.Thread(target=client, args=(connection,), daemon=True).start()


if __name__ == '__main__':
    main()
