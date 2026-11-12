"""Bounded local process and Unix-socket transport for the VM controller."""
import json
import os
import selectors
import signal
import socket
import subprocess
import time

LIMIT = 96 * 1024 * 1024


def communicate(argv, payload, *, env, timeout, cap=64 * 1024 * 1024):
    if len(payload) > LIMIT:
        raise ValueError('VM request exceeds transfer cap')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, cwd='/private/tmp', start_new_session=True, close_fds=True)
    output, error, offset = bytearray(), bytearray(), 0
    selector = selectors.DefaultSelector()
    for stream, event, label in ((process.stdin, selectors.EVENT_WRITE, 'in'),
                                 (process.stdout, selectors.EVENT_READ, 'out'),
                                 (process.stderr, selectors.EVENT_READ, 'err')):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, event, label)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError('VM operation timed out')
            for key, event in selector.select(timeout=min(0.25, max(0, deadline-time.monotonic()))):
                stream = key.fileobj
                if key.data == 'in':
                    if offset < len(payload):
                        try:
                            offset += os.write(stream.fileno(), payload[offset:offset+65536])
                        except BrokenPipeError:
                            offset = len(payload)
                    if offset == len(payload):
                        selector.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    sink = output if key.data == 'out' else error
                    sink.extend(chunk)
                    if len(sink) > (cap if key.data == 'out' else 1024*1024):
                        raise ValueError('VM output exceeds transfer cap')
        return process.wait(timeout=max(1, deadline-time.monotonic())), bytes(output), bytes(error)
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def read_frame(connection):
    output = bytearray()
    while len(output) <= LIMIT:
        data = connection.recv(min(65536, LIMIT + 1 - len(output)))
        if not data:
            raise ValueError('controller disconnected before result')
        output.extend(data)
        if b'\n' in data:
            if not output.endswith(b'\n') or b'\n' in output[:-1]:
                raise ValueError('unexpected controller frames')
            value = json.loads(output)
            if not isinstance(value, dict):
                raise ValueError('invalid controller result')
            return value
    raise ValueError('controller frame exceeds cap')


def rpc(path, request, timeout=30):
    data = json.dumps(request, separators=(',', ':')).encode() + b'\n'
    if len(data) > LIMIT:
        raise ValueError('controller request exceeds cap')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(data)
        return read_frame(connection)
