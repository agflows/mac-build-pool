"""Bounded local process and Unix-socket transport for the VM controller."""
import json
import os
import selectors
import signal
import socket
import subprocess
import time

LIMIT = 96 * 1024 * 1024
INPUT_REQUEST_LIMIT = 128 * 1024
INPUT_RESULT_LIMIT = 2 * 1024 * 1024


class InputPipe:
    """One controller-owned, ordered stdio channel to a lease guest."""

    def __init__(self, argv, env):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env, cwd='/private/tmp',
                                        start_new_session=True, close_fds=True)
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)

    def exchange(self, request, timeout):
        payload = json.dumps(request, separators=(',', ':')).encode() + b'\n'
        if len(payload) > INPUT_REQUEST_LIMIT:
            raise ValueError('simulator request exceeds transfer cap')
        pending = memoryview(payload)
        reply = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while (remaining := deadline - time.monotonic()) > 0:
                for key, event in selector.select(min(remaining, 0.25)):
                    if event == selectors.EVENT_WRITE:
                        pending = pending[os.write(key.fd, pending):]
                        if not pending:
                            selector.unregister(key.fileobj)
                        continue
                    chunk = os.read(key.fd, min(65536, INPUT_RESULT_LIMIT + 1 - len(reply)))
                    if not chunk:
                        raise EOFError('simulator channel closed')
                    reply.extend(chunk)
                    if len(reply) > INPUT_RESULT_LIMIT:
                        raise ValueError('simulator reply exceeds transfer cap')
                    if b'\n' in chunk:
                        if pending or not reply.endswith(b'\n') or b'\n' in reply[:-1]:
                            raise ValueError('unexpected simulator reply framing')
                        result = json.loads(reply)
                        if not isinstance(result, dict) or result.get('job_id') != request['job_id']:
                            raise ValueError('unexpected simulator reply')
                        return result
        raise TimeoutError('simulator channel timed out')

    def close(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()


def communicate(argv, payload, *, env, timeout, cap=64 * 1024 * 1024, sink=None):
    streamed = hasattr(payload, 'read')
    if not streamed and len(payload) > LIMIT:
        raise ValueError('VM request exceeds transfer cap')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, cwd='/private/tmp', start_new_session=True, close_fds=True)
    output, error, offset, written = bytearray(), bytearray(), 0, 0
    chunk_in = b""
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
                    if not chunk_in:
                        if streamed:
                            chunk_in = payload.read(65536)
                        else:
                            chunk_in = payload[offset:offset+65536]
                            offset += len(chunk_in)
                    if chunk_in:
                        try:
                            count = os.write(stream.fileno(), chunk_in)
                            chunk_in = chunk_in[count:]
                        except BrokenPipeError:
                            selector.unregister(stream)
                            stream.close()
                    else:
                        selector.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if key.data == 'out':
                        written += len(chunk)
                        if written > cap:
                            raise ValueError('VM output exceeds transfer cap')
                        if sink is None:
                            output.extend(chunk)
                        else:
                            sink.write(chunk)
                    else:
                        error.extend(chunk)
                        if len(error) > 1024 * 1024:
                            raise ValueError('VM error output exceeds transfer cap')
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
