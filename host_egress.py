"""Host-enforced HTTP/TLS package relay. Guest Ethernet has no uplink."""
import base64
import json
import socket
import subprocess
import threading
import queue

from egress_policy import connect,EgressDenied,PACKAGE_HOSTS
from http_policy import HTTPGate

class Relay:
    def __init__(self,process,*,allowed=PACKAGE_HOSTS,host_addresses=()):
        self.process=process
        self.allowed=allowed
        self.host_addresses=host_addresses
        self.connections={}
        self.lock=threading.RLock()
        self.output_lock=threading.Lock()
        self.denied=[]
        self.closed=False

    def send(self,message):
        with self.output_lock:
            if self.closed:return
            self.process.stdin.write(json.dumps(message,separators=(',',':')).encode()+b'\n')
            self.process.stdin.flush()

    def close_connection(self,cid):
        with self.lock:state=self.connections.pop(cid,None)
        if state:
            state['ready'].set()
            try:state['socket'].shutdown(socket.SHUT_RDWR)
            except OSError:pass
            state['socket'].close()
        self.send({'op':'close','id':cid})

    def open(self,message):
        cid=message['id']
        try:
            connection=connect(message.get('host'),message.get('port'),allowed=self.allowed,host_addresses=self.host_addresses)
            state={'socket':connection,'ready':threading.Event(),'gate':HTTPGate(message['host']),
                   'request':bytearray(),'outbound':queue.Queue(maxsize=64)}
            with self.lock:
                if self.closed or cid not in self.connections:
                    connection.close();return
                self.connections[cid]=state
            self.send({'op':'opened','id':cid})
            if not state['ready'].wait(30):raise EgressDenied('request headers timed out')
            with self.lock:
                if self.connections.get(cid) is not state:return
            connection.sendall(state['request'])
            state['request'].clear()
            received=0
            while True:
                while not state['outbound'].empty():
                    connection.settimeout(20)
                    connection.sendall(state['outbound'].get_nowait())
                connection.settimeout(0.05)
                try:
                    data=connection.recv(32768)
                except socket.timeout:
                    continue
                if not data:break
                received+=len(data)
                if received>512*1024*1024:raise EgressDenied('connection byte limit')
                state['gate'].response(data)
                self.send({'op':'data','id':cid,'data':base64.b64encode(data).decode()})
        except (ValueError,OSError):
            with self.lock:
                self.denied.append(str(message.get('host'))[:253]);self.denied[:]=self.denied[-100:]
        finally:self.close_connection(cid)

    def run(self):
        try:
            while not self.closed:
                line=self.process.stdout.readline(65537)
                if not line:return
                if len(line)>65536:raise EgressDenied('oversize relay frame')
                message=json.loads(line)
                if not isinstance(message,dict) or type(message.get('id')) is not int or not 0<message['id']<2**53:
                    raise EgressDenied('invalid relay frame')
                cid,op=message['id'],message.get('op')
                if op=='open':
                    if set(message)!={'op','id','host','port'}:raise EgressDenied('invalid open frame')
                    with self.lock:
                        if cid in self.connections or len(self.connections)>=16:raise EgressDenied('connection cap or duplicate id')
                        self.connections[cid]=None
                    threading.Thread(target=self.open,args=(message,),daemon=True).start()
                elif op=='data':
                    if set(message)!={'op','id','data'}:raise EgressDenied('invalid data frame')
                    data=base64.b64decode(message['data'],validate=True)
                    if len(data)>32768:raise EgressDenied('oversize data frame')
                    with self.lock:state=self.connections.get(cid)
                    if not state:raise EgressDenied('connection is not ready')
                    try:
                        forwarded=state['gate'].feed(data)
                        if forwarded:
                            if state['gate'].upgraded:
                                state['outbound'].put_nowait(forwarded)
                            else:
                                state['request'].extend(forwarded)
                                if state['gate'].remaining==0:state['ready'].set()
                    except (ValueError,OSError,queue.Full):
                        self.send({'op':'data','id':cid,'data':base64.b64encode(
                            b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n').decode()})
                        self.close_connection(cid)
                elif op=='close':self.close_connection(cid)
                else:raise EgressDenied('unsupported relay operation')
        finally:self.close()

    def close(self):
        with self.lock:
            if self.closed:return
            self.closed=True
            states,self.connections=self.connections,{}
        for state in states.values():
            if state:
                state['ready'].set()
                try:state['socket'].shutdown(socket.SHUT_RDWR)
                except OSError:pass
                state['socket'].close()
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=10)
        for stream in (self.process.stdin,self.process.stdout):
            if stream is not None and not stream.closed:stream.close()
