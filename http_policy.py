"""One canonical HTTP/1.1 request per approved TLS connection.

The host validates decrypted requests, preventing domain fronting, absolute-URL
proxying and request smuggling by an untrusted guest. WebSocket upgrade is only
allowed for explicitly approved app backends, never package hosts.
"""
import re
from egress_policy import EgressDenied, PACKAGE_HOSTS

COCOAPODS_SPEC_PATH = re.compile(
    r'/cocoa/Specs/[0-9a-f]/[0-9a-f]/[0-9a-f]/'
    r'[A-Za-z0-9][A-Za-z0-9_.+-]*/[0-9][A-Za-z0-9_.+-]*/'
    r'[A-Za-z0-9][A-Za-z0-9_.+-]*\.podspec\.json'
)
REACT_NATIVE_ARTIFACT_PATH = re.compile(
    r'/maven2/com/facebook/'
    r'(?:react/react-native-artifacts/(?P<rn>\d+\.\d+\.\d+(?:-rc\.\d+)?)/'
    r'react-native-artifacts-(?P=rn)-reactnative-(?:core-(?:dSYM-)?|dependencies-)'
    r'|hermes/hermes-ios/(?P<hermes>\d+\.\d+\.\d+(?:-rc\.\d+)?)/'
    r'hermes-ios-(?P=hermes)-hermes-ios-)'
    r'(?:debug|release)\.tar\.gz(?:\.sha1)?'
)
PACKAGE_PATH_SCOPES = {
    'cdn.jsdelivr.net': COCOAPODS_SPEC_PATH,
    'repo.reactnative.dev': REACT_NATIVE_ARTIFACT_PATH,
}

class HTTPGate:
    def __init__(self,host):
        self.host=host
        self.header=bytearray()
        self.remaining=None
        self.want_websocket=False
        self.upgraded=False
        self.response_header=bytearray()

    def feed(self,data):
        if self.upgraded:
            return data
        if self.remaining is not None:
            if len(data)>self.remaining:
                raise EgressDenied('pipelined or excess request data')
            self.remaining-=len(data)
            return data
        self.header.extend(data)
        boundary=self.header.find(b'\r\n\r\n')
        if boundary<0:
            if len(self.header)>32768:raise EgressDenied('request headers exceed cap')
            return b''
        if boundary>32768:raise EgressDenied('request headers exceed cap')
        raw,body=bytes(self.header[:boundary]),bytes(self.header[boundary+4:])
        self.header.clear()
        lines=raw.decode('latin1').split('\r\n')
        first=lines.pop(0).split(' ')
        if (len(first)!=3 or first[2]!='HTTP/1.1' or not first[1].startswith('/')
                or first[1].startswith('//') or any(ord(c)<33 for c in first[1])):
            raise EgressDenied('invalid origin request target')
        method=first[0]
        if method not in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}:
            raise EgressDenied('HTTP method is not allowed')
        fields=[]
        for line in lines:
            key,sep,value=line.partition(':')
            if (not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key)
                    or any(ord(c)<32 and c!='\t' for c in value)):
                raise EgressDenied('invalid HTTP header')
            fields.append((key.lower(),value.strip(),key))
        hosts=[value.lower() for key,value,original in fields if key=='host']
        if len(hosts)!=1 or hosts[0] not in (self.host,self.host+':443'):
            raise EgressDenied('HTTP host does not match approved destination')
        if any(key=='transfer-encoding' for key,value,original in fields):
            raise EgressDenied('streamed request bodies are not supported')
        if any(key=='expect' for key,value,original in fields):
            raise EgressDenied('expect-continue requests are not supported')
        lengths=[value for key,value,original in fields if key=='content-length']
        if len(lengths)>1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit())):
            raise EgressDenied('invalid Content-Length')
        self.remaining=int(lengths[0]) if lengths else 0
        if self.remaining>8*1024*1024 or len(body)>self.remaining:
            raise EgressDenied('request body exceeds cap or is pipelined')
        scope = PACKAGE_PATH_SCOPES.get(self.host)
        if scope and (
            method not in {'GET', 'HEAD'} or self.remaining or not scope.fullmatch(first[1])
        ):
            raise EgressDenied('request is outside the approved package download paths')
        if self.host in PACKAGE_HOSTS and method not in {'GET','HEAD'}:
            if not (self.host=='github.com' and method=='POST' and first[1].split('?',1)[0].endswith('/git-upload-pack')):
                raise EgressDenied('package hosts permit download requests only')
        upgrades=[value.lower() for key,value,original in fields if key=='upgrade']
        self.want_websocket=(upgrades==['websocket'] and self.host not in PACKAGE_HOSTS and method=='GET' and self.remaining==0)
        if upgrades and not self.want_websocket:raise EgressDenied('unsupported protocol upgrade')
        # A fresh TLS connection per request eliminates request-pipeline ambiguity.
        output=[f'{method} {first[1]} HTTP/1.1',f'Host: {self.host}',
                'Connection: Upgrade' if self.want_websocket else 'Connection: close']
        if self.want_websocket:output.append('Upgrade: websocket')
        excluded={'host','connection','proxy-connection','proxy-authorization','upgrade','te','trailer'}
        output.extend(f'{original}: {value}' for key,value,original in fields if key not in excluded)
        self.remaining-=len(body)
        return ('\r\n'.join(output)+'\r\n\r\n').encode('latin1')+body

    def response(self,data):
        if not self.want_websocket or self.upgraded:return
        self.response_header.extend(data)
        boundary=self.response_header.find(b'\r\n\r\n')
        if boundary>=0:
            self.upgraded=bytes(self.response_header).startswith(b'HTTP/1.1 101 ')
            self.response_header.clear()
            self.want_websocket=False
        elif len(self.response_header)>32768:
            raise EgressDenied('response headers exceed cap')
