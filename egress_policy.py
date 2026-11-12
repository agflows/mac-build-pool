"""Host-side destination policy for a guest with a disconnected Ethernet NIC."""
from __future__ import annotations

import ipaddress
import socket
import subprocess
import ssl

# Exact package-distribution hosts. No wildcards, client URLs, proxies or ports.
PACKAGE_HOSTS = frozenset({
    'registry.npmjs.org', 'registry.npmjs.com', 'bun.sh', 'nodejs.org',
    'github.com', 'raw.githubusercontent.com', 'codeload.github.com',
    'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
    'rubygems.org', 'index.rubygems.org', 'rubygems.global.ssl.fastly.net',
    'cdn.cocoapods.org', 'trunk.cocoapods.org', 'storage.googleapis.com',
    'repo.maven.apache.org', 'repo1.maven.org', 'dl.google.com',
    'pub.dev', 'cdn.jsdelivr.net', 'repo.reactnative.dev',
})


class EgressDenied(ValueError):
    pass


def destination(host, port, *, allowed=PACKAGE_HOSTS, host_addresses=(), forbidden_networks=(), resolver=socket.getaddrinfo):
    if (not isinstance(host, str) or host != host.lower() or host not in allowed
            or type(port) is not int or port != 443):
        raise EgressDenied('destination is not approved')
    forbidden = {ipaddress.ip_address(a.split('%')[0]) for a in host_addresses}
    answers = resolver(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    approved = []
    for family, kind, proto, canon, address in answers:
        ip = ipaddress.ip_address(address[0].split('%')[0])
        if (family != socket.AF_INET or not ip.is_global or ip in forbidden or ip.is_multicast or ip.is_unspecified
                or any(ip in network for network in forbidden_networks if network.version == ip.version)):
            raise EgressDenied('DNS resolved to a non-public or host address')
        approved.append((family, kind, proto, address))
    if not approved:
        raise EgressDenied('no approved destination addresses')
    return approved


def connect(host, port, *, allowed=PACKAGE_HOSTS, host_addresses=()):
    # Resolve/validate once, then connect to that exact numeric address. No
    # hostname lookup inside connect, redirect handling, or DNS rebinding gap.
    networks, current_addresses = local_networks()
    for family, kind, proto, address in destination(host, port, allowed=allowed,
            host_addresses=(*host_addresses, *current_addresses), forbidden_networks=networks):
        connection = socket.socket(family, kind, proto)
        connection.settimeout(20)
        try:
            connection.connect(address)
            context=ssl.create_default_context()
            context.set_alpn_protocols(['http/1.1'])
            connection=context.wrap_socket(connection,server_hostname=host)
            return connection
        except OSError:
            connection.close()
    raise EgressDenied('approved destination is unavailable')


def local_networks():
    """Refresh host/on-link addresses for every connection, including public LANs.

    IPv6 is not transported by this relay at all. Guest Ethernet drops both
    address families. Unknown interface state fails closed.
    """
    result = subprocess.run(['/sbin/ifconfig'], capture_output=True, text=True, check=True, timeout=5)
    networks, addresses = [], []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == 'inet' and 'netmask' in parts:
            address = ipaddress.ip_address(parts[1])
            addresses.append(str(address))
            mask = ipaddress.ip_address(int(parts[parts.index('netmask')+1], 16))
            networks.append(ipaddress.ip_network(str(address) + '/' + str(mask), strict=False))
    if not addresses:
        raise EgressDenied('host interface state is unavailable')
    routes = subprocess.run(['/usr/sbin/netstat','-rn','-f','inet'],capture_output=True,text=True,check=True,timeout=5)
    for line in routes.stdout.splitlines():
        parts=line.split()
        if len(parts)<4 or not parts[3].startswith('utun') or parts[0]=='default':
            continue
        value=parts[0]
        if not value[0].isdigit():
            continue
        address,separator,prefix=value.partition('/')
        octets=address.split('.')
        address='.'.join(octets+['0']*(4-len(octets)))
        networks.append(ipaddress.ip_network(address+'/'+(prefix if separator else str(len(octets)*8)),strict=False))
    return networks, addresses
