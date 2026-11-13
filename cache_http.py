"""Cache only complete anonymous package downloads from fixed registry paths."""
from contextlib import ExitStack, contextmanager
import hashlib
import re
import sqlite3
import time

from http_policy import REACT_NATIVE_ARTIFACT_PATH
from worker_cache import CacheFull, MAX_ARCHIVE

NPM_ARCHIVE = re.compile(r'/(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/-/[a-z0-9_.+-]+\.tgz')
PUB_ARCHIVE = re.compile(r'/api/archives/[a-zA-Z0-9_.+-]+\.tar\.gz')
EXCLUDED = {'authorization', 'cookie', 'range', 'if-match', 'if-none-match',
            'if-modified-since', 'if-unmodified-since', 'if-range', 'upgrade', 'cache-control', 'pragma'}


def cache_key(host, request):
    lines = request.decode('latin1').split('\r\n')
    parts = lines[0].split(' ')
    if len(parts) != 3 or parts[0] != 'GET' or any(
        line.partition(':')[0].lower() in EXCLUDED for line in lines[1:]
    ):
        return None
    path = parts[1]
    if ((host in {'registry.npmjs.org', 'registry.npmjs.com'} and NPM_ARCHIVE.fullmatch(path))
        or (host == 'pub.dev' and PUB_ARCHIVE.fullmatch(path))
        or (host == 'repo.reactnative.dev' and REACT_NATIVE_ARTIFACT_PATH.fullmatch(path)
            and path.endswith('.tar.gz'))):
        return f'{host}{path}'
    return None


@contextmanager
def capture(cache, key, header, project):
    lines = header.decode('latin1').split('\r\n')
    pairs = [line.partition(':') for line in lines[1:] if line]
    headers = [(name.lower(), value.strip()) for name, sep, value in pairs if sep]
    lengths = [value for name, value in headers if name == 'content-length']
    restricted = any(
        name in {'transfer-encoding', 'set-cookie', 'content-range'}
        or (name == 'vary' and value.lower() != 'accept-encoding')
        or (name == 'content-encoding' and value.lower() != 'identity')
        or (name == 'cache-control' and any(word in value.lower() for word in ('private', 'no-store', 'no-cache')))
        for name, value in headers
    )
    if (not re.match(r'^HTTP/1\.[01] 200(?: |$)', lines[0]) or restricted
            or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0])):
        yield None
        return
    control = ','.join(value.lower() for name, value in headers if name == 'cache-control')
    max_age = re.search(r'(?:^|,)\s*max-age=(\d{1,10})(?:,|$)', control)
    if not max_age:
        yield None
        return
    age = next((value for name, value in headers if name == 'age'), '0')
    if not re.fullmatch(r'[0-9]{1,10}', age):
        yield None
        return
    lifetime = min(int(max_age[1]) - int(age), 30 * 24 * 3600)
    if lifetime <= 0:
        yield None
        return
    expires = int(time.time()) + lifetime
    length = int(lengths[0])
    if not 0 < length <= MAX_ARCHIVE:
        yield None
        return

    with ExitStack() as stack:
        try:
            entry, stream = stack.enter_context(cache.stage(length + len(header)))
        except (CacheFull, OSError, sqlite3.Error):
            yield None
            return
        digest = hashlib.sha256()
        remaining = length
        try:
            stream.write(header)
        except OSError:
            yield None
            return
        digest.update(header)

        def append(data):
            nonlocal remaining
            remaining -= len(data)
            if remaining >= 0:
                try:
                    stream.write(data)
                    digest.update(data)
                except OSError:
                    remaining = -1

        yield append
        if remaining == 0:
            try:
                stream.flush()
                cache.publish(entry, 'dependency', key, digest.hexdigest(), project=project, expires=expires)
            except (OSError, sqlite3.Error):
                pass
