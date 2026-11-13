import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from cache_http import cache_key, capture
from guest_cache import archive_app, restore
from worker_cache import CacheFull, WorkerCache


class CacheTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'cache'
        self.cache = WorkerCache(self.root, capacity=30, free_reserve=0)
        self.addCleanup(self.cache.db.close)

    def put(self, kind, key, size, *, project=None, resume=None):
        data = b'x' * size
        with self.cache.stage(size, key if kind == 'binary' else None) as (entry, file):
            file.write(data)
            file.flush()
            return self.cache.publish(entry, kind, key, hashlib.sha256(data).hexdigest(),
                                      project=project, resume=resume, device='device', base='base')

    def test_binary_evicts_other_project_only(self):
        self.put('dependency', 'shared', 10, project='a')
        self.put('dependency', 'other', 10, project='b')
        self.put('binary', 'b', 10, resume='b1')
        with self.cache.read('dependency', 'shared', project='b'):
            pass
        self.put('binary', 'a', 16, resume='a1')
        with self.cache.read('dependency', 'other') as other:
            self.assertIsNone(other)
        with self.cache.read('binary', 'b1', project='b') as binary:
            self.assertIsNone(binary)
        with self.cache.read('dependency', 'shared') as shared:
            self.assertIsNotNone(shared)
        with self.assertRaises(CacheFull):
            self.put('binary', 'a', 12, resume='a2')
        with self.cache.read('binary', 'a1', project='a') as binary:
            self.assertEqual(binary[0].read(), b'x' * 16)

    def test_replace_previous_and_deny_another_project(self):
        self.put('binary', 'a', 12, resume='a1')
        self.put('binary', 'a', 15, resume='a2')
        with self.cache.read('binary', 'a1', project='a') as old:
            self.assertIsNone(old)
        with self.cache.read('binary', 'a2', project='b') as wrong:
            self.assertIsNone(wrong)
        with self.cache.read('binary', 'a2', project='a') as current:
            self.assertEqual(current[0].read(), b'x' * 15)

    def test_pins_and_lru(self):
        self.put('dependency', 'first', 10)
        self.put('dependency', 'second', 10)
        self.put('binary', 'a', 10, resume='a1')
        with self.cache.read('binary', 'a1', project='a'):
            self.put('dependency', 'third', 10)
            with self.cache.read('dependency', 'first') as first:
                self.assertIsNone(first)
        self.put('dependency', 'fourth', 10)
        with self.cache.read('binary', 'a1', project='a') as evicted:
            self.assertIsNone(evicted)

    def test_partial_responses_are_not_published(self):
        header = b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nCache-Control: public, max-age=60\r\n\r\n'
        cache = WorkerCache(self.root.parent / 'proxy', 1000, 0)
        self.addCleanup(cache.db.close)
        with capture(cache, 'key', header, 'a') as add:
            add(b'ab')
        with cache.read('dependency', 'key') as partial:
            self.assertIsNone(partial)
        with capture(cache, 'key', header, 'a') as add:
            add(b'abcde')
        with cache.read('dependency', 'key') as complete:
            self.assertEqual(complete[0].read(), header + b'abcde')

    def test_proxy_allowlist_and_credentials(self):
        request = b'GET /expo/-/expo-1.0.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\n'
        self.assertTrue(cache_key('registry.npmjs.org', request))
        self.assertIsNone(cache_key('registry.npmjs.org', request+b'Authorization: Bearer x\r\n'))
        self.assertIsNone(cache_key('registry.npmjs.org', request+b'Range: bytes=0-1\r\n'))
        self.assertIsNone(cache_key('app.example.com', request))

    def test_guest_bundle_archive_can_be_restored(self):
        root = self.root.parent.resolve()
        original = root / 'Original.app'
        original.mkdir()
        executable = original / 'Original'
        executable.write_bytes(b'executable')
        executable.chmod(0o755)
        (original / 'Alias').symlink_to('Original')
        data = io.BytesIO()
        archive_app(original, data)
        data.seek(0)
        restored = restore(data, root / 'restored')
        self.assertEqual((restored / 'Alias').readlink(), Path('Original'))
        self.assertEqual((restored / 'Original').read_bytes(), b'executable')
        self.assertEqual((restored / 'Original').stat().st_mode & 0o777, 0o700)

    def test_guest_rejects_escaping_archive_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                item = tarfile.TarInfo('Cached.app/../escape')
                archive.addfile(item, io.BytesIO())
            data.seek(0)
            with self.assertRaises(ValueError):
                restore(data, Path(temporary))
