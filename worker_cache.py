"""Host-owned immutable archives, with one shared disk budget."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import time
from uuid import uuid4

CAPACITY = 5_000_000_000
INDEX_RESERVE = 8 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
FREE_RESERVE = 4 * 1024**3
HEX = re.compile(r'[0-9a-f]{64}')


class CacheFull(Exception):
    pass


class WorkerCache:
    def __init__(self, root, capacity=CAPACITY, free_reserve=FREE_RESERVE):
        self.root = Path(root)
        self.capacity = capacity - INDEX_RESERVE if capacity == CAPACITY else capacity
        self.block_size = 4096 if capacity == CAPACITY else 1
        self.free_reserve = free_reserve
        self.lock = threading.RLock()
        self.pins = {}
        self.invalid = set()
        self.pending = 0
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_uid != os.getuid() or self.root.stat().st_mode & 0o077:
            raise ValueError('Cache directory must be private to the controller')
        self.db = sqlite3.connect(self.root / 'index.sqlite3', check_same_thread=False)
        self.db.execute('PRAGMA max_page_count = 1024')
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, size INTEGER NOT NULL,
                digest TEXT NOT NULL, used INTEGER NOT NULL, resume TEXT, device TEXT,
                base TEXT, expires INTEGER, UNIQUE(kind,key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS resume_lookup ON entries(resume);
            CREATE TABLE IF NOT EXISTS consumers (
                entry TEXT NOT NULL, project TEXT NOT NULL, PRIMARY KEY(entry,project),
                FOREIGN KEY(entry) REFERENCES entries(id) ON DELETE CASCADE
            );
            PRAGMA foreign_keys = ON;
        """)
        if not any(row[1] == 'expires' for row in self.db.execute('PRAGMA table_info(entries)')):
            self.db.execute('ALTER TABLE entries ADD COLUMN expires INTEGER')
        with self.db:
            for (entry,) in self.db.execute('SELECT id FROM entries').fetchall():
                if not (self.root / entry).is_file():
                    self.db.execute('DELETE FROM entries WHERE id=?', (entry,))
        live = {row[0] for row in self.db.execute('SELECT id FROM entries')}
        for item in self.root.iterdir():
            if HEX.fullmatch(item.name) and item.name not in live:
                item.unlink()
        self.trim()

    def _allocation(self, size):
        return ((size + self.block_size - 1) // self.block_size) * self.block_size

    def _evict(self, needed, project=None):
        used = self.db.execute('SELECT coalesce(sum(((size+?-1)/?)*?),0) FROM entries',
                               (self.block_size,) * 3).fetchone()[0]
        free = shutil.disk_usage(self.root).free
        shortage = max(used + self.pending + needed - self.capacity,
                       self.free_reserve + needed + self.pending - free, 0)
        if not shortage:
            return
        victims = []
        for entry, size in self.db.execute("""
            SELECT id,((size+?-1)/?)*? FROM entries
            WHERE NOT (? IS NOT NULL AND (
                (kind='binary' AND key=?) OR
                EXISTS (SELECT 1 FROM consumers WHERE entry=id AND project=?)
            ))
            ORDER BY kind='dependency', used, id
        """, (self.block_size, self.block_size, self.block_size, project, project, project)):
            if entry in self.pins:
                continue
            victims.append(entry)
            shortage -= size
            if shortage <= 0:
                break
        if shortage > 0:
            raise CacheFull()
        for entry in victims:
            with self.db:
                self.db.execute('DELETE FROM entries WHERE id=?', (entry,))
            (self.root / entry).unlink(missing_ok=True)

    def trim(self):
        with self.lock:
            try:
                self._evict(0)
            except CacheFull:
                pass

    @contextmanager
    def stage(self, maximum, project=None, *, incremental=False):
        """Reserve bytes before writing. An interrupted write has no index entry."""
        if not 0 < maximum <= min(MAX_ARCHIVE, self.capacity):
            raise CacheFull()
        reserved = 0 if incremental else self._allocation(maximum)
        with self.lock:
            self._evict(reserved, project)
            self.pending += reserved
        entry = uuid4().hex + uuid4().hex
        path = self.root / entry
        try:
            with path.open('xb') as file:
                if not incremental:
                    yield entry, file
                else:
                    def write(data):
                        nonlocal reserved
                        required = file.tell() + len(data)
                        if required > maximum:
                            raise CacheFull()
                        if required > reserved:
                            target = min(maximum, ((required + 1048575) // 1048576) * 1048576)
                            increase = self._allocation(target) - reserved
                            with self.lock:
                                self._evict(increase, project)
                                self.pending += increase
                                reserved += increase
                        return file.write(data)

                    yield entry, IncrementalWriter(file, write)
        finally:
            with self.lock:
                self.pending -= reserved
                if not self.db.execute('SELECT 1 FROM entries WHERE id=?', (entry,)).fetchone():
                    path.unlink(missing_ok=True)

    def publish(self, entry, kind, key, digest, *, project=None, resume=None, device=None, base=None, expires=None):
        path = self.root / entry
        size = path.stat().st_size
        with self.lock:
            old = self.db.execute('SELECT id FROM entries WHERE kind=? AND key=?', (kind, key)).fetchone()
            if old and (kind == 'dependency' or old[0] in self.pins):
                if kind == 'dependency':
                    self._touch(old[0], project)
                return False
            with self.db:
                if old:
                    self.db.execute('DELETE FROM entries WHERE id=?', old)
                self.db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?)',
                                (entry, kind, key, size, digest, time.time_ns(), resume, device, base, expires))
                if kind == 'dependency' and project:
                    self.db.execute('INSERT INTO consumers VALUES (?,?)', (entry, project))
            if old:
                (self.root / old[0]).unlink(missing_ok=True)
            return True

    def _touch(self, entry, project):
        with self.db:
            self.db.execute('UPDATE entries SET used=? WHERE id=?', (time.time_ns(), entry))
            if project:
                self.db.execute('INSERT OR IGNORE INTO consumers VALUES (?,?)', (entry, project))

    def lookup_resume(self, resume_id, project):
        with self.lock:
            return self.db.execute(
                "SELECT device,base FROM entries WHERE kind='binary' AND resume=? AND key=?",
                (resume_id, project)).fetchone()

    @contextmanager
    def read(self, kind, key, *, project=None):
        """Keep an archive pinned through transfer and verify its stored digest."""
        column = 'key' if kind == 'dependency' else 'resume'
        with self.lock:
            item = self.db.execute(f'SELECT id,size,digest,key,device,base,expires FROM entries WHERE kind=? AND {column}=?',
                                   (kind, key)).fetchone()
            if item and (item[0] in self.invalid or (kind == 'binary' and item[3] != project)):
                item = None
            if item:
                entry = item[0]
                self.pins[entry] = self.pins.get(entry, 0) + 1
        if not item:
            yield None
            return
        try:
            try:
                file = (self.root / entry).open('rb')
            except FileNotFoundError:
                with self.lock:
                    self.invalid.add(entry)
                yield None
                return
            with file as stream:
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
                if (stream.tell() != item[1] or digest.hexdigest() != item[2]
                        or (item[6] is not None and item[6] <= time.time())):
                    with self.lock:
                        self.invalid.add(entry)
                    yield None
                    return
                stream.seek(0)
                with self.lock:
                    self._touch(entry, project if kind == 'dependency' else None)
                yield stream, *item[1:6]
        finally:
            with self.lock:
                self.pins[entry] -= 1
                if not self.pins[entry]:
                    del self.pins[entry]
                    if entry in self.invalid:
                        with self.db:
                            self.db.execute('DELETE FROM entries WHERE id=?', (entry,))
                        (self.root / entry).unlink(missing_ok=True)
                        self.invalid.remove(entry)


class IncrementalWriter:
    def __init__(self, file, write):
        self.file = file
        self.write = write

    def __getattr__(self, attribute):
        return getattr(self.file, attribute)
