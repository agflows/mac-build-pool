import json
import unittest
from pathlib import Path
import test_preparation as fixtures
from policy import PolicyError

class BunPreparationTest(unittest.TestCase):
    setUp = fixtures.PreparationTest.setUp
    prepare = fixtures.PreparationTest.prepare
    def test_bun_uses_frozen_lockfile_without_npm(self):
        (self.revision / 'package-lock.json').unlink()
        (self.revision / 'bun.lock').write_text('{}')
        self.tools['bun'] = Path('/approved/bun/bin/bun')
        self.tools.pop('npm_cli')
        self.prepare()
        self.assertEqual(self.commands.calls[0][0], ['/approved/bun/bin/bun','install','--frozen-lockfile'])
        self.assertEqual(json.loads((self.revision / '.worker/prepared.json').read_text())['recipe'],'expo-ios')

    def test_bun_requires_an_owner_toolchain(self):
        (self.revision / 'package-lock.json').unlink()
        (self.revision / 'bun.lock').write_text('{}')
        with self.assertRaises(PolicyError):
            self.prepare()
        self.assertEqual(self.commands.calls,[])

    def test_ambiguous_lockfiles_do_not_execute(self):
        (self.revision / 'bun.lock').write_text('{}')
        self.tools['bun'] = Path('/approved/bun/bin/bun')
        with self.assertRaises(PolicyError):
            self.prepare()
        self.assertEqual(self.commands.calls,[])
