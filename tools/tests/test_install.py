import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / 'install.sh'


class BootstrapTests(unittest.TestCase):
    def shell(self, args, script=None):
        return subprocess.run(['/bin/sh', '-s', '--', *args], input=script or SCRIPT.read_bytes(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

    def test_streamed_help_and_invalid_options(self):
        self.assertEqual(self.shell(['--help']).returncode, 0)
        for args in (['--bundle', '/tmp/b', '--version', 'v1'],
                     ['--version', 'v1', '--version', 'v2'],
                     ['--role', 'backup', '--role', 'primary'],
                     ['--version', '../bad']):
            self.assertEqual(self.shell(args).returncode, 2, args)

    def test_missing_controlling_terminal_and_truncated_pipe(self):
        result = self.shell(['--role', 'backup'])
        self.assertEqual(result.returncode, 3)
        self.assertIn(b'controlling terminal', result.stderr)
        script = SCRIPT.read_bytes()
        result = self.shell([], script[:len(script) // 2])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'controlling terminal', result.stderr)

    def download(self, publication, signed_tag, qualification='candidate', requested=None, payload=b'payload', symlink=False):
        source = SCRIPT.read_text().split("import hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request\n", 1)[1].split('\nPY\n)', 1)[0]
        source = 'import hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request\n' + source
        signed_payload = b'payload'
        manifest = {'schema_version': 1, 'purpose': 'pico2-kes-agent-distribution-v1',
                    'qualification': qualification,
                    'release': {'tag': signed_tag, 'version': signed_tag, 'channel': 'stable'},
                    'artifacts': [{'path': 'bin/p2kesup', 'size_bytes': len(signed_payload),
                                   'sha256': hashlib.sha256(signed_payload).hexdigest(), 'mode': 493}]}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            member = tarfile.TarInfo('bin/p2kesup')
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                tar.addfile(member)
            else:
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
        names = ('distribution.json', 'distribution.json.asc', 'release-authority.asc', 'distribution.tar')
        base = 'https://github.com/AndrewWestberg/pico2-kes-agent/releases/download/' + publication + '/'
        release = {'tag_name': publication, 'draft': False, 'prerelease': qualification == 'candidate',
                   'assets': [{'name': n, 'browser_download_url': base + n} for n in names]}
        responses = {base + 'distribution.json': json.dumps(manifest).encode(),
                     base + 'distribution.json.asc': b'signature', base + 'release-authority.asc': b'key',
                     base + 'distribution.tar': archive.getvalue()}
        responses['https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/' +
                  ('tags/' + requested if requested else 'latest')] = json.dumps(release).encode()

        class Opener:
            def open(self, request, timeout):
                return io.BytesIO(responses[request.full_url])

        def command(args, **kwargs):
            if args[0].endswith('gpgv'):
                return b'[GNUPG:] VALIDSIG 78C0F32094CD02A4BAFA444C684E37A210480F82 0 0 0 0 0 0 0 0 9FF957E79B5D853544805F4725491F18087931B6\n'
            return b''

        with tempfile.TemporaryDirectory() as tmp, patch('urllib.request.build_opener', return_value=Opener()), \
                patch.object(sys, 'argv', ['download', tmp, requested or '']):
            exec(source, {'bounded_command': command})

    def test_explicit_release_identity_and_tampered_archive(self):
        self.download('v1-rc1', 'v1-rc1', requested='v1-rc1')
        self.download('qualified-v1', 'v1', qualification='qualified')
        with self.assertRaises(ValueError):
            self.download('v1-rc1', 'v2-rc1', requested='v1-rc1')
        with self.assertRaises(ValueError):
            self.download('v1-rc1', 'v1-rc1', requested='v1-rc1', payload=b'tamper!')
        with self.assertRaises(ValueError):
            self.download('v1-rc1', 'v1-rc1', requested='v1-rc1', symlink=True)
        with self.assertRaises(ValueError):
            self.download('v1-rc1', 'v1-rc1')


if __name__ == '__main__':
    unittest.main()
