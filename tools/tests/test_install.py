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

    def download(self, publication, signed_tag, qualification='candidate', requested=None, payload=b'payload', symlink=False, standalone_tamper=False):
        source = SCRIPT.read_text().split("import hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request\n", 1)[1].split('\nPY\n)', 1)[0]
        source = 'import hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request\n' + source
        signed_payload = b'payload'
        files = {'bin/p2kesup': signed_payload, 'distribution-authority.json': b'authority',
                 'distribution-authority.json.asc': b'pgp', 'firmware/release-authority.asc': b'key',
                 'install.sh': b'installer', 'install.sh.sig': b'installer signature'}
        manifest = {'schema_version': 1, 'purpose': 'pico2-kes-agent-distribution-v1',
                    'qualification': qualification,
                    'release': {'tag': signed_tag, 'version': signed_tag, 'channel': 'stable'},
                    'artifacts': [{'path': name, 'size_bytes': len(data),
                                   'sha256': hashlib.sha256(data).hexdigest(),
                                   'mode': 493 if name in ('bin/p2kesup', 'install.sh') else 420,
                                   'class': 'bootstrap'} for name, data in files.items()]}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                if name == 'bin/p2kesup' and symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    tar.addfile(member)
                else:
                    if name == 'bin/p2kesup': data = payload
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
        names = ('distribution.json', 'distribution.json.sig', 'distribution-authority.json',
                 'distribution-authority.json.asc', 'release-authority.asc', 'install.sh', 'install.sh.sig', 'distribution.tar')
        base = 'https://github.com/AndrewWestberg/pico2-kes-agent/releases/download/' + publication + '/'
        release = {'tag_name': publication, 'draft': False, 'prerelease': qualification == 'candidate',
                   'assets': [{'name': n, 'browser_download_url': base + n} for n in names]}
        responses = {base + 'distribution.json': json.dumps(manifest).encode(),
                     base + 'distribution.json.sig': b'signature',
                     base + 'distribution-authority.json': files['distribution-authority.json'],
                     base + 'distribution-authority.json.asc': files['distribution-authority.json.asc'],
                     base + 'release-authority.asc': files['firmware/release-authority.asc'],
                     base + 'install.sh': files['install.sh'], base + 'install.sh.sig': files['install.sh.sig'],
                     base + 'distribution.tar': archive.getvalue()}
        if standalone_tamper:
            responses[base + 'distribution-authority.json'] = b'other authority'
        responses['https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases/' +
                  ('tags/' + requested if requested else 'latest')] = json.dumps(release).encode()

        class Opener:
            def open(self, request, timeout):
                return io.BytesIO(responses[request.full_url])

        helper = SCRIPT.read_text().split("verifier_code=$(cat <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        namespace = {}
        exec(helper, namespace)
        namespace['authenticate_authority'] = lambda directory: None
        namespace['distribution_signature'] = lambda *args: None
        with tempfile.TemporaryDirectory() as tmp, patch('urllib.request.build_opener', return_value=Opener()), \
                patch.object(sys, 'argv', ['download', tmp, requested or '']):
            exec(source, namespace)

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
            self.download('v1-rc1', 'v1-rc1', requested='v1-rc1', standalone_tamper=True)
        with self.assertRaises(ValueError):
            self.download('v1-rc1', 'v1-rc1')

    def test_delegated_key_and_domain_separated_signatures(self):
        helper = SCRIPT.read_text().split("verifier_code=$(cat <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        ns = {}
        exec(helper, ns)
        real_command = ns['bounded_command']
        valid = b'[GNUPG:] VALIDSIG 78C0F32094CD02A4BAFA444C684E37A210480F82 0 0 0 0 0 0 0 0 9FF957E79B5D853544805F4725491F18087931B6\n'
        def command(args, **kwargs):
            if args[0] == '/usr/bin/gpg': return b''
            if args[0] == '/usr/bin/gpgv': return valid
            return real_command(args, **kwargs)
        ns['bounded_command'] = command
        with tempfile.TemporaryDirectory() as temporary:
            d = Path(temporary)
            private = d/'private.pem'
            public = d/'public.pem'
            subprocess.run(['/usr/bin/openssl', 'ecparam', '-name', 'secp256k1', '-genkey', '-noout', '-out', str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            statement = {'schema_version': 1, 'purpose': 'pico2-kes-agent-distribution-authority-v1',
                         'project': 'https://github.com/AndrewWestberg/pico2-kes-agent',
                         'algorithm': 'secp256k1', 'public_key_pem': public.read_text()}
            (d/'distribution-authority.json').write_text(json.dumps(statement))
            key = ns['authenticate_authority'](d)
            data = d/'distribution.json'
            data.write_bytes(b'{"release":1}')
            signed = d/'input'
            signed.write_bytes(b'pico2-kes-agent-distribution-v1\n' + data.read_bytes())
            subprocess.run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(private), '-out', str(d/'distribution.json.sig'), str(signed)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ns['distribution_signature'](d, key, 'distribution.json', 'pico2-kes-agent-distribution-v1')
            with self.assertRaises(subprocess.CalledProcessError):
                ns['distribution_signature'](d, key, 'distribution.json', 'pico2-kes-agent-bootstrap-v1')
            data.write_bytes(b'altered')
            with self.assertRaises(subprocess.CalledProcessError):
                ns['distribution_signature'](d, key, 'distribution.json', 'pico2-kes-agent-distribution-v1')
            statement['purpose'] = 'pico2-kes-agent-firmware-authority-v1'
            (d/'distribution-authority.json').write_text(json.dumps(statement))
            with self.assertRaises(ValueError):
                ns['authenticate_authority'](d)
            ns['bounded_command'] = lambda args, **kwargs: valid.replace(b'78C0F320', b'00000000') if args[0] == '/usr/bin/gpgv' else b''
            with self.assertRaises(ValueError):
                ns['authenticate_authority'](d)


if __name__ == '__main__':
    unittest.main()
