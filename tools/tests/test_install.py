from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / 'install.sh'


class BootstrapTests(unittest.TestCase):
    def test_valid_posix_shell_syntax(self):
        result = subprocess.run(['/bin/sh', '-n', str(SCRIPT)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_runs_extracted_updater_with_default_and_explicit_bundle_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / 'extracted bundle'
            updater = bundle / 'bin' / 'p2kesup'
            updater.parent.mkdir(parents=True)
            updater.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@" > "$RECORD"\n')
            updater.chmod(0o755)
            sudo = root / 'sudo'
            sudo.write_text('#!/bin/sh\n[ "$1" = "--" ] || exit 42\nshift\nexec "$@"\n')
            sudo.chmod(0o755)
            record = root / 'arguments'
            for args, cwd, expected in (([], bundle, '.'),
                                        ([str(bundle)], root, str(bundle))):
                with self.subTest(args=args):
                    result = subprocess.run(
                        ['/bin/sh', str(SCRIPT), *args], cwd=cwd,
                        env={'PATH': str(root), 'RECORD': str(record)},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(record.read_text().splitlines(), [
                        f'{expected}/bin/p2kesup', 'install', '--bundle', expected,
                    ])

    def test_missing_extracted_updater_never_invokes_sudo(self):
        with tempfile.TemporaryDirectory() as temporary:
            sudo = Path(temporary) / 'sudo'
            sudo.write_text('#!/bin/sh\nexit 42\n')
            sudo.chmod(0o755)
            result = subprocess.run(
                ['/bin/sh', str(SCRIPT), temporary], env={'PATH': temporary},
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn('authenticated, extracted release bundle', result.stderr)


if __name__ == '__main__':
    unittest.main()
