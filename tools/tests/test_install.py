from pathlib import Path
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / 'install.sh'


class BootstrapTests(unittest.TestCase):
    def test_valid_posix_shell_syntax(self):
        result = subprocess.run(['/bin/sh', '-n', str(SCRIPT)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_slim_bootstrap_contract(self):
        text = SCRIPT.read_text()
        self.assertIn('apt-get --simulate install', text)
        self.assertIn('gpgv --keyring', text)
        self.assertIn('p2kesup', text)
        self.assertNotIn('python3', text)


if __name__ == '__main__':
    unittest.main()
