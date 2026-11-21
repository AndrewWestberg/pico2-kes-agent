import errno
import json
import os
import pty
import select
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest
from time import monotonic


SCRIPT = Path(__file__).resolve().parents[2] / 'install.sh'
REPOSITORY = 'AndrewWestberg/pico2-kes-agent'
LATEST = f'https://api.github.com/repos/{REPOSITORY}/releases/latest'
RELEASES = f'https://github.com/{REPOSITORY}/releases/download'
RAW = f'https://raw.githubusercontent.com/{REPOSITORY}/'
HELPERS = ('firmware.py', 'publish_release.py')
RC = 'v0.1.0-rc.26'
ASSETS = (
    'distribution.json', 'distribution.json.sig', 'distribution.tar',
    'distribution-authority.json', 'distribution-authority.json.asc',
    'release-authority.asc', 'install.sh', 'install.sh.sig',
)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bundle = self.root / 'extracted bundle'
        self.updater = self.bundle / 'bin' / 'p2kesup'
        self.sudo_log = self.root / 'sudo.log'
        self.updater_log = self.root / 'updater.log'
        self.curl_log = self.root / 'curl.log'
        self.download_dir_log = self.root / 'download-dir.log'
        self.routes = self.root / 'routes.json'
        self.env = {
            'PATH': f'{self.root}:/usr/bin:/bin',
            'HOME': str(self.root),
            'SUDO_LOG': str(self.sudo_log),
            'UPDATER_LOG': str(self.updater_log),
            'CURL_LOG': str(self.curl_log),
            'DOWNLOAD_DIR_LOG': str(self.download_dir_log),
            'RAW': RAW,
            'ROUTES': str(self.routes),
        }
        self.routes.write_text('{}')
        self.executable(self.root / 'sudo',
                        '#!/bin/sh\nprintf "%s\\n" "$@" > "$SUDO_LOG"\n'
                        '[ "$1" = "--" ] || exit 42\nshift\nexec "$@"\n')
        self.executable(self.root / 'curl', '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith("https://"))
with open(os.environ["CURL_LOG"], "a") as log:
    print(url, file=log)
Path(os.environ["DOWNLOAD_DIR_LOG"]).write_text(os.getcwd())
routes = json.loads(Path(os.environ["ROUTES"]).read_text())
route = routes.get(url)
if route is None and url.startswith(os.environ["RAW"]):
    route = routes.get(url.rsplit("/", 1)[-1])
if route is None:
    sys.exit(22)
status, body = route
Path(args[args.index("-o") + 1]).write_text(body)
if "-w" in args:
    print(status, end="")
elif status != 200:
    sys.exit(22)
''')

    @staticmethod
    def executable(path, source):
        path.write_text(source)
        path.chmod(0o755)

    def make_bundle(self):
        self.updater.parent.mkdir(parents=True)
        self.executable(self.updater,
                        '#!/bin/sh\n'
                        'if [ "$1" = "--version" ]; then echo fixture-version; exit; fi\n'
                        'printf "%s\\n" "$0" "$@" > "$UPDATER_LOG"\n')

    def run_launcher(self, *args, answer=None):
        if answer is None:
            command = ['/bin/sh', str(SCRIPT), *args]
            return subprocess.run(command, cwd=self.root, env=self.env,
                                  input='y\n', capture_output=True, text=True,
                                  start_new_session=True, timeout=15)

        command = ['/bin/sh', '-s', '--', *args]
        pid, master = pty.fork()
        if pid == 0:
            try:
                os.chdir(self.root)
                # Shell input is the launcher, while /dev/tty still receives consent.
                with SCRIPT.open('rb') as source:
                    os.dup2(source.fileno(), 0)
                os.execve(command[0], command, self.env)
            finally:
                os._exit(127)

        output = bytearray()
        deadline = monotonic() + 15
        try:
            while select.select([master], [], [], max(0, deadline - monotonic()))[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if answer is not None and b'[y/N]' in output:
                    self.assertFalse(self.sudo_log.exists(), output.decode())
                    os.write(master, answer.encode() + b'\n')
                    answer = None
            else:
                self.fail(f'Installer timed out:\n{output.decode()}')
        except BaseException:
            os.kill(pid, signal.SIGKILL)
            raise
        finally:
            os.close(master)
            _, status = os.waitpid(pid, 0)
        return subprocess.CompletedProcess(command, os.waitstatus_to_exitcode(status),
                                           output.decode(), '')

    def assert_no_sudo(self):
        self.assertFalse(self.sudo_log.exists())
        self.assertFalse(self.updater_log.exists())

    def assert_refused_before_prompt(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('[y/N]', result.stdout)
        self.assert_no_sudo()

    def candidate_routes(self):
        routes = {f'{RELEASES}/{RC}/{name}': [200, 'untrusted fixture'] for name in ASSETS}
        routes[f'{RELEASES}/{RC}/distribution-authority.json'][1] = '{}'
        for name in HELPERS:
            routes[name] = [200, (SCRIPT.parent / 'tools' / name).read_text()]
        return routes

    def test_valid_posix_shell_syntax(self):
        result = subprocess.run(['/bin/sh', '-n', str(SCRIPT)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_attended_offline_delegation_uses_absolute_bundle(self):
        self.make_bundle()
        expected = [str(self.updater), 'install', '--bundle', str(self.bundle)]
        for args in ((self.bundle.name,), ('--bundle', str(self.bundle))):
            with self.subTest(args=args):
                result = self.run_launcher(*args, answer='y')
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn('[y/N]', result.stdout)
                self.assertEqual(self.sudo_log.read_text().splitlines(), ['--', *expected])
                self.assertEqual(self.updater_log.read_text().splitlines(), expected)
                self.sudo_log.unlink()
                self.updater_log.unlink()
        self.assertFalse(self.curl_log.exists())

    def test_empty_answer_declines_and_piped_yes_is_not_attended(self):
        self.make_bundle()
        for answer in ('', None):
            with self.subTest(answer=answer):
                result = self.run_launcher('--bundle', self.bundle.name, answer=answer)
                self.assertNotEqual(result.returncode, 0)
                if answer == '':
                    self.assertIn('[y/N]', result.stdout)
                self.assert_no_sudo()
        self.assertFalse(self.curl_log.exists())

    def test_invalid_flags_fail_before_download_or_sudo(self):
        self.make_bundle()
        for args in (
            ('--unknown',), ('--bundle',), ('--version',),
            ('--bundle', ''), ('--version', ''), ('--version', '../v1.2.3'),
            ('--bundle', self.bundle.name, '--version', RC),
            ('--version', RC, '--bundle', self.bundle.name),
            (self.bundle.name, self.bundle.name),
        ):
            with self.subTest(args=args):
                result = self.run_launcher(*args, answer='y')
                self.assert_refused_before_prompt(result)
                self.assertFalse(self.curl_log.exists())

    def test_missing_extracted_updater_fails_before_prompt_or_sudo(self):
        self.bundle.mkdir()
        result = self.run_launcher('--bundle', self.bundle.name, answer='y')
        self.assert_refused_before_prompt(result)
        self.assertIn('bundle', result.stdout)
        self.assertFalse(self.curl_log.exists())

    def test_missing_stable_release_does_not_fall_back(self):
        self.updater = self.root / 'bin' / 'p2kesup'
        self.make_bundle()
        self.routes.write_text(json.dumps({LATEST: [404, '{}']}))
        result = self.run_launcher(answer='y')
        self.assert_refused_before_prompt(result)
        self.assertIn('No qualified stable release is available', result.stdout)
        self.assertEqual(self.curl_log.read_text().splitlines(), [LATEST])

    def test_latest_candidate_is_not_selected(self):
        self.routes.write_text(json.dumps({LATEST: [200, json.dumps({
            'tag_name': RC, 'draft': False, 'prerelease': False,
        })]}))
        result = self.run_launcher(answer='y')
        self.assert_refused_before_prompt(result)
        self.assertIn('qualified stable', result.stdout)
        self.assertEqual(self.curl_log.read_text().splitlines(), [LATEST])

    def test_explicit_candidate_downloads_exact_assets_and_rejects_untrusted_bundle(self):
        self.routes.write_text(json.dumps(self.candidate_routes()))
        result = self.run_launcher('--version', RC, answer='y')
        self.assert_refused_before_prompt(result)
        self.assertIn('unknown or missing fields', result.stdout)
        requests = self.curl_log.read_text().splitlines()
        assets = [url for url in requests if url.startswith(RELEASES)]
        self.assertCountEqual(assets, [f'{RELEASES}/{RC}/{name}' for name in ASSETS])
        self.assertNotIn(LATEST, requests)
        helpers = [url.removeprefix(RAW).split('/') for url in requests if url.startswith(RAW)]
        self.assertCountEqual([path[-1] for path in helpers], HELPERS)
        self.assertEqual(helpers[0][0], helpers[1][0])
        self.assertRegex(helpers[0][0], r'^[0-9a-f]{40}$')
        self.assertFalse(Path(self.download_dir_log.read_text()).exists())

    def test_tampered_verifier_is_not_run(self):
        executed = self.root / 'untrusted-helper-ran'
        routes = self.candidate_routes()
        routes['publish_release.py'][1] = (
            f'from pathlib import Path\nPath({str(executed)!r}).touch()\n'
        )
        self.routes.write_text(json.dumps(routes))
        result = self.run_launcher('--version', RC, answer='y')
        self.assert_refused_before_prompt(result)
        self.assertIn('Release verifier checksum mismatch', result.stdout)
        self.assertFalse(executed.exists())
        self.assertFalse(Path(self.download_dir_log.read_text()).exists())


if __name__ == '__main__':
    unittest.main()
