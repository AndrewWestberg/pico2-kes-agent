import copy
import importlib.util
import hashlib
import json
import os
import pty
import select
import struct
from pathlib import Path
import subprocess
import tempfile
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('otp_repair', ROOT / 'tools/otp_diagnostic/repair.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def state(group=None):
    rows = {f'{n:04x}': 0 for n in r.ROWS}
    for i, value in enumerate(group or [7] + [5] * 7):
        rows[f'{0x40+i:04x}'] = value
    for i in range(0x48, 0x4b): rows[f'{i:04x}'] = 0x2da180
    for i in range(0x4b, 0x4e): rows[f'{i:04x}'] = 0xe01
    return {'identity': {'result': 1, 'words': 4, 'flags': 1, 'package': 0, 'chip': r.SERIAL, 'rom': 2, 'critical': 5, 'key_match': 1, 'key': r.KEY},
            'rows': rows, 'pages': {'1': [0, 0, 0], '2': [0, 0x151515, 0], '3': [0, 0, 0], '63': [0, 0x151515, 0]},
            'controller': {'status': 0x801001, 'usr': 1, 'dbg': 0, 'debugen': 0, 'debugen_lock': 0x10f, 'rma': 0}}


def lines(s):
    i = s['identity']
    result = ['CRIT1_REPAIR protocol=1', f"identity result={i['result']} words={i['words']} flags={i['flags']:08x} package={i['package']:08x} chip={i['chip']} rom={i['rom']} critical={i['critical']:08x} key_match={i['key_match']} key={i['key']}"]
    def emit(rows):
        for n in rows:
            result.append(f"row={n:04x} raw={s['rows'][f'{n:04x}']:08x} read_ok=1")
    emit(r.ROWS[:14])
    for n in (1, 2, 3, 63):
        a, b, c = s['pages'][str(n)]
        result.append(f'page{n} lock0={a:08x} lock1={b:08x} sw={c:08x} reads_ok=1')
    emit(r.ROWS[14:])
    c = s['controller']
    result.append(f"controller status={c['status']:08x} usr={c['usr']:08x} dbg={c['dbg']:08x} debugen={c['debugen']:08x} debugen_lock={c['debugen_lock']:08x} rma={c['rma']}")
    result.append('SNAPSHOT_END')
    return result


class Fake:
    def __init__(self, snapshot=None, fault=None):
        self.state = snapshot or state()
        self.fault = fault
        self.queue = []
        self.commands = []
        self.writes = []
    def assert_idle(self):
        if self.queue: raise r.Failure('unexpected queued response', 5)
    def command(self, command):
        self.commands.append(command)
        if command == 'SNAPSHOT':
            self.queue += lines(self.state)
        elif command.startswith('CRIT1REPAIR'):
            self.queue.append('READY step=1 next=0041')
        else:
            step = int(command.split()[-1]); row = 0x40 + step
            self.writes.append(row)
            self.queue.append(f'INTENT step={step} row={row:04x} count=1 payload=00000007')
            if self.fault == 'timeout': return
            if self.fault == 'disconnect': self.queue.append(None); return
            if self.fault not in ('raw', 'snapshot_mismatch'): self.state['rows'][f'{row:04x}'] = 7
            raw = 5 if self.fault == 'raw' else 7
            result = f'RESULT step={step} row={row:04x} rc=0 status=00801001 raw={raw:08x} read_ok=1 elapsed_us=5'
            if self.fault == 'malformed': result += ' unexpected'
            if self.fault == 'order': result = result.replace(f'step={step}', f'step={step+1}')
            self.queue.append(result)
            if self.fault == 'duplicate': self.queue.append(result)
            if step == 7: self.queue.append('COMPLETE')
    def line(self):
        if not self.queue or self.queue[0] is None: raise r.Failure('disconnected or timeout', 4)
        return self.queue.pop(0)


class HostTests(unittest.TestCase):
    def run_controller(self, fake, apply=True):
        record = {'pending': None, 'rows': []}
        saved = []
        claimed = []
        error = None
        try:
            r.execute(fake, record, lambda: saved.append(copy.deepcopy(record)), apply, lambda: claimed.append(True))
        except r.Failure as exc:
            error = exc
        return record, saved, claimed, error

    def test_preview_and_complete_never_write(self):
        for fake, apply in ((Fake(), False), (Fake(state([7]*8)), True)):
            rec, saved, claims, error = self.run_controller(fake, apply)
            self.assertIsNone(error)
            self.assertFalse(claims)
            self.assertEqual(fake.writes, [])
            self.assertEqual(fake.commands, ['SNAPSHOT'])
            if apply:
                self.assertEqual(rec['final_snapshot'], rec['admission'])

    def test_success_fixed_rows_and_pending_before_dispatch(self):
        fake = Fake()
        rec, saved, claims, error = self.run_controller(fake)
        self.assertIsNone(error)
        self.assertEqual(fake.writes, list(range(0x41, 0x48)))
        self.assertEqual(len(claims), 1)
        self.assertEqual([x['pending']['row'] for x in saved if x['pending']], [f'{i:04x}' for i in range(0x41, 0x48) for _ in range(2)])
        self.assertEqual(rec['status'], 'raw_complete_awaiting_cold_boot')
        self.assertIsNone(rec['pending'])

    def test_admission_rejects_identity_permission_partial(self):
        for mutation in ('identity', 'permission', 'partial'):
            s = state()
            if mutation == 'identity': s['identity']['chip'] = '0000000000000000'
            if mutation == 'permission': s['pages']['1'][0] = 1
            if mutation == 'partial': s['rows']['0042'] = 7
            fake = Fake(s)
            rec, saved, claims, error = self.run_controller(fake)
            self.assertIsNotNone(error)
            self.assertFalse(claims)
            self.assertFalse(fake.writes)

    def test_no_next_after_ambiguous_or_bad_result(self):
        for fault in ('raw', 'snapshot_mismatch', 'order', 'duplicate', 'malformed', 'disconnect', 'timeout'):
            fake = Fake(fault=fault)
            rec, saved, claims, error = self.run_controller(fake)
            self.assertIsNotNone(error, fault)
            self.assertEqual(fake.writes, [0x41], fault)
            self.assertEqual(rec['status'], 'uncertain')
            self.assertEqual(saved[-1]['pending']['row'], '0041')

    def test_exclusive_durable_marker_and_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'record.json'
            r.create_exclusive(path, {'pending': {'row': '0041'}, 'status': 'uncertain'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): r.create_exclusive(path, {})
            self.assertIn('0041', path.read_text())
            r.checkpoint(path, {'pending': {'row': '0041'}, 'status': 'uncertain'})
            with self.assertRaises(FileExistsError): r.create_exclusive(path, {})

    def test_manifest_rejects_duplicate_before_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'repair-manifest.json').write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(r.Failure): r.image_manifest(path)

    def test_manifest_rejects_hash_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            for name in r.FILES:
                (path / name).write_bytes(Path(r.__file__).read_bytes() if name == 'repair.py' else name.encode())
            manifest = {'schema_version': 1, 'kind': 'crit1-row-repair', 'protocol_version': 1,
                        'serial': r.SERIAL, 'bootkey_sha256': r.KEY, 'source_commit': 'a' * 40,
                        'incident_index_sha256': 'b' * 64,
                        'files': {name: hashlib.sha256((path / name).read_bytes()).hexdigest() for name in r.FILES}}
            (path / 'repair-manifest.json').write_text(json.dumps(manifest))
            (path / 'repair-signed.uf2').write_bytes(b'changed')
            with self.assertRaises(r.Failure): r.image_manifest(path)
            (path / 'repair-signed.uf2').unlink()
            (path / 'repair-signed.uf2').symlink_to(path / 'repair-signed.elf')
            with self.assertRaises(r.Failure): r.image_manifest(path)

    def test_elf_copy_to_ram_bss_and_firmware_bounds(self):
        # ELF32 ARM LOAD layout with the actual flash-backed BSS shape emitted by
        # the SDK linker: BSS has SRAM VMA, flash PADDR and zero file bytes.
        data = bytearray(0x1210)
        ident = b'\x7fELF\x01\x01\x01' + bytes(9)
        struct.pack_into('<16sHHIIIIIHHHHHH', data, 0, ident, 2, 40, 1, 0x1000014d,
                         52, 0, 0, 52, 32, 2, 0, 0, 0)
        struct.pack_into('<IIIIIIII', data, 52, 1, 0x1000, 0x10000000, 0x10000000,
                         0x210, 0x210, 5, 0x1000)
        struct.pack_into('<IIIIIIII', data, 84, 1, 0xb78, 0x20007b78, 0x10007c70,
                         0, 0x944, 6, 0x1000)
        for off, value in ((0x1100, 0xffffded3), (0x1104, 0x10210142),
                           (0x1108, 0x1ff), (0x110c, 0x30), (0x1110, 0xab123579),
                           (0x1130, 0xffffded3), (0x1134, 0x1fe), (0x1138, 0x1ff),
                           (0x113c, 0xffffffd0), (0x1140, 0xab123579)):
            struct.pack_into('<I', data, off, value)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image.elf'
            path.write_bytes(data)
            segments = r.diagnostic_segments(path)
            self.assertEqual(len(segments), 1)
            r.diagnostic_metadata(segments, False)
            with self.assertRaises(r.Failure): r.diagnostic_metadata(segments, True)
            struct.pack_into('<I', data, 52 + 12, 0x10100000)
            path.write_bytes(data)
            with self.assertRaises(r.Failure): r.diagnostic_segments(path)

    def test_built_copy_to_ram_image_when_available(self):
        path = ROOT / 'target/otp-diagnostic/pico2-otp-crit1-repair.elf'
        if not path.exists():
            self.skipTest('SDK diagnostic build not present')
        r.diagnostic_metadata(r.diagnostic_segments(path), False)

    def test_complete_bypasses_write_permissions(self):
        snap = state([7]*8)
        snap['identity']['critical'] = 7
        snap['pages']['1'] = [1, 0xaaaaaa, 15]
        fake = Fake(snap)
        record, _, claims, error = self.run_controller(fake)
        self.assertIsNone(error)
        self.assertFalse(claims)
        self.assertEqual(record['final_snapshot']['identity']['critical'], 7)
        self.assertFalse(fake.writes)

    def test_transcript_capacity_fails_explicitly(self):
        link = r.Serial.__new__(r.Serial)
        link.transcript = bytearray(b'x' * r.LIMIT)
        with self.assertRaisesRegex(r.Failure, 'capacity'): link._log(b'x')

    def test_main_blocks_existing_records_and_attempt_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / 'existing.json'
            existing.write_text('partial')
            fake = Fake()
            fake.transcript = bytearray()
            fake.close = lambda: None
            args = ['--port', '/dev/test', '--image-dir', tmp, '--record', str(existing), '--apply']
            with mock.patch.object(r, 'image_manifest', return_value=({}, 'a' * 64)), \
                 mock.patch.object(r, 'tool_provenance', return_value={}), \
                 mock.patch.object(r, 'usb_parent', return_value={'sysfs': '/test'}), \
                 mock.patch.object(r, 'Serial', return_value=fake), \
                 mock.patch.object(sys.stdin, 'isatty', return_value=True), \
                 mock.patch.object(sys.stdout, 'isatty', return_value=True), \
                 mock.patch('builtins.input', return_value=r.SERIAL):
                self.assertEqual(r.main(args), 2)
                self.assertEqual(existing.read_text(), 'partial')
                self.assertFalse(fake.commands)
                (Path(tmp) / 'repair-attempt.json').write_text('previous attempt')
                args[args.index(str(existing))] = str(Path(tmp) / 'second.json')
                self.assertEqual(r.main(args), 5)
                self.assertEqual(fake.commands, ['SNAPSHOT'])
                self.assertFalse(fake.writes)

    def test_main_checkpoint_failure_retains_pending(self):
        for phase in ('observation', 'clear', 'interrupt', 'print'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                fake = Fake()
                fake.transcript = bytearray()
                fake.close = lambda: None
                original_command = fake.command
                if phase == 'interrupt':
                    def interrupted(command):
                        if command.startswith('NEXT '): raise KeyboardInterrupt()
                        original_command(command)
                    fake.command = interrupted
                original_checkpoint = r.checkpoint
                failed = [False]
                def checkpoint(path, record):
                    should_fail = (phase == 'observation' and record['rows'] and record['pending']) or \
                                  (phase == 'clear' and record['rows'] and record['pending'] is None)
                    if should_fail and not failed[0]:
                        failed[0] = True
                        raise OSError('injected checkpoint failure')
                    return original_checkpoint(path, record)
                def printing(*args, **kwargs):
                    if phase == 'print' and not failed[0]:
                        failed[0] = True
                        raise BrokenPipeError('injected output failure')
                path = Path(tmp) / 'result.json'
                args = ['--port', '/dev/test', '--image-dir', tmp, '--record', str(path), '--apply']
                with mock.patch.object(r, 'image_manifest', return_value=({}, 'a' * 64)), \
                     mock.patch.object(r, 'tool_provenance', return_value={}), \
                     mock.patch.object(r, 'usb_parent', return_value={'sysfs': '/test'}), \
                     mock.patch.object(r, 'Serial', return_value=fake), \
                     mock.patch.object(r, 'checkpoint', side_effect=checkpoint), \
                     mock.patch.object(sys.stdin, 'isatty', return_value=True), \
                     mock.patch.object(sys.stdout, 'isatty', return_value=True), \
                     mock.patch('builtins.input', return_value=r.SERIAL), \
                     mock.patch('builtins.print', side_effect=printing):
                    self.assertEqual(r.main(args), 6)
                saved = json.loads(path.read_text())
                self.assertEqual(saved['status'], 'uncertain')
                self.assertIsNotNone(saved['pending'])
                self.assertTrue((Path(tmp) / 'repair-attempt.json').exists())
                self.assertLessEqual(len(fake.writes), 7 if phase == 'print' else 1)

    def test_real_tty_timeout_retains_uncertain(self):
        for apply in (False, True):
            with self.subTest(apply=apply), tempfile.TemporaryDirectory() as tmp:
                master, slave = pty.openpty()
                port = os.ttyname(slave)
                fake = Fake(fault='timeout' if apply else None)
                stop = threading.Event()
                def peer():
                    buffer = b''
                    while not stop.is_set():
                        if not select.select([master], [], [], 0.05)[0]:
                            continue
                        try:
                            data = os.read(master, 4096)
                        except OSError:
                            return
                        if not data:
                            return
                        buffer += data
                        while b'\n' in buffer:
                            command, buffer = buffer.split(b'\n', 1)
                            fake.command(command.decode().strip())
                            while fake.queue:
                                line = fake.queue.pop(0)
                                os.write(master, (line + '\n').encode())
                thread = threading.Thread(target=peer, daemon=True)
                thread.start()
                record = Path(tmp) / 'record.json'
                args = ['--port', port, '--image-dir', tmp, '--record', str(record)]
                if apply: args.append('--apply')
                try:
                    with mock.patch.object(r, 'image_manifest', return_value=({}, 'a' * 64)), \
                         mock.patch.object(r, 'tool_provenance', return_value={}), \
                         mock.patch.object(r, 'usb_parent', return_value={'sysfs': '/test/usb'}), \
                         mock.patch.object(r, 'COMMAND_TIMEOUT', 0.2), \
                         mock.patch.object(sys.stdin, 'isatty', return_value=True), \
                         mock.patch.object(sys.stdout, 'isatty', return_value=True), \
                         mock.patch('builtins.input', return_value=r.SERIAL):
                        code = r.main(args)
                    saved = json.loads(record.read_text())
                    if apply:
                        self.assertEqual(code, 6)
                        self.assertEqual(saved['status'], 'uncertain')
                        self.assertEqual(saved['pending']['row'], '0041')
                        self.assertEqual(fake.writes, [0x41])
                        self.assertTrue((Path(tmp) / 'repair-attempt.json').exists())
                    else:
                        self.assertEqual(code, 0)
                        self.assertEqual(fake.writes, [])
                        self.assertEqual(saved['status'], 'admitted')
                finally:
                    stop.set()
                    thread.join(timeout=1)
                    os.close(master)
                    os.close(slave)


class NativeGuardTests(unittest.TestCase):
    def test_real_sequence_guard(self):
        source = r'''#include <assert.h>
#include "repair_sequence.h"
int main(void) {
 struct repair_sequence s = {IDLE,1}; int writes=0;
 assert(repair_arm(&s));
 if (repair_claim(&s,1)) ++writes;
 assert(!repair_claim(&s,1)); assert(writes==1 && s.phase==HALTED);
 assert(!repair_claim(&s,2)); assert(!repair_arm(&s));
 s=(struct repair_sequence){IDLE,1}; assert(repair_arm(&s)); assert(repair_claim(&s,1)); assert(repair_finish(&s,true)); assert(!repair_claim(&s,1)); assert(!repair_claim(&s,2));
 s=(struct repair_sequence){IDLE,1}; assert(repair_arm(&s)); assert(!repair_claim(&s,2));
 s=(struct repair_sequence){IDLE,1}; assert(repair_arm(&s)); assert(!repair_arm(&s)); assert(!repair_claim(&s,1));
 s=(struct repair_sequence){IDLE,1}; assert(repair_arm(&s)); assert(repair_claim(&s,1)); assert(!repair_finish(&s,false)); assert(!repair_claim(&s,1));
 s=(struct repair_sequence){IDLE,1}; assert(repair_arm(&s)); writes=0;
 for(int n=1;n<=7;n++){assert(repair_claim(&s,n)); ++writes; assert(repair_finish(&s,true));}
 assert(writes==7 && s.phase==COMPLETE); assert(!repair_claim(&s,7)); assert(!repair_arm(&s));
 return 0;
}'''
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / 'guard.c'; exe = Path(tmp) / 'guard'
            c.write_text(source)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'tools/otp_diagnostic'), str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
