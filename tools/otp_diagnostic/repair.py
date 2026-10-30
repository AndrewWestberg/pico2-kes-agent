#!/usr/bin/env python3
"""Attended, one-shot host controller for the private CRIT1 repair image."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import struct
import stat
import sys
import tempfile
import termios
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import firmware

SERIAL = '00afd9003906a634'
KEY = 'be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0'
FILES = {'repair-unsigned.elf', 'repair-signed.elf', 'repair-signed.uf2',
         'diagnostic-source.c', 'diagnostic-CMakeLists.txt', 'repair_sequence.h', 'repair.py'}
ROWS = list(range(0x40, 0x4e)) + list(range(0xc4, 0xcc)) + list(range(0xd0, 0xd8)) + list(range(0xe0, 0xf0))
LIMIT = 65536
COMMAND_TIMEOUT = 10


class Failure(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def require(condition, message, code=5):
    if not condition:
        raise Failure(message, code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key', 2)
        result[key] = value
    return result


def diagnostic_segments(path):
    """Validate this copy-to-RAM diagnostic without changing production ELF rules."""
    data = firmware.bounded_file(path, firmware.MAX_ELF)
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01', 'invalid ELF identification', 7)
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    require(h[1:4] == (2, 40, 1) and h[8] == 52 and h[9] == 32 and
            0 < h[10] <= 128 and h[5] + h[9] * h[10] <= len(data), 'invalid ELF header', 7)
    require(firmware.FIRMWARE_START <= (h[4] & ~1) < firmware.FIRMWARE_END, 'ELF entry outside firmware', 7)
    segments = []
    for i in range(h[10]):
        typ, off, va, pa, size, mem, flags, align = struct.unpack_from('<IIIIIIII', data, h[5] + i * 32)
        if typ != 1:
            continue
        # picotool's appended .sigx PT_LOAD can have an odd file offset despite
        # p_align=2; physical and virtual address/length bounds are authoritative.
        require(size <= mem and off + size <= len(data) and va + mem <= 0x100000000 and
                pa + size <= 0x100000000 and
                (align in (0, 1) or (align > 1 and not (align & (align - 1)))),
                'invalid ELF load bounds', 7)
        if mem > size:
            require(0x20000000 <= va and va + mem <= 0x20082000, 'BSS outside SRAM', 7)
        if not size:
            continue
        require(pa % 4 == size % 4 == 0 and firmware.FIRMWARE_START <= pa < pa + size <= firmware.FIRMWARE_END,
                'ELF load outside firmware', 7)
        require((firmware.FIRMWARE_START <= va and va + mem <= firmware.FIRMWARE_END) or
                (0x20000000 <= va and va + mem <= 0x20082000), 'ELF virtual load outside flash or SRAM', 7)
        require(all(pa + size <= start or start + len(contents) <= pa for start, contents in segments),
                'overlapping ELF loads', 7)
        segments.append((pa, data[off:off + size]))
    require(segments, 'empty ELF', 7)
    return segments


def diagnostic_metadata(segments, signed):
    """Validate the SDK discovery/ignored/signed block loop for copy-to-RAM."""
    image = {}
    for address, data in segments:
        image.update((address + i, b) for i, b in enumerate(data))
    def word(address):
        require(address % 4 == 0 and all(address + i in image for i in range(4)), 'metadata outside ELF loads', 7)
        return sum(image[address + i] << (8 * i) for i in range(4))
    starts = [a for a in range(firmware.FIRMWARE_START, firmware.FIRMWARE_START + 4096, 4)
              if all(a + i in image for i in range(4)) and word(a) == 0xffffded3]
    require(starts, 'missing image definition', 7)
    start = current = starts[0]
    blocks, ends, visited = [], [], set()
    while True:
        require(current not in visited and len(visited) < 16 and word(current) == 0xffffded3, 'invalid metadata loop', 7)
        visited.add(current)
        pos, items = current + 4, []
        for _ in range(96):
            header = word(pos)
            typ = header & 255
            size = (header >> 8) & (0xffff if typ & 0x80 else 0xff)
            if typ == 0xff:
                require(size == (pos-current-4)//4 and word(pos+8) == 0xab123579, 'invalid metadata terminator', 7)
                delta = struct.unpack('<i', struct.pack('<I', word(pos+4)))[0]
                break
            require(size and pos + size*4 <= current + 0x280, 'invalid metadata item', 7)
            items.append((typ, header, [word(pos + 4*i) for i in range(1, size)], pos))
            pos += size*4
        else:
            raise Failure('unterminated metadata', 7)
        blocks.append(items)
        ends.append(pos + 12)
        current += delta
        if current == start:
            break
    require(len(blocks) == (3 if signed else 2) and
            len(blocks[0]) == 1 and blocks[0][0][1] == 0x10210142 and
            len(blocks[1]) == 1 and blocks[1][0][1] == 0x000001fe,
            'unexpected diagnostic image blocks', 7)
    require(not any(t == 9 for block in blocks[:2] for t, _, _, _ in block), 'unexpected signature', 7)
    if not signed:
        return
    items = blocks[2]
    require(items and items[0][0] == 0x42 and items[0][1] >> 16 == 0x1821 and
            sum(t == 9 for t, _, _, _ in items) == 1 and
            not any(t == 0x0a for t, _, _, _ in items), 'invalid signed image definition', 7)
    maps = [(h, v, p) for t, h, v, p in items if t == 6]
    require(len(maps) == 1, 'invalid signed load map', 7)
    header, values, pos = maps[0]
    count, absolute = (header >> 24) & 0x7f, bool(header & 0x80000000)
    require(count and len(values) == count * 3, 'malformed signed load map', 7)
    covered = []
    for i in range(count):
        source, target, size = values[i*3:i*3+3]
        if not source:
            continue
        if absolute:
            require(size >= target, 'invalid absolute load map', 7)
            size -= target
        else:
            source = (source + pos) & 0xffffffff
        require(size and firmware.FIRMWARE_START <= source < source + size <= firmware.FIRMWARE_END and
                ((firmware.FIRMWARE_START <= target and target + size <= firmware.FIRMWARE_END) or
                 (0x20000000 <= target and target + size <= 0x20082000)),
                'signed load map outside allowed memory', 7)
        covered.append((source, source + size))
    require(any(lo <= start and ends[0] <= hi for lo, hi in covered), 'discovery block not signed', 7)
    vectors = [v for t, _, v, _ in items if t == 3]
    entries = [v for t, _, v, _ in items if t == 0x44]
    require(len(vectors) == 1 and len(vectors[0]) == 1 and len(entries) == 1 and
            len(entries[0]) in (2, 3), 'invalid signed entry', 7)
    vector = vectors[0][0]
    require(any(lo <= vector and vector + 8 <= hi for lo, hi in covered) and
            word(vector) == entries[0][1] and word(vector+4) == entries[0][0], 'signed vector mismatch', 7)


def verify_diagnostic_signature(path, segments, point):
    firmware.check_picotool()
    diagnostic_metadata(segments, True)
    output, _ = firmware.run(['picotool', 'info', '-a', path, '-t', 'elf'])
    text = output.decode('ascii')
    signatures = re.findall(r'(?m)^[ \t]*signature:[ \t]*(\S+)[ \t]*$', text)
    sections = re.split(r'(?m)^Metadata Block [0-9]+[ \t]*$', text)
    signed = [s for s in sections[1:] if re.search(r'(?m)^[ \t]*signature:', s)]
    require(signatures and all(s == 'verified' for s in signatures) and len(signed) == 1, 'invalid signature', 7)
    keys = re.findall(r'(?m)^[ \t]*public key:[ \t]*([0-9a-fA-F]+)[ \t]*$', signed[0])
    require(len(keys) == 1 and keys[0].lower() == point.hex() and
            re.findall(r'(?m)^[ \t]*signature:[ \t]*(\S+)[ \t]*$', signed[0]) == ['verified'],
            'signature authority mismatch', 7)


def image_manifest(directory):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), 'invalid image directory', 2)
    try:
        raw = firmware.bounded_file(directory / 'repair-manifest.json')
        manifest = json.loads(raw, object_pairs_hook=unique)
        keys = {'schema_version', 'kind', 'protocol_version', 'serial', 'bootkey_sha256',
                'source_commit', 'incident_index_sha256', 'files'}
        require(type(manifest) is dict and set(manifest) == keys, 'manifest fields mismatch', 2)
        require(type(manifest['schema_version']) is int and manifest['schema_version'] == 1 and
                type(manifest['protocol_version']) is int and manifest['protocol_version'] == 1 and
                manifest['kind'] == 'crit1-row-repair' and manifest['serial'] == SERIAL and
                manifest['bootkey_sha256'] == KEY, 'manifest identity mismatch', 2)
        require(isinstance(manifest['source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', manifest['source_commit']) and
                isinstance(manifest['incident_index_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', manifest['incident_index_sha256']), 'manifest provenance invalid', 2)
        hashes = manifest['files']
        require(type(hashes) is dict and set(hashes) == FILES, 'manifest payload set mismatch', 2)
        # The only permitted extra file is the separately durable one-shot marker.
        require({p.name for p in directory.iterdir()} <= FILES | {'repair-manifest.json', 'repair-attempt.json'}, 'unexpected image directory entry', 2)
        marker = directory / 'repair-attempt.json'
        require(not marker.is_symlink(), 'attempt marker is a symlink', 2)
        for name in FILES:
            require(isinstance(hashes[name], str) and re.fullmatch(r'[0-9a-f]{64}', hashes[name]), 'invalid payload digest', 2)
            data = firmware.bounded_file(directory / name, firmware.MAX_ELF if name.endswith('.elf') else 4 * 1024 * 1024)
            require(hashlib.sha256(data).hexdigest() == hashes[name], 'payload hash mismatch: ' + name, 2)
        require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == hashes['repair.py'], 'running controller differs from manifest', 2)
        security = Path(__file__).resolve().parents[2] / 'security'
        authority = firmware.verify_authority(security)
        require(authority['bootkey_sha256'] == KEY, 'authority mismatch', 7)
        point = firmware.public_point(security / 'firmware-signing-public.pem')
        unsigned = diagnostic_segments(directory / 'repair-unsigned.elf')
        diagnostic_metadata(unsigned, False)
        segments = diagnostic_segments(directory / 'repair-signed.elf')
        verify_diagnostic_signature(directory / 'repair-signed.elf', segments, point)
        firmware.validate_uf2(directory / 'repair-signed.uf2', segments)
        return manifest, hashlib.sha256(raw).hexdigest()
    except Failure:
        raise
    except (OSError, ValueError, UnicodeError, firmware.ToolError) as exc:
        raise Failure('image validation failed: ' + str(exc), 7) from exc


def tool_provenance():
    pico = firmware.bind_tool()
    tools = {}
    for name in ('openssl', 'gpg', 'gpgv'):
        selected = shutil.which(name)
        require(selected is not None, name + ' unavailable', 7)
        path = Path(selected).resolve(strict=True)
        tools[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    return {'firmware_py_sha256': hashlib.sha256(Path(firmware.__file__).read_bytes()).hexdigest(),
            'picotool': pico, 'crypto_tools': tools}


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_exclusive(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
        with os.fdopen(fd, 'wb') as out:
            fd = -1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)


def checkpoint(path, value):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def usb_parent(port):
    st = os.stat(port)
    require(stat.S_ISCHR(st.st_mode), 'port is not a character device', 2)
    device = (Path('/sys/dev/char') / (str(os.major(st.st_rdev)) + ':' + str(os.minor(st.st_rdev))) / 'device').resolve(strict=True)
    for parent in (device, *device.parents):
        if (parent / 'idVendor').is_file() and (parent / 'idProduct').is_file():
            vendor = (parent / 'idVendor').read_text().strip().lower()
            product = (parent / 'idProduct').read_text().strip().lower()
            serial_file = parent / 'serial'
            serial = serial_file.read_text().strip() if serial_file.is_file() else ''
            require(vendor == '2e8a', 'tty is not attached to Raspberry Pi USB parent', 4)
            return {'sysfs': str(parent), 'vendor': vendor, 'product': product, 'serial': serial}
    raise Failure('tty has no USB parent', 4)


class Serial:
    def __init__(self, port):
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            self.old = termios.tcgetattr(self.fd)
            tty.setraw(self.fd)
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except (OSError, termios.error):
            os.close(self.fd)
            raise
        self.buffer = b''
        self.transcript = bytearray()

    def close(self):
        try:
            termios.tcsetattr(self.fd, termios.TCSANOW, self.old)
        finally:
            os.close(self.fd)

    def command(self, text):
        self.deadline = time.monotonic() + COMMAND_TIMEOUT
        data = (text + '\n').encode('ascii')
        self._log(b'> ' + data)
        while data:
            remaining = self.deadline - time.monotonic()
            require(remaining > 0 and select.select([], [self.fd], [], max(0, remaining))[1], 'serial write timeout', 4)
            n = os.write(self.fd, data)
            require(n > 0, 'serial disconnected', 4)
            data = data[n:]

    def _log(self, data):
        require(len(self.transcript) + len(data) <= LIMIT, 'serial transcript capacity exceeded', 4)
        self.transcript.extend(data)

    def assert_idle(self):
        if self.buffer:
            raise Failure('unexpected buffered serial response', 5)
        if select.select([self.fd], [], [], 0)[0]:
            data = os.read(self.fd, 4096)
            if data:
                self._log(data)
            raise Failure('unexpected serial data or disconnect', 4)

    def line(self):
        while b'\n' not in self.buffer:
            remaining = self.deadline - time.monotonic()
            require(remaining > 0 and select.select([self.fd], [], [], max(0, remaining))[0], 'serial response timeout', 4)
            data = os.read(self.fd, 4096)
            require(data, 'serial disconnected', 4)
            self._log(data)
            self.buffer += data
        line, self.buffer = self.buffer.split(b'\n', 1)
        try:
            return line.rstrip(b'\r').decode('ascii')
        except UnicodeError as exc:
            raise Failure('non-ASCII serial response', 4) from exc


def match(line, pattern):
    result = re.fullmatch(pattern, line)
    require(result is not None, 'unexpected serial response: ' + line[:200], 5)
    return result


HEX = r'([0-9a-f]{8})'


def snapshot(link, initial=False):
    link.command('SNAPSHOT')
    require(link.line() == 'CRIT1_REPAIR protocol=1', 'missing protocol marker')
    line = link.line()
    # USB connection can race the one startup banner with the first response.
    if initial and line == 'CRIT1_REPAIR protocol=1':
        line = link.line()
    ident = match(line, r'identity result=([01]) words=(\d+) flags=' + HEX + r' package=' + HEX + r' chip=([0-9a-f]{16}) rom=(\d+) critical=' + HEX + r' key_match=([01]) key=([0-9a-f]{64})')
    identity = {'result': int(ident[1]), 'words': int(ident[2]), 'flags': int(ident[3], 16), 'package': int(ident[4], 16), 'chip': ident[5], 'rom': int(ident[6]), 'critical': int(ident[7], 16), 'key_match': int(ident[8]), 'key': ident[9]}
    rows = {}
    def getrows(which):
        for row in which:
            m = match(link.line(), r'row=([0-9a-f]{4}) raw=' + HEX + r' read_ok=([01])')
            require(int(m[1], 16) == row and m[3] == '1', 'row order or read failure')
            rows[f'{row:04x}'] = int(m[2], 16)
    getrows(ROWS[:14])
    pages = {}
    for page in (1, 2, 3, 63):
        m = match(link.line(), rf'page{page} lock0=' + HEX + r' lock1=' + HEX + r' sw=' + HEX + r' reads_ok=([01])')
        require(m[4] == '1', 'lock read failure')
        pages[str(page)] = [int(m[i], 16) for i in (1, 2, 3)]
    getrows(ROWS[14:])
    m = match(link.line(), r'controller status=' + HEX + r' usr=' + HEX + r' dbg=' + HEX + r' debugen=' + HEX + r' debugen_lock=' + HEX + r' rma=([01])')
    controller = {'status': int(m[1], 16), 'usr': int(m[2], 16), 'dbg': int(m[3], 16), 'debugen': int(m[4], 16), 'debugen_lock': int(m[5], 16), 'rma': int(m[6])}
    require(link.line() == 'SNAPSHOT_END', 'missing snapshot terminator')
    return {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'identity': identity, 'rows': rows, 'pages': pages, 'controller': controller}


def admit(snap, prefix=0, baseline=None, write=True):
    ident, rows, pages, ctl = (snap[k] for k in ('identity', 'rows', 'pages', 'controller'))
    require(ident['result'] == ident['key_match'] == 1 and ident['words'] == 4 and ident['chip'] == SERIAL and ident['rom'] == 2 and ident['key'] == KEY and ident['critical'] in (5, 7), 'identity or critical policy mismatch')
    group = [rows[f'{i:04x}'] for i in range(0x40, 0x48)]
    complete = group == [7] * 8
    require(group == [7] * (prefix + 1) + [5] * (7 - prefix) or (prefix == 0 and complete), 'unexpected CRIT1 physical group')
    require(all(rows[f'{i:04x}'] == 0x2da180 for i in range(0x48, 0x4b)) and all(rows[f'{i:04x}'] == 0xe01 for i in range(0x4b, 0x4e)), 'boot flags mismatch')
    require(pages['2'][:2] == [0, 0x151515] and pages['63'][:2] == [0, 0x151515] and not ctl['rma'] and not (ctl['dbg'] & 0x1000), 'locks or RMA mismatch')
    require(ctl['debugen'] == 0 and ctl['debugen_lock'] == 0x10f, 'debug override mismatch')
    if write and not complete:
        require(ident['critical'] == 5, 'write requires latched CRIT1=5')
        l0, l1, sw = pages['1']
        b = l1 & 255
        require(l0 == 0 and l1 == b * 0x10101 and not (b & 0xc3) and (b >> 2 & 3) != 2 and (b >> 4 & 3) != 2 and not (sw & ~15) and not (sw & 3) and (sw >> 2 & 3) != 2, 'page-1 write permission mismatch')
        require(ctl['usr'] == 1 and not (ctl['status'] & 0x110), 'controller not ready')
    if baseline is not None:
        require(ident == baseline['identity'] and pages == baseline['pages'], 'identity or locks changed')
        for row in ROWS:
            if not 0x40 <= row <= 0x47:
                require(rows[f'{row:04x}'] == baseline['rows'][f'{row:04x}'], 'non-CRIT1 row changed')
        for k in ('usr', 'dbg', 'debugen', 'debugen_lock', 'rma'):
            require(ctl[k] == baseline['controller'][k], 'controller policy changed')
        require(not (ctl['status'] & 0x110), 'controller error after write')
    return complete


def execute(link, record, save, apply, claim):
    before = snapshot(link, initial=True)
    record['admission'] = before
    complete = admit(before)
    if complete:
        record['final_snapshot'] = before
    record['status'] = 'already_complete' if complete else 'admitted'
    save()
    if not apply or complete:
        return
    link.assert_idle()
    claim()
    link.command('CRIT1REPAIR ' + SERIAL)
    require(link.line() == 'READY step=1 next=0041', 'arming rejected')
    for step in range(1, 8):
        link.assert_idle()
        row = 0x40 + step
        pending = {'step': step, 'row': f'{row:04x}', 'payload': 7}
        record['pending'] = pending
        record['status'] = 'uncertain'
        save()  # Crash-safe before even a partial serial write.
        record['last_dispatched'] = pending
        link.command(f'NEXT {SERIAL} {step}')
        require(link.line() == f'INTENT step={step} row={row:04x} count=1 payload=00000007', 'invalid intent')
        m = match(link.line(), rf'RESULT step={step} row={row:04x} rc=(-?\d+) status=' + HEX + r' raw=' + HEX + r' read_ok=([01]) elapsed_us=(\d+)')
        result = {'step': step, 'row': f'{row:04x}', 'rc': int(m[1]), 'status': int(m[2], 16), 'raw': int(m[3], 16), 'read_ok': int(m[4]), 'elapsed_us': int(m[5])}
        require(result['rc'] == 0 and not (result['status'] & 0x110) and result['raw'] == 7 and result['read_ok'] == 1, 'row result failed')
        if step == 7:
            require(link.line() == 'COMPLETE', 'missing completion')
        after = snapshot(link)
        admit(after, step, before)
        record['rows'].append({'intent': pending, 'result': result, 'snapshot': after})
        record['final_snapshot'] = after
        # Persist the observation while the durable record still says uncertain.
        save()
        record['pending'] = None
        record['status'] = 'raw_complete_awaiting_cold_boot' if step == 7 else 'in_progress'
        try:
            save()
        except BaseException:
            record['pending'] = pending
            record['status'] = 'uncertain'
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--image-dir', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    port, directory, path = map(Path, (args.port, args.image_dir, args.record))
    record = None
    link = None
    created = False
    try:
        require(all(p.is_absolute() for p in (port, directory, path)), 'all paths must be absolute', 2)
        manifest, manifest_hash = image_manifest(directory)
        provenance = tool_provenance()
        if args.apply:
            require(sys.stdin.isatty() and sys.stdout.isatty(), 'apply requires a terminal', 3)
            require(input('Type exact CHIPID to authorize repair: ') == SERIAL, 'confirmation mismatch', 3)
        try:
            parent = usb_parent(port)
        except FileNotFoundError as exc:
            raise Failure('tty or USB parent unavailable', 4) from exc
        record = {'schema_version': 1, 'protocol_version': 1, 'mode': 'apply' if args.apply else 'snapshot', 'serial': SERIAL, 'port': str(port), 'usb_parent': parent, 'manifest': manifest, 'manifest_sha256': manifest_hash, 'tools': provenance, 'created': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'starting', 'pending': None, 'rows': [], 'transcript': ''}
        try:
            create_exclusive(path, record)
        except FileExistsError as exc:
            raise Failure('record already exists', 2) from exc
        created = True
        try:
            link = Serial(str(port))
        except FileNotFoundError as exc:
            raise Failure('tty unavailable', 4) from exc
        require(usb_parent(port) == parent, 'tty USB parent changed while opening', 4)
        def save():
            record['transcript'] = link.transcript.decode('ascii', errors='backslashreplace')
            checkpoint(path, record)
        def claim():
            try:
                create_exclusive(directory / 'repair-attempt.json', {'serial': SERIAL, 'record': str(path), 'manifest_sha256': manifest_hash, 'created': datetime.datetime.now(datetime.timezone.utc).isoformat()})
            except FileExistsError as exc:
                raise Failure('repair attempt already claimed', 5) from exc
        execute(link, record, save, args.apply, claim)
        print(json.dumps({'status': record['status'], 'admission': record['admission']}, indent=2, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        pending = record is not None and (record.get('pending') is not None or record.get('last_dispatched') is not None)
        if pending and record.get('pending') is None:
            record['pending'] = record['last_dispatched']
        code = 6 if pending else (exc.code if isinstance(exc, Failure) else (3 if isinstance(exc, PermissionError) else 7))
        if created:
            record['status'] = 'uncertain' if pending else 'failed'
            record['error'] = str(exc)[:500]
            if link is not None:
                record['transcript'] = link.transcript.decode('ascii', errors='backslashreplace')
            try:
                checkpoint(path, record)
            except OSError:
                pass
        try:
            print(str(exc), file=sys.stderr)
        except OSError:
            pass
        return code
    finally:
        if link is not None:
            try:
                link.close()
            except (OSError, termios.error):
                pass


if __name__ == '__main__':
    sys.exit(main())
