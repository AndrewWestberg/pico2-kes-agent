#!/usr/bin/env python3
"""Offline firmware verification and explicit attended RP2350 provisioning."""
import argparse
import json
import hashlib
import os
import re
import subprocess
import shutil
import struct
import tempfile
import stat
import sys
import time
import signal
from pathlib import Path

PROFILE = "rp2350-signed-msd-v1"
WRITES_ATTEMPTED = False
ACTIVE_ACTION = None
ACTIVE_CHECKPOINT = None
BOUND_TOOL = None
TRACE_HOOK = None
OUTPUT_LIMIT = 65536
EVIDENCE_OUTPUT_LIMIT = 4096
MAX_ACTION_PROCESSES = 8
MAX_RECORD = 8 * 1024 * 1024
ACTION_RESERVE = 1024 * 1024
FIRMWARE_START, FIRMWARE_END, STATE_END = 0x10000000, 0x10100000, 0x10308000
PRIMARY = "9FF957E79B5D853544805F4725491F18087931B6"
SIGNER = "78C0F32094CD02A4BAFA444C684E37A210480F82"
PROJECT = "https://github.com/AndrewWestberg/pico2-kes-agent"
PUBLIC_FILES = ("firmware-signing-public.pem", "firmware-key.json",
                "firmware-key.json.asc", "release-authority.asc")
SPKI_PREFIX = bytes.fromhex("3056301006072a8648ce3d020106052b8104000a03420004")
SET_FIELDS = frozenset((
    "CRIT1.SECURE_BOOT_ENABLE", "CRIT1.DEBUG_DISABLE", "CRIT1.SECURE_DEBUG_DISABLE",
    "BOOT_FLAGS0.DISABLE_BOOTSEL_USB_PICOBOOT_IFC", "BOOT_FLAGS0.DISABLE_BOOTSEL_UART_BOOT",
    "BOOT_FLAGS0.DISABLE_SRAM_WINDOW_BOOT", "BOOT_FLAGS0.DISABLE_OTP_BOOT",
    "BOOT_FLAGS0.DISABLE_WATCHDOG_SCRATCH", "BOOT_FLAGS0.DISABLE_POWER_SCRATCH",
    "BOOT_FLAGS0.DISABLE_AUTO_SWITCH_ARCH", "BOOT_FLAGS0.SINGLE_FLASH_BINARY",
))
CLEAR_FIELDS = frozenset((
    "CRIT1.BOOT_ARCH", "BOOT_FLAGS0.DISABLE_BOOTSEL_USB_MSD_IFC",
    "BOOT_FLAGS0.DISABLE_FLASH_BOOT", "BOOT_FLAGS0.ENABLE_OTP_BOOT",
    "BOOT_FLAGS0.ROLLBACK_REQUIRED", "BOOT_FLAGS0.OVERRIDE_FLASH_PARTITION_SLOT_SIZE",
))

class ToolError(ValueError):
    def __init__(self, message, code=7, *, write_happened=False, evidence=None):
        super().__init__(message)
        self.code = 6 if write_happened else code
        self.write_happened = write_happened
        self.evidence = evidence



def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(obj, keys):
    require(type(obj) is dict and set(obj) == set(keys), "unknown or missing fields")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    data = bounded_file(path)
    return json.loads(data, object_pairs_hook=unique_object)


def validate_policy(policy):
    exact_keys(policy, ("schema_version", "profile", "steppings", "flash", "firmware_region",
                        "state_region", "fields", "page_locks", "rma", "otp_access_keys",
                        "storage_version", "usb_protocol_major"))
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1, "policy version")
    require(policy["profile"] == PROFILE, "unsupported profile")
    require(policy["steppings"] == {"A2": "qualification-required", "A4": "expected-compatible-unverified"}, "unsupported stepping policy")
    require(policy["flash"] == {"jedec_id": "ef4016", "sfdp_header": "534644500a0100ff00080117800000ff", "density_bits_minus_one": 0x1ffffff}, "unsupported flash")
    for name, start, end in (("firmware_region", FIRMWARE_START, FIRMWARE_END),
                              ("state_region", FIRMWARE_END, STATE_END)):
        region = policy[name]
        exact_keys(region, ("start", "end"))
        require(all(type(region[k]) is int for k in region), "invalid region type")
        require(region["start"] == start and region["end"] == end, "unsafe flash boundary")
    fields = policy["fields"]
    exact_keys(fields, SET_FIELDS | CLEAR_FIELDS | {"BOOT_FLAGS1.KEY_VALID", "BOOT_FLAGS1.KEY_INVALID"})
    require(all(type(v) is int for v in fields.values()), "invalid OTP field type")
    require(all(fields[k] == 1 for k in SET_FIELDS), "required protection disabled")
    require(all(fields[k] == 0 for k in CLEAR_FIELDS), "recovery or boot policy conflict")
    require(fields["BOOT_FLAGS1.KEY_VALID"] == 1 and fields["BOOT_FLAGS1.KEY_INVALID"] == 14, "alternate authority enabled")
    exact_keys(policy["page_locks"], ("2", "63"))
    for lock in policy["page_locks"].values():
        exact_keys(lock, ("lock_s", "lock_ns", "lock_bl"))
        require(all(type(v) is int for v in lock.values()), "invalid lock type")
        require(lock["lock_s"] == 1 and lock["lock_ns"] in (1, 3) and lock["lock_bl"] in (1, 3), "unsafe page lock")
    require(policy["rma"] is False and policy["otp_access_keys"] is False, "unsupported OTP access")
    require(type(policy["storage_version"]) is int and policy["storage_version"] == 2, "incompatible storage")
    require(type(policy["usb_protocol_major"]) is int and policy["usb_protocol_major"] == 1, "incompatible USB")
    return policy


def run(command, *, input=None, timeout=60, failure_code=7, extra_env=None):
    """Bound diagnostics; never expose stdin or outputs from unrelated commands."""
    command = [str(arg) for arg in command]
    if command[0] == "picotool" and BOUND_TOOL:
        command[0] = BOUND_TOOL["path"]
    public_device_info = len(command) > 1 and command[1] == "info"
    public_pico_command = BOUND_TOOL is not None and command[0] == BOUND_TOOL["path"] and not public_device_info
    captured = ACTIVE_ACTION is not None and public_pico_command
    if captured:
        require(len(ACTIVE_ACTION) < MAX_ACTION_PROCESSES, "action subprocess evidence budget exhausted")
    if TRACE_HOOK and captured:
        command = [TRACE_HOOK, *command]
    isolated = public_pico_command or (TRACE_HOOK is not None and command[0] == TRACE_HOOK)
    environment = {**os.environ, "LC_ALL": "C", **(extra_env or {})}
    environment = {key: value for key, value in environment.items() if value is not None}
    evidence, interrupted = None, None
    started = time.time_ns()
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            with subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else None,
                                  stdout=stdout, stderr=stderr, env=environment,
                                  start_new_session=isolated) as process:
                try:
                    process.communicate(input=input, timeout=timeout)
                    status = process.returncode
                except BaseException as error:
                    status = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted"
                    interrupted = None if status == "timeout" else error
                    try:
                        if isolated:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait()
                else:
                    if isolated:
                        # A trace supervisor must not leave a writer running after it exits.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        else:
                            status = "orphaned process group"
            stdout.seek(0)
            stderr.seek(0)
            output, diagnostic = stdout.read(OUTPUT_LIMIT + 1), stderr.read(OUTPUT_LIMIT + 1)
        if captured:
            evidence = {"command": command, "status": status,
                        "started_ns": started, "finished_ns": time.time_ns(),
                        "stdout": output[:EVIDENCE_OUTPUT_LIMIT].decode("utf-8", "replace"),
                        "stderr": diagnostic[:EVIDENCE_OUTPUT_LIMIT].decode("utf-8", "replace"),
                        "stdout_truncated": len(output) > EVIDENCE_OUTPUT_LIMIT,
                        "stderr_truncated": len(diagnostic) > EVIDENCE_OUTPUT_LIMIT}
            ACTIVE_ACTION.append(evidence)
            if ACTIVE_CHECKPOINT:
                ACTIVE_CHECKPOINT()
        if interrupted is not None:
            raise interrupted
        if status == "timeout":
            raise ToolError(f"{command[0]} timed out", evidence=evidence)
        if len(output) > OUTPUT_LIMIT or len(diagnostic) > OUTPUT_LIMIT:
            raise ToolError("tool output exceeded limit", evidence=evidence)
        if status != 0:
            raise ToolError(f"{command[0]} failed (exit {status})", failure_code, evidence=evidence)
        return output, diagnostic
    except OSError as error:
        if captured and evidence is None:
            ACTIVE_ACTION.append({"command": command, "status": type(error).__name__,
                                  "started_ns": started, "finished_ns": time.time_ns(),
                                  "stdout": "", "stderr": "", "stdout_truncated": False,
                                  "stderr_truncated": False})
            if ACTIVE_CHECKPOINT:
                ACTIVE_CHECKPOINT()
        raise ToolError(f"{command[0]} could not be executed",
                        4 if isinstance(error, FileNotFoundError) else
                        3 if isinstance(error, PermissionError) else 7) from error


def bounded_file(path, maximum=1024 * 1024):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), f"not a regular payload: {path.name}")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    require(len(data) <= maximum, f"oversized payload: {path.name}")
    return data


def public_point(path):
    run(["openssl", "pkey", "-pubin", "-in", path, "-pubcheck", "-noout"])
    der, _ = run(["openssl", "pkey", "-pubin", "-in", path, "-outform", "DER"])
    require(len(der) == len(SPKI_PREFIX) + 64 and der.startswith(SPKI_PREFIX),
            "authority must be an uncompressed secp256k1 public key")
    return der[len(SPKI_PREFIX):]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def statement(public_key):
    return {
        "schema_version": 1, "purpose": "pico2-kes-firmware-boot-authority-v1",
        "project": PROJECT, "algorithm": "secp256k1", "bootkey_slot": 0,
        "bootkey_sha256": sha256(public_point(public_key)),
        "public_pem_sha256": sha256(bounded_file(public_key)),
    }


def verify_authority(directory, *, trust=(PRIMARY, SIGNER)):
    """Internal trust injection is for isolated tests; CLI always pins production."""
    directory = Path(directory)
    for name in PUBLIC_FILES:
        bounded_file(directory / name)
    expected = statement(directory / PUBLIC_FILES[0])
    actual = read_json(directory / "firmware-key.json")
    exact_keys(actual, expected)
    require(type(actual["schema_version"]) is int and type(actual["bootkey_slot"]) is int
            and actual == expected, "public authority statement mismatch")
    with tempfile.TemporaryDirectory(prefix="pico2-gpgv-") as temporary:
        keyring = Path(temporary) / "authority.gpg"
        run(["gpg", "--batch", "--no-options", "--dearmor", "--output", keyring,
             directory / "release-authority.asc"])
        status, _ = run(["gpgv", "--homedir", temporary, "--keyring", keyring,
                         "--status-fd", "1", directory / "firmware-key.json.asc",
                         directory / "firmware-key.json"], failure_code=5)
    signatures = [line.split() for line in status.decode("ascii").splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(signatures) == 1, "missing or ambiguous GPG authorization")
    valid = signatures[0]
    require(len(valid) == 12 and valid[2] == trust[1] and valid[11] == trust[0],
            "GPG authorization is not from pinned primary/signing subkey")
    require(not any(f"[GNUPG:] {bad}" in status.decode("ascii") for bad in
                    ("REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG")),
            "revoked, expired or invalid GPG authorization")
    return expected


def authorize(public_key, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    require(all(not os.path.lexists(out_dir / name) for name in PUBLIC_FILES),
            "authority already exists; refusing overwrite")
    published = []
    try:
        with tempfile.TemporaryDirectory(prefix=".authority-", dir=out_dir) as temporary:
            temporary = Path(temporary)
            (temporary / PUBLIC_FILES[0]).write_bytes(bounded_file(public_key))
            data = json.dumps(statement(public_key), indent=2).encode() + b"\n"
            (temporary / "firmware-key.json").write_bytes(data)
            certificate, _ = run(["gpg", "--batch", "--armor", "--export", PRIMARY])
            require(certificate.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"), "GPG certificate unavailable")
            (temporary / "release-authority.asc").write_bytes(certificate)
            run(["gpg", "--armor", "--detach-sign", "--local-user", SIGNER + "!",
                 "--output", temporary / "firmware-key.json.asc",
                 temporary / "firmware-key.json"], timeout=300)
            verify_authority(temporary)
            for name in PUBLIC_FILES:
                os.link(temporary / name, out_dir / name)
                published.append(out_dir / name)
    except BaseException:
        for path in published:
            path.unlink()
        raise
    return statement(public_key)


ARTIFACTS = ("pico2-kes-firmware.signed.elf", "pico2-kes-firmware.signed.uf2",
             "pico2-otp-permissions.elf", "firmware.py", "otp-policy.json", *PUBLIC_FILES)
MAX_ELF = 16 * 1024 * 1024


def elf_segments(path, helper=False):
    data = bounded_file(path, MAX_ELF)
    require(len(data) >= 52 and data[:7] == b"\x7fELF\x01\x01\x01", "not ELF32 little endian")
    h = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    require(h[1] == 2 and h[2] == 40 and h[3] == 1 and h[8] == 52
            and h[9] == 32 and 0 < h[10] <= 128, "unsupported Arm ELF header")
    require(h[5] + h[9] * h[10] <= len(data), "truncated program headers")
    segments = []
    for i in range(h[10]):
        typ, off, va, pa, filesz, memsz, flags, align = struct.unpack_from(
            "<IIIIIIII", data, h[5] + i * 32)
        if typ != 1:
            continue
        require(filesz <= memsz and off + filesz <= len(data)
                and pa + memsz <= 0x100000000 and va + memsz <= 0x100000000,
                "invalid load segment bounds")
        if helper and memsz:
            require(0x13ffc000 <= pa < pa + memsz <= 0x14000000
                    and 0x13ffc000 <= va < va + memsz <= 0x14000000,
                    "helper load or BSS outside XIP SRAM")
        elif not helper and not filesz and memsz:
            require(0x20000000 <= va < va + memsz <= 0x20082000
                    and 0x20000000 <= pa < pa + memsz <= 0x20082000,
                    "firmware BSS outside SRAM")
        if not filesz:
            continue
        low, high = (0x13ffc000, 0x14000000) if helper else (FIRMWARE_START, FIRMWARE_END)
        require(pa % 4 == 0 and filesz % 4 == 0 and low <= pa < pa + filesz <= high,
                "load segment outside permitted region or unaligned")
        require(all(pa + filesz <= p or p + len(b) <= pa for p, b in segments),
                "overlapping load segments")
        segments.append((pa, data[off:off + filesz]))
    require(segments, "no file-backed load segments")
    if helper:
        require(0x13ffc000 <= (h[4] & ~1) < 0x14000000, "helper entry outside XIP SRAM")
    return segments
def validate_helper(path):
    """Validate the helper and return its two target value file offsets by field name."""
    elf_segments(path, helper=True)
    data = bounded_file(path, MAX_ELF)
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    mapped = []
    for i in range(header[10]):
        typ, off, va, _, size, _, _, _ = struct.unpack_from("<IIIIIIII", data, header[5] + 32*i)
        if typ == 1 and size:
            mapped.append((va, off, data[off:off + size]))

    def file_offset(address, size):
        matches = [offset + address - va for va, offset, content in mapped
                   if va <= address and address + size <= va + len(content)]
        require(len(matches) == 1, "invalid or ambiguous helper binary-info pointer")
        return matches[0]

    def read_virtual(address, size):
        offset = file_offset(address, size)
        return data[offset:offset + size]

    pattern = struct.pack("<HHI", 11, 0x1111, 0x2222)
    fields = {}
    for _, _, content in mapped:
        for offset in range(0, len(content) - 15, 4):
            if content[offset:offset + 8] != pattern:
                continue
            value, label = struct.unpack_from("<II", content, offset + 8)
            names = ("expected_chipid_low", "expected_chipid_high")
            matched = [name for name in names
                       if read_virtual(label, len(name) + 1) == name.encode() + b"\0"]
            require(len(matched) == 1 and matched[0] not in fields and value % 4 == 0
                    and read_virtual(value, 4) == b"\xff" * 4,
                    "invalid helper target field")
            fields[matched[0]] = file_offset(value, 4)
    require(set(fields) == {"expected_chipid_low", "expected_chipid_high"}
            and len(set(fields.values())) == 2, "missing or duplicate helper target fields")
    check_picotool()
    output, _ = run(["picotool", "config", "--group", "otp_target", path, "-t", "elf"])
    text = output.decode("ascii")
    require(len(re.findall(r"(?m)^otp_target:[ \t]*$", text)) == 1,
            "missing or duplicate helper target group")
    group = text.split("otp_target:", 1)[1]
    values = re.findall(r"(?m)^[ \t]*([a-zA-Z0-9_]+)[ \t]*=[ \t]*(\S+)[ \t]*$", group)
    require(sorted(values) == [("expected_chipid_high", "-1"), ("expected_chipid_low", "-1")],
            "helper target fields are not uniquely unconfigured")
    return fields




def image_metadata(segments, signed):
    image = {}
    for start, contents in segments:
        image.update((start + i, b) for i, b in enumerate(contents))

    def word(address):
        require(address % 4 == 0 and all(address + i in image for i in range(4)),
                "metadata references unmapped bytes")
        return sum(image[address + i] << (i * 8) for i in range(4))

    candidates = [addr for addr in range(FIRMWARE_START, FIRMWARE_START + 4096, 4)
                  if all(addr + i in image for i in range(4)) and word(addr) == 0xffffded3]
    require(candidates, "no first-sector image definition")
    start = candidates[0]
    current, visited, blocks, ends = start, set(), [], []
    while True:
        require(current not in visited and len(visited) < 16, "lollipop or oversized metadata loop")
        visited.add(current)
        require(word(current) == 0xffffded3, "invalid block marker")
        pos, items = current + 4, []
        for _ in range(96):
            header = word(pos)
            typ = header & 255
            size = (header >> 8) & (0xffff if typ & 0x80 else 0xff)
            if typ == 0xff:
                require(size == (pos - current - 4) // 4 and word(pos + 8) == 0xab123579,
                        "invalid metadata terminator")
                delta = struct.unpack("<i", struct.pack("<I", word(pos + 4)))[0]
                break
            require(size and pos + size * 4 <= current + 0x280, "invalid metadata item size")
            items.append((typ, header, [word(pos + 4 * i) for i in range(1, size)], pos))
            pos += size * 4
        else:
            raise ValueError("unterminated metadata block")
        require(items and items[0][0] == 0x42 and all(t != 0x0a for t, _, _, _ in items),
                "partition table or non-image metadata")
        flags = items[0][1] >> 16
        require(flags & 0x773f == 0x1021, "unexpected image type")
        blocks.append(items)
        ends.append(pos + 12)
        current += delta
        if current == start:
            break
    require(len(blocks[0]) == 1 and blocks[0][0][0] == 0x42
            and blocks[0][0][1] == 0x10210142,
            "discovery image definition is not canonical")
    require(len(blocks) == (2 if signed else 1), "unexpected number of image definitions")
    if signed:
        signed_blocks = [items for items in blocks if any(t == 9 for t, _, _, _ in items)]
        require(len(signed_blocks) == 1, "missing or ambiguous signed image")
        items = signed_blocks[0]
        require((items[0][1] >> 16) & 0x800 and
                {3, 0x44} <= {t for t, _, _, _ in items}, "missing signed entry metadata")
        require((blocks[0][0][1] >> 16) & ~0x800 == (items[0][1] >> 16) & ~0x800,
                "discovery and signed image type differ")
        maps = [(header, values, pos) for typ, header, values, pos in items if typ == 6]
        require(len(maps) == 1, "signed image must contain one load map")
        header, values, pos = maps[0]
        count, absolute = (header >> 24) & 0x7f, bool(header & 0x80000000)
        require(len(values) == 3 * count, "malformed load map")
        covered = []
        for i in range(count):
            source, target, size = values[3*i:3*i+3]
            if source:
                if absolute:
                    require(size >= target, "invalid absolute load map")
                    size -= target
                else:
                    source = (source + pos) & 0xffffffff
                require(source + size <= 0x100000000, "load map overflow")
                covered.append((source, source + size))
        require(any(lo <= start and ends[0] <= hi for lo, hi in covered),
                "discovery image definition is not signed")
        vectors = [values for t, _, values, _ in items if t == 3]
        entries = [values for t, _, values, _ in items if t == 0x44]
        require(len(vectors) == 1 and len(vectors[0]) == 1 and len(entries) == 1
                and len(entries[0]) in (2, 3), "invalid vector or entry metadata")
        vector = vectors[0][0]
        require(any(lo <= vector and vector + 8 <= hi for lo, hi in covered),
                "vector table is not signed")
        require(word(vector) == entries[0][1] and word(vector + 4) == entries[0][0],
                "signed entry does not match vector table")
    else:
        require(not any(t == 9 for items in blocks for t, _, _, _ in items), "unsigned image contains signature")


def expected_pages(segments):
    pages = {}
    for address, data in segments:
        for i, byte in enumerate(data):
            target = address + i
            page = target & ~255
            pages.setdefault(page, bytearray(256))[target & 255] = byte
    last = max(pages)
    sectors = {p & ~4095 for p in pages}
    for sector in sectors:
        require(FIRMWARE_START <= sector and sector + 4096 <= FIRMWARE_END,
                "UF2 erase sector outside firmware")
        for page in range(sector, sector + 4096, 256):
            if page < last:
                pages.setdefault(page, bytearray(256))
    return {p: bytes(b) for p, b in pages.items()}


def validate_uf2(path, segments):
    data = bounded_file(path, 4 * 1024 * 1024)
    require(data and len(data) % 512 == 0, "invalid UF2 length")
    count, pages, numbers = len(data) // 512, {}, set()
    for offset in range(0, len(data), 512):
        block = data[offset:offset + 512]
        a, b, flags, address, size, number, total, family = struct.unpack_from("<8I", block)
        require((a, b, flags, size, total, family, struct.unpack_from("<I", block, 508)[0])
                == (0x0a324655, 0x9e5d5157, 0x2000, 256, count, 0xe48bff59, 0x0ab16f30),
                "invalid UF2 header")
        require(number < count and number not in numbers and address % 256 == 0
                and address not in pages and block[288:508] == bytes(220),
                "duplicate, unaligned or noncanonical UF2 block")
        numbers.add(number)
        pages[address] = block[32:288]
    require(pages == expected_pages(segments), "UF2 does not exactly match ELF pages")


def check_picotool():
    output, _ = run(["picotool", "version"])
    require(output.startswith(b"picotool v2.3.1 (")
            and b"without libusb" not in output.lower()
            and b"without usb support" not in output.lower(),
            "picotool 2.3.1 with libusb is required")

def tool_identity():
    path = shutil.which("picotool")
    require(path is not None, "picotool unavailable")
    path = str(Path(path).resolve(strict=True))
    hook = None
    command = [path, "version"]
    if TRACE_HOOK:
        require(Path(TRACE_HOOK).is_file() and os.access(TRACE_HOOK, os.X_OK), "trace hook is not executable")
        hook = {"path": TRACE_HOOK, "sha256": sha256(Path(TRACE_HOOK).read_bytes())}
        command.insert(0, TRACE_HOOK)
    version, loader_log = run(command, extra_env={"LD_DEBUG": "libs", "LD_DEBUG_OUTPUT": None})
    require(version.startswith(b"picotool v2.3.1 (")
            and b"without libusb" not in version.lower()
            and b"without usb support" not in version.lower(),
            "picotool 2.3.1 with libusb is required")
    notes, _ = run(["readelf", "-n", path])
    ids = re.findall(rb"Build ID:\s*([0-9a-fA-F]+)", notes)
    require(len(ids) == 1, "picotool GNU build ID unavailable")
    libraries = re.findall(rb"(?m)^\s*\d+:\s*calling init:\s*(/\S*/libusb-1\.0\.so[^\s]*)\s*$",
                           loader_log)
    require(len(libraries) == 1, "loaded libusb path unavailable")
    library = str(Path(os.fsdecode(libraries[0])).resolve(strict=True))
    package, _ = run(["dpkg-query", "-S", os.fsdecode(libraries[0])])
    names = package.decode().split(": ", 1)
    require(len(names) == 2 and "\n" not in names[0], "libusb package unavailable")
    package_version, _ = run(["dpkg-query", "-W", "-f=${Version}", names[0]])
    require(bool(package_version.strip()), "libusb package version unavailable")
    return {"path": path, "sha256": sha256(Path(path).read_bytes()),
            "build_id": ids[0].decode().lower(), "version": version.decode("utf-8"),
            "provisioner_sha256": sha256(Path(__file__).read_bytes()), "trace_hook": hook,
            "libusb": {"path": library, "sha256": sha256(Path(library).read_bytes()),
                       "package": names[0], "version": package_version.decode().strip()}}


def bind_tool(expected=None):
    global BOUND_TOOL
    identity = tool_identity()
    require(expected is None or identity == expected, "picotool or libusb identity changed")
    BOUND_TOOL = identity
    return identity


def verify_image(path, point):
    segments = elf_segments(path)
    check_picotool()
    image_metadata(segments, True)
    output, _ = run(["picotool", "info", "-a", path, "-t", "elf"])
    text = output.decode("ascii")
    signatures = re.findall(r"(?m)^[ \t]*signature:[ \t]*(\S+)[ \t]*$", text)
    sections = re.split(r"(?m)^Metadata Block [0-9]+[ \t]*$", text)
    signed_sections = [section for section in sections[1:]
                       if re.search(r"(?m)^[ \t]*signature:", section)]
    require(signatures and all(value == "verified" for value in signatures)
            and len(signed_sections) == 1, "missing, incorrect or ambiguous signed metadata")
    signed = signed_sections[0]
    block_signatures = re.findall(r"(?m)^[ \t]*signature:[ \t]*(\S+)[ \t]*$", signed)
    keys = re.findall(r"(?m)^[ \t]*public key:[ \t]*([0-9a-fA-F]+)[ \t]*$", signed)
    require(block_signatures == ["verified"] and len(keys) == 1 and keys[0].lower() == point.hex(),
            "picotool signature or public key mismatch")
    return segments


def manifest_metadata(tag, commit, authority):
    require(type(tag) is str and tag.startswith("v") and len(tag) <= 255
            and all(ord(c) >= 32 and ord(c) != 127 for c in tag), "invalid tag")
    require(type(commit) is str and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit),
            "invalid full commit ID")
    return {"schema_version": 1, "purpose": "pico2-kes-firmware-release-v1",
            "tag": tag, "commit": commit, "profile": PROFILE,
            "bootkey_sha256": authority["bootkey_sha256"],
            "firmware_region": {"start": FIRMWARE_START, "end": FIRMWARE_END},
            "state_region": {"start": FIRMWARE_END, "end": STATE_END},
            "storage_version": 2, "usb_protocol_major": 1}


def verify_bundle(bundle, *, trust=(PRIMARY, SIGNER)):
    bundle = Path(bundle)
    require(bundle.is_dir() and not bundle.is_symlink(), "bundle is not a directory")
    require({p.name for p in bundle.iterdir()} == set(ARTIFACTS) | {"release.json", "release.json.sig"},
            "unexpected or missing bundle files")
    authority = verify_authority(bundle, trust=trust)
    manifest = read_json(bundle / "release.json")
    exact_keys(manifest, (*manifest_metadata("v", "0" * 40, authority), "artifacts"))
    expected = manifest_metadata(manifest["tag"], manifest["commit"], authority)
    for key, value in expected.items():
        if type(value) is dict:
            exact_keys(manifest[key], value)
            require(all(type(manifest[key][k]) is int for k in value), "invalid region field type")
        require(type(manifest[key]) is type(value) and manifest[key] == value, "manifest metadata mismatch")
    entries = manifest["artifacts"]
    require(type(entries) is list and len(entries) == len(ARTIFACTS), "invalid artifact list")
    names = set()
    for entry in entries:
        exact_keys(entry, ("name", "size_bytes", "sha256"))
        name = entry["name"]
        require(type(name) is str and name in ARTIFACTS and name not in names, "invalid artifact name")
        names.add(name)
        data = bounded_file(bundle / name, MAX_ELF)
        require(type(entry["size_bytes"]) is int and entry["size_bytes"] == len(data)
                and type(entry["sha256"]) is str and entry["sha256"] == sha256(data),
                "artifact digest mismatch")
    bounded_file(bundle / "release.json")
    bounded_file(bundle / "release.json.sig")
    run(["openssl", "dgst", "-sha256", "-verify", bundle / PUBLIC_FILES[0],
         "-signature", bundle / "release.json.sig", bundle / "release.json"], failure_code=5)
    validate_policy(read_json(bundle / "otp-policy.json"))
    validate_helper(bundle / "pico2-otp-permissions.elf")
    segments = verify_image(bundle / ARTIFACTS[0], public_point(bundle / PUBLIC_FILES[0]))
    validate_uf2(bundle / ARTIFACTS[1], segments)
    return manifest


def seal(elf, permissions_helper, tag, commit, key_file, out_dir, *,
         authority_dir=None, trust=(PRIMARY, SIGNER)):
    authority_dir = Path(authority_dir) if authority_dir else Path(__file__).resolve().parent.parent / "security"
    authority = verify_authority(authority_dir, trust=trust)
    metadata = manifest_metadata(tag, commit, authority)
    check_picotool()
    key_public, _ = run(["openssl", "pkey", "-in", key_file, "-pubout", "-outform", "DER"])
    require(key_public == SPKI_PREFIX + public_point(authority_dir / PUBLIC_FILES[0]),
            "private key does not match authorized public key")
    image_metadata(elf_segments(elf), False)
    validate_helper(permissions_helper)
    out_dir = Path(out_dir)
    require(not os.path.lexists(out_dir), "output directory already exists")
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".firmware-release-", dir=out_dir.parent) as temp:
        tmp = Path(temp)
        for name in PUBLIC_FILES:
            shutil.copyfile(authority_dir / name, tmp / name)
        shutil.copyfile(authority_dir / "otp-policy.json", tmp / "otp-policy.json")
        shutil.copyfile(Path(__file__), tmp / "firmware.py")
        shutil.copyfile(permissions_helper, tmp / ARTIFACTS[2])
        otp = tmp / "otp.json"
        run(["picotool", "seal", "--sign", elf, "-t", "elf", tmp / ARTIFACTS[0],
             "-t", "elf", key_file, otp])
        otp_values = read_json(otp)["bootkey0"]
        require(type(otp_values) is list and len(otp_values) == 32
                and all(type(x) is int and 0 <= x <= 255 for x in otp_values)
                and bytes(otp_values).hex() == authority["bootkey_sha256"],
                "picotool OTP key fingerprint mismatch")
        otp.unlink()
        run(["picotool", "uf2", "convert", tmp / ARTIFACTS[0], tmp / ARTIFACTS[1],
             "--platform", "rp2350"])
        metadata["artifacts"] = [{"name": name, "size_bytes": len(data), "sha256": sha256(data)}
                                 for name in ARTIFACTS
                                 for data in [bounded_file(tmp / name, MAX_ELF)]]
        (tmp / "release.json").write_bytes(json.dumps(metadata, indent=2).encode() + b"\n")
        run(["openssl", "dgst", "-sha256", "-sign", key_file, "-out", tmp / "release.json.sig",
             tmp / "release.json"])
        verify_bundle(tmp, trust=trust)
        os.rename(tmp, out_dir)
    return metadata


def selected_usb_board(sysfs=Path("/sys/bus/usb/devices")):
    """Find one application or ROM device without trusting a BOOTSEL serial."""
    boards = []
    for entry in sysfs.iterdir():
        try:
            vendor = (entry / "idVendor").read_text(encoding="ascii").strip()
            product = (entry / "idProduct").read_text(encoding="ascii").strip()
        except FileNotFoundError:
            continue
        if (vendor, product) not in (("1209", "4b45"), ("2e8a", "000f"), ("2e8a", "0003")):
            continue
        try:
            bus = int((entry / "busnum").read_text(encoding="ascii").strip())
            address = int((entry / "devnum").read_text(encoding="ascii").strip())
        except (ValueError, FileNotFoundError) as error:
            raise ToolError("USB enumeration changed during discovery", 4) from error
        require(0 <= bus <= 255 and 1 <= address <= 127, "invalid USB bus/address")
        boards.append((vendor, product, bus, address))
    if not boards:
        raise ToolError("no application or BOOTSEL device found", 4)
    require(len(boards) == 1, "multiple candidate boards attached")
    return boards[0]


def parse_bootsel_info(data, serial):
    text = data.decode("ascii")
    require(len(text) <= 65536 and "\x00" not in text, "invalid picotool output")
    allowed = {"type", "revision", "package", "chipid", "flash devinfo", "current cpu",
               "available cpus", "default cpu", "secure boot", "debug enable", "secure debug enable",
               "boot_random", "boot type", "last booted partition", "explicit buy pending",
               "other slot/partition erased", "OTP version applied", "diagnostic source",
               "last boot diagnostics", "reboot param 0", "reboot param 1", "rom gitrev", "flash size"}
    seen = set()
    for line in text.splitlines():
        if not line.strip() or line.strip() == "Device Information":
            continue
        pair = re.fullmatch(r"[ \t]+([^:\n]+):[ \t]*(.*)", line)
        require(pair is not None and pair[1] in allowed and pair[1] not in seen,
                "unexpected or duplicate picotool device field")
        seen.add(pair[1])
    def field(name):
        matches = re.findall(r"(?m)^[ \t]*" + re.escape(name) + r":[ \t]*(.*?)[ \t]*$", text)
        require(len(matches) == 1, "missing or duplicate picotool " + name)
        return matches[0]
    require(field("type") in ("RP2350", "RP2350(64k)"), "unsupported BOOTSEL device")
    chipid = field("chipid")
    require(re.fullmatch(r"0x[0-9a-f]{16}", chipid) is not None
            and chipid[2:] == serial, "BOOTSEL CHIPID differs from selected serial")
    secure = field("secure boot")
    require(secure in ("0", "1"), "invalid picotool secure boot value")
    stepping = field("revision")
    require(stepping in ("A2", "A4"), "unsupported silicon revision")
    require(field("current cpu") == "ARM" and "ARM" in field("available cpus").split(", "),
            "Arm architecture unavailable")
    if "default cpu" in seen:
        require(field("default cpu") == "ARM", "conflicting default architecture")
    return {"mode": "bootsel", "usb_serial": serial, "chipid": chipid[2:],
            "secure_boot": secure == "1", "fitted_flash": "unavailable",
            "stepping": stepping}


def inspect_device(serial, *, sysfs=Path("/sys/bus/usb/devices"),
                   config=Path("/etc/pico2-kes-agent/config.json")):
    require(re.fullmatch(r"[0-9a-f]{16}", serial) is not None, "invalid device serial")
    vendor, product, bus, address = selected_usb_board(sysfs)
    if (vendor, product) == ("2e8a", "0003"):
        raise ValueError("RP2040 is not supported")
    if (vendor, product) == ("2e8a", "000f"):
        check_picotool()
        data, _ = run(["picotool", "info", "--device", "--debug", "--bus", str(bus),
                       "--address", str(address)], failure_code=4)
        result = parse_bootsel_info(data, serial)
        result.update({"bus": bus, "address": address})
        return result
    if not config.exists():
        raise ToolError("installed daemon configuration/application report unavailable", 4)
    configuration = read_json(config)
    require(type(configuration) is dict and type(configuration.get("device")) is dict
            and configuration["device"].get("usb_serial") == serial,
            "daemon configuration does not select this serial")
    data, _ = run(["pico2-kes-agent-cli", "--json", "device", "security"], failure_code=4)
    envelope = json.loads(data, object_pairs_hook=unique_object)
    require(type(envelope) is dict and type(envelope.get("result")) is dict,
            "invalid security response")
    report = envelope["result"]
    require(report.get("usb_serial") == serial, "security report serial mismatch")
    return {"mode": "application", "usb_serial": serial, "security": report}

FLAG0_BITS = {
    "DISABLE_BOOTSEL_USB_PICOBOOT_IFC": 18, "DISABLE_BOOTSEL_UART_BOOT": 19,
    "DISABLE_SRAM_WINDOW_BOOT": 21, "DISABLE_OTP_BOOT": 13,
    "DISABLE_WATCHDOG_SCRATCH": 16, "DISABLE_POWER_SCRATCH": 15,
    "DISABLE_AUTO_SWITCH_ARCH": 8, "SINGLE_FLASH_BINARY": 7,
}
REQUIRED_FLAGS0 = sum(1 << bit for bit in FLAG0_BITS.values())
FORBIDDEN_FLAGS0 = (1 << 17) | (1 << 14) | (1 << 12) | (1 << 11) | (1 << 6)
PUBLIC_ROWS = tuple(range(0x40, 0x4e)) + tuple(range(0x80, 0xc0)) + (
    0xf82, 0xf83, 0xf84, 0xf85, 0xffc, 0xffd, 0xffe, 0xfff)


def attended(serial, description):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ToolError("applying stages require an interactive terminal", 3)
    print(description)
    require(input(f"Type the exact device serial {serial}: ").strip() == serial,
            "device confirmation did not match")


def pause(description):
    if not sys.stdin.isatty():
        raise ToolError("attended physical transition requires a terminal", 3)
    input(description + "\nPress Enter only after completing this transition: ")


def application_report(serial, *, blank=False, expected=None,
                       config=Path("/etc/pico2-kes-agent/config.json")):
    if not config.exists():
        raise ToolError("installed daemon configuration/application report unavailable", 4)
    selected = read_json(config)
    require(type(selected.get("device")) is dict
            and selected["device"].get("usb_serial") == serial, "daemon selects another device")
    if blank:
        require(set(selected["device"]) == {"usb_serial"} and selected.get("pools") == [],
                "initial provisioning requires the commissioning configuration")
    data, _ = run(["pico2-kes-agent-cli", "--json", "device", "security"], failure_code=4)
    envelope = json.loads(data, object_pairs_hook=unique_object)
    require(type(envelope) is dict and envelope.get("outcome") == "success"
            and envelope.get("error") is None, "application security unavailable")
    report = envelope.get("result")
    integer8 = ("chip_revision", "rom_version", "page2_lock0", "page2_lock1",
                "page63_lock0", "page63_lock1")
    integer32 = ("critical", "boot_flags0", "boot_flags1", "debugen", "debugen_lock",
                 "density_bits_minus_one")
    exact_keys(report, (*integer8, *integer32, "bootkey0", "redundancy_ok", "jedec_id",
                        "sfdp_header", "usb_serial", "storage_blank_at_boot", "profile", "stepping"))
    for names, maximum in ((integer8, 255), (integer32, 0xffffffff)):
        require(all(type(report[k]) is int and 0 <= report[k] <= maximum for k in names),
                "invalid security integer")
    for name, length in (("bootkey0", 64), ("jedec_id", 6), ("sfdp_header", 32), ("usb_serial", 16)):
        require(type(report[name]) is str and re.fullmatch(f"[0-9a-f]{{{length}}}", report[name]),
                "invalid security hexadecimal field")
    require(type(report["redundancy_ok"]) is bool and type(report["storage_blank_at_boot"]) is bool,
            "invalid security boolean")
    require(report["usb_serial"] == serial and report["stepping"] == {2: "A2", 4: "A4"}.get(report["rom_version"])
            and report["redundancy_ok"], "unsupported stepping, identity or incomplete redundancy")
    require(report["jedec_id"] == "ef4016" and report["sfdp_header"] == "534644500a0100ff00080117800000ff"
            and report["density_bits_minus_one"] == 0x1ffffff, "unapproved fitted flash")
    require(report["profile"] in ("unlocked", "incomplete", PROFILE), "invalid security profile")
    def locked_page(prefix):
        value = report[prefix + "_lock1"]
        return report[prefix + "_lock0"] == 0 and value & 0xc0 == 0 and value & 3 == 1 \
            and ((value >> 2) & 3) in (1, 3) and ((value >> 4) & 3) in (1, 3)
    locked = expected is not None and report["bootkey0"] == expected \
        and report["critical"] & 0x1000f == 7 \
        and report["boot_flags0"] & REQUIRED_FLAGS0 == REQUIRED_FLAGS0 \
        and report["boot_flags0"] & FORBIDDEN_FLAGS0 == 0 \
        and report["boot_flags1"] & 0xf0f == 0xe01 \
        and locked_page("page2") and locked_page("page63") \
        and report["debugen"] & 0x10f == 0 and report["debugen_lock"] & 0x10f == 0x10f
    classification = "unlocked" if report["critical"] & 1 == 0 else PROFILE if locked else "incomplete"
    require(report["profile"] == classification, "forged or incomplete profile classification")
    if expected is not None:
        require(report["bootkey0"] == expected, "application boot authority mismatch")
    if blank:
        require(report["storage_blank_at_boot"] is True, "state was not wholly blank at boot")
        status_data, _ = run(["pico2-kes-agent-cli", "--json", "status"], failure_code=4)
        status_envelope = json.loads(status_data, object_pairs_hook=unique_object)
        require(status_envelope.get("outcome") == "success"
                and status_envelope.get("result", {}).get("commissioning_state") == "blank",
                "device is not still uncommissioned")
    return report


def parse_public_rows(data, rows):
    text = data.decode("ascii")
    result = {}
    chunks = re.split(r"(?m)^ROW ", text)
    require(not chunks[0].strip() and len(chunks) - 1 == len(rows), "unexpected OTP output")
    for chunk in chunks[1:]:
        lines = [line.strip() for line in chunk.splitlines() if line.strip()]
        match = re.fullmatch(r"0x([0-9a-f]{4})(?:: OTP_DATA_[A-Z0-9_]+(?: \([^()\n]+\))*)?", lines[0])
        require(match is not None, "unexpected OTP row header")
        row = int(match[1], 16)
        require(row in rows and row not in result and len(lines) >= 2, "unexpected or duplicate OTP row")
        value = re.fullmatch(r"VALUE 0x([0-9a-f]{4}|[0-9a-f]{6})", lines[1])
        require(value is not None, "OTP read warning, error or malformed value")
        require(all(re.fullmatch(r"field [A-Z0-9_]+ \(bits? [0-9]+(?:-[0-9]+)?\) = [0-9a-f]+", line)
                    for line in lines[2:]), "unexpected OTP read output")
        result[row] = int(value[1], 16)
    require(set(result) == set(rows), "incomplete public OTP read")
    return result


class Board:
    """Every ROM operation reselects and checks the public CHIPID first."""
    def __init__(self, serial):
        require(re.fullmatch("[0-9a-f]{16}", serial) is not None, "invalid selected serial")
        self.serial = serial

    def identify(self):
        vendor, product, bus, address = selected_usb_board()
        require((vendor, product) == ("2e8a", "000f"), "physically enter RP2350 BOOTSEL first")
        selection = ["--bus", str(bus), "--address", str(address)]
        data, _ = run(["picotool", "info", "--device", "--debug", *selection], failure_code=4)
        info = parse_bootsel_info(data, self.serial)
        revisions = re.findall(rb"(?m)^[ \t]*revision:[ \t]*(\S+)[ \t]*$", data)
        require(revisions in ([b"A2"], [b"A4"]), "unsupported or unavailable silicon revision")
        info["stepping"] = revisions[0].decode()
        info["selection"] = selection
        return info

    def command(self, *arguments, selectors=()):
        info = self.identify()
        if ACTIVE_ACTION is not None and arguments[:2] == ("otp", "set") or (
                ACTIVE_ACTION is not None and arguments[0] in ("load", "erase", "reboot")):
            active = ACTIVE_ACTION
            try:
                globals()["ACTIVE_ACTION"] = None
                bind_tool(BOUND_TOOL)
            finally:
                globals()["ACTIVE_ACTION"] = active
        # OTP get's repeatable selectors consume trailing options in picotool
        # 2.3.1, so device selection must precede those selectors.
        return run(["picotool", *arguments, *info["selection"], *selectors], failure_code=4)[0]

    def raw_row(self, row):
        require(row in PUBLIC_ROWS and not 0x80 <= row < 0xc0, "non-public raw row")
        return parse_public_rows(self.command("otp", "get", "-c", "1", "-r", "-n",
                                              selectors=(hex(row),)), (row,))[row]

    def snapshot(self):
        # Whitelisted public rows only; never invoke otp dump or read RANDID.
        raw_rows = tuple(row for row in PUBLIC_ROWS if not 0x80 <= row < 0xc0)
        raw = parse_public_rows(self.command("otp", "get", "-c", "1", "-r", "-n",
                                            selectors=tuple(hex(row) for row in raw_rows)), raw_rows)
        key_rows = tuple(range(0x80, 0xc0))
        keys = parse_public_rows(self.command("otp", "get", "-c", "1", "-e", "-n",
                                             selectors=tuple(hex(row) for row in key_rows)), key_rows)
        require(all(value <= 0xffff for value in keys.values()), "invalid ECC boot key")
        info = self.identify()
        return {"stepping": info["stepping"], "secure_boot": info["secure_boot"],
                "rows": {f"{row:04x}": value for row, value in sorted({**raw, **keys}.items())}}


def lock_byte(raw):
    require(type(raw) is int and 0 <= raw <= 0xffffff, "invalid lock word")
    value = raw & 255
    require(raw == value * 0x010101, "incomplete page-lock redundancy")
    return value


def public_policy(snapshot, expected, stage):
    rows = {int(row, 16): value for row, value in snapshot["rows"].items()}
    require(set(rows) == set(PUBLIC_ROWS) and snapshot["stepping"] in ("A2", "A4"),
            "incomplete public snapshot")
    for start, count in ((0x40, 8), (0x48, 3), (0x4b, 3)):
        require(all(rows[start + i] == rows[start] for i in range(count)), "incomplete OTP redundancy")
    critical, flags0, flags1 = rows[0x40], rows[0x48], rows[0x4b]
    require(critical & ~7 == 0 and bool(critical & 1) == snapshot["secure_boot"],
            "conflicting critical architecture/glitch flags")
    require(flags0 & ~REQUIRED_FLAGS0 == 0 and flags0 & FORBIDDEN_FLAGS0 == 0,
            "conflicting boot paths")
    require(flags1 & ~0xe01 == 0, "unexpected alternate boot authority")
    hashes = [b"".join(rows[0x80 + slot * 16 + i].to_bytes(2, "little")
                       for i in range(16)).hex() for slot in range(4)]
    require(all(key == "00" * 32 for key in hashes[1:]), "unexpected alternate boot keys")
    require(hashes[0] in ("00" * 32, expected), "unexpected or partial slot-0 hash")
    for page, row in ((1, 0xf82), (2, 0xf84), (62, 0xffc), (63, 0xffe)):
        require(lock_byte(rows[row]) == 0, f"page {page} has access keys or RMA enabled")
        permissions = lock_byte(rows[row + 1])
        require(permissions & 0xc0 == 0 and all(((permissions >> shift) & 3) != 2 for shift in (0, 2, 4)),
                "reserved or conflicting page permissions")
        if page in (1, 62):
            require(permissions & 3 == 0, "flag/permission rows cannot be programmed")
        elif stage == "prepare":
            require(permissions & 3 == 0, "page already Secure-locked; do not replay helper")
        else:
            require(permissions & 3 == 1 and ((permissions >> 2) & 3) in (1, 3)
                    and ((permissions >> 4) & 3) in (1, 3), "preparation page locks not complete")
    if stage != "prepare":
        require(hashes[0] == expected and flags1 == 0xe01, "preparation authority not complete")
    require(critical == (1 if stage == "lock" else 0), "wrong stage or partial critical programming")
    require(flags0 == 0, "interface restrictions already programmed; no automatic repair")
    return rows


def owner_record(path, *, expected_pending=None):
    metadata = Path(path).lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o077 == 0, "record must be an owner-only regular file")
    record = json.loads(bounded_file(path, MAX_RECORD), object_pairs_hook=unique_object)
    exact_keys(record, ("schema_version", "serial", "profile", "bundle_sha256", "bootkey_sha256",
                        "tool_identity", "completed_stage", "pending", "observations", "actions"))
    require(record["schema_version"] == 2 and record["profile"] == PROFILE
            and type(record["observations"]) is list and type(record["actions"]) is list
            and (record["pending"] is None if expected_pending is None else
                 type(record["pending"]) is dict and record["pending"].get("step") == expected_pending),
            "incomplete/uncertain record; diagnose fresh readback before any further writes")
    return record


def save_record(path, record, *, create=False):
    path = Path(path)
    require(path.parent.is_dir() and not path.is_symlink(), "invalid record path")
    payload = json.dumps(record, indent=2).encode() + b"\n"
    require(len(payload) <= MAX_RECORD, "provisioning record exceeds evidence budget")
    fd, temp = tempfile.mkstemp(prefix=".provision-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if create:
            os.link(temp, path)
        else:
            require(path.lstat().st_uid == os.geteuid() and not path.is_symlink(), "record ownership changed")
            os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def record_action(path, record, label, operation, observe, expected, intended):
    global WRITES_ATTEMPTED, ACTIVE_ACTION, ACTIVE_CHECKPOINT
    require(record["pending"] is None, "uncertain operation cannot be replayed or overwritten")
    require(len(json.dumps(record, indent=2).encode()) + ACTION_RESERVE <= MAX_RECORD,
            "record evidence budget exhausted before action; preserve record")
    bind_tool(record["tool_identity"])
    action = {"step": label, "state": "pending", "started_ns": time.time_ns(),
              "intended": intended, "expected": expected, "processes": []}
    record["pending"] = action
    save_record(path, record)
    WRITES_ATTEMPTED = True
    ACTIVE_ACTION = action["processes"]
    ACTIVE_CHECKPOINT = lambda: save_record(path, record)
    try:
        operation()
        observation = observe()
        action["observed"] = observation
        require(observation == expected, "physical postcondition mismatch")
        action["finished_ns"] = time.time_ns()
        action["state"] = "verified"
        record["observations"].append({"step": label, "public": observation})
        record["actions"].append(action)
        record["pending"] = None
        save_record(path, record)
        return observation
    except BaseException as error:
        record["pending"] = action
        if record["actions"] and record["actions"][-1] is action:
            record["actions"].pop()
        if record["observations"] and record["observations"][-1].get("step") == label:
            record["observations"].pop()
        action["state"] = "uncertain"
        action["finished_ns"] = time.time_ns()
        action["error_type"] = type(error).__name__
        try:
            save_record(path, record)
        finally:
            raise ToolError(f"{label}: potentially applied write; preserve record and diagnose, do not replay",
                            write_happened=True) from error
    finally:
        ACTIVE_ACTION = None
        ACTIVE_CHECKPOINT = None


def program_group(path, record, board, name, start, count, target):
    before = board.snapshot()
    values = [before["rows"][f"{start + i:04x}"] for i in range(count)]
    require(len(set(values)) == 1, "unequal redundant group; no automatic repair")
    require(values[0] & ~target == 0, "redundant group conflicts with policy")
    for index in range(count):
        row = start + index
        wanted = {"row": row, "value": target}
        record_action(path, record, f"{name}_{index}",
                      lambda row=row: board.command("otp", "set", "-c", "1", "-r",
                                                    hex(row), hex(target)),
                      lambda row=row: {"row": row, "value": board.raw_row(row)},
                      wanted, {"register": name, "row": row, "physical_copies": 1,
                               "raw_target": target, "payload_le": struct.pack("<I", target).hex(),
                               "postcondition": wanted})
    expected_snapshot = {**before, "rows": dict(before["rows"])}
    for index in range(count):
        expected_snapshot["rows"][f"{start + index:04x}"] = target
    expected = {"copies": [target] * count, "vote": target, "snapshot": expected_snapshot}
    def observe_group():
        snap = board.snapshot()
        copies = [snap["rows"][f"{start + i:04x}"] for i in range(count)]
        threshold = 3 if count == 8 else 2
        vote = sum(1 << bit for bit in range(24)
                   if sum(bool(value & (1 << bit)) for value in copies) >= threshold)
        return {"copies": copies, "vote": vote, "snapshot": snap}
    record_action(path, record, name + "_group_readback", lambda: None, observe_group, expected,
                  {"operation": "independent redundant readback", "register": name,
                   "start_row": start, "physical_copies": count, "raw_target": target})


def bind_helper(original, configured, serial):
    offsets = validate_helper(original)
    before = bounded_file(original, MAX_ELF)
    shutil.copyfile(original, configured)
    chipid = int(serial, 16)
    for field, value in (("expected_chipid_low", chipid & 0xffffffff),
                         ("expected_chipid_high", chipid >> 32)):
        signed = value if value < 0x80000000 else value - 0x100000000
        run(["picotool", "config", "-g", "otp_target", "-s", field, str(signed), configured, "-t", "elf"])
    after = bounded_file(configured, MAX_ELF)
    require(len(before) == len(after), "helper configuration changed file size")
    expected = bytearray(before)
    for field, value in (("expected_chipid_low", chipid & 0xffffffff),
                         ("expected_chipid_high", chipid >> 32)):
        struct.pack_into("<I", expected, offsets[field], value)
    require(after == expected, "helper configuration changed non-target bytes")
    elf_segments(configured, helper=True)


def msd_copy(serial, bundle, *, picoboot_available):
    pause("Stop the commissioning daemon. Hold BOOTSEL while reconnecting this exact board; mount its USB mass-storage volume.")
    vendor, product, bus, address = selected_usb_board()
    require((vendor, product) == ("2e8a", "000f"), "RP2350 BOOTSEL volume not present")
    if picoboot_available:
        Board(serial).identify()
    volume = Path(input("Absolute RP2350 mass-storage mount path: ").strip())
    require(volume.is_absolute() and volume.is_dir() and not volume.is_symlink(), "invalid mass-storage mount")
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[4].replace("\\040", " ") == str(volume.resolve()):
            matches.append(fields[2])
    require(len(matches) == 1, "path is not a distinct mounted volume")
    block_path = (Path("/sys/dev/block") / matches[0]).resolve(strict=True)
    candidates = []
    for entry in Path("/sys/bus/usb/devices").iterdir():
        try:
            if int((entry / "busnum").read_text()) == bus and int((entry / "devnum").read_text()) == address:
                candidates.append(entry.resolve())
        except FileNotFoundError:
            pass
    require(len(candidates) == 1 and candidates[0] in block_path.parents, "volume belongs to another USB device")
    info = bounded_file(volume / "INFO_UF2.TXT", 4096).decode("ascii")
    require(re.search(r"(?m)^Board-ID: RP2350[ \r]*$", info), "volume is not an RP2350 bootloader")
    if not picoboot_available:
        classes = []
        for entry in Path("/sys/bus/usb/devices").iterdir():
            if entry.name.startswith(candidates[0].name + ":"):
                classes.append((entry / "bInterfaceClass").read_text().strip())
        require("08" in classes and "ff" not in classes, "MSD missing or PICOBOOT vendor interface remains")
        return {"msd_interface": True, "picoboot_interface": False}
    source = bounded_file(Path(bundle) / ARTIFACTS[1], 4 * 1024 * 1024)
    with (volume / ARTIFACTS[1]).open("wb") as output:
        output.write(source)
        output.flush()
        os.fsync(output.fileno())
    return {"uf2_sha256": sha256(source), "mounted_device": matches[0]}


def _prepare_resume_record(record_path, serial, bundle, manifest):
    record = owner_record(record_path)
    require(record["serial"] == serial
            and record["bundle_sha256"] == sha256(bounded_file(Path(bundle) / "release.json"))
            and record["bootkey_sha256"] == manifest["bootkey_sha256"],
            "resume target, authority or bundle mismatch")
    require(record["completed_stage"] is None and len(record["observations"]) == 2,
            "resume is limited to completed firmware installation before any OTP write")
    preflight, installed = record["observations"]
    for observation in (preflight, installed):
        exact_keys(observation, ("step", "public"))
    require(preflight["step"] == "public_preparation_preflight"
            and installed["step"] == "install_signed_firmware",
            "resume refuses any OTP action or different preparation checkpoint")
    elf_digest = next(item["sha256"] for item in manifest["artifacts"]
                      if item["name"] == ARTIFACTS[0])
    require(installed["public"] == {"elf_sha256": elf_digest},
            "recorded firmware installation differs from the verified bundle")
    before = preflight["public"]
    public_policy(before, manifest["bootkey_sha256"], "prepare")
    require(before["secure_boot"] is False, "resume requires pre-enable preparation")
    bind_tool(record["tool_identity"])
    return record, before


def provision(stage, serial, bundle, record_path, apply=False, *, resume=False):
    global WRITES_ATTEMPTED
    WRITES_ATTEMPTED = False
    if resume and (stage != "prepare" or not apply):
        raise ToolError("--resume requires --stage prepare --apply", 2)
    manifest = verify_bundle(bundle)
    expected = manifest["bootkey_sha256"]
    policy = validate_policy(read_json(Path(bundle) / "otp-policy.json"))
    checkpoint = _prepare_resume_record(record_path, serial, bundle, manifest) if resume else None
    if not apply:
        try:
            report = inspect_device(serial)
        except ToolError as error:
            if error.code != 4:
                raise
            report = {"mode": "unavailable", "reason": str(error)}
        if report["mode"] == "bootsel":
            snapshot = Board(serial).snapshot()
            public_policy(snapshot, expected, stage)
            report["public_otp"] = snapshot
        fields = {key: value for key, value in policy["fields"].items()
                  if (stage == "prepare" and key.startswith("BOOT_FLAGS1."))
                  or (stage == "enable" and key == "CRIT1.SECURE_BOOT_ENABLE")
                  or (stage == "lock" and (key.startswith("BOOT_FLAGS0.") and value == 1
                                          or key in ("CRIT1.DEBUG_DISABLE", "CRIT1.SECURE_DEBUG_DISABLE")))}
        return {"apply": False, "stage": stage, "device": report,
                "intended_fields": fields, "page_locks": policy["page_locks"] if stage == "prepare" else {},
                "bootkey_sha256": expected, "state_erasure": False,
                "application_admission": "unobserved" if report["mode"] != "application" else "must-be-rechecked-before-writes"}
    attended(serial, f"IRREVERSIBLE {stage}: only {PROFILE}; never erase state automatically.")
    observed = inspect_device(serial)
    if resume:
        require(observed["mode"] == "application"
                and observed["security"].get("profile") == "unlocked",
                "resume requires the selected unlocked application and commissioning daemon")
    if observed["mode"] == "application" and observed["security"].get("profile") == PROFILE:
        report = application_report(serial, expected=expected)
        require(report["profile"] == PROFILE, "locked application policy differs")
        return {"already_provisioned": True, "security": report, "writes": False}
    if stage == "prepare":
        board = Board(serial)
        if resume:
            record, before = checkpoint
        else:
            require(not os.path.lexists(record_path), "preparation record exists; do not replay partial programming")
            pause("Stop the daemon and physically enter BOOTSEL on the selected board.")
            before = board.snapshot()
            public_policy(before, expected, stage)
            identity = bind_tool()
            record = {"schema_version": 2, "serial": serial, "profile": PROFILE,
                      "bundle_sha256": sha256(bounded_file(Path(bundle) / "release.json")),
                      "bootkey_sha256": expected, "tool_identity": identity,
                      "completed_stage": None, "pending": None, "actions": [],
                      "observations": [{"step": "public_preparation_preflight", "public": before}]}
            save_record(record_path, record, create=True)
            elf_digest = next(item["sha256"] for item in manifest["artifacts"] if item["name"] == ARTIFACTS[0])
            def observe_install():
                board.command("verify", Path(bundle) / ARTIFACTS[0], "-t", "elf")
                return {"elf_sha256": elf_digest}
            record_action(record_path, record, "install_signed_firmware",
                          lambda: board.command("load", "-v", Path(bundle) / ARTIFACTS[0], "-t", "elf"),
                          observe_install, {"elf_sha256": elf_digest},
                          {"operation": "load firmware", "elf_sha256": elf_digest})
        pause("Start the installed daemon in commissioning mode with the selected serial and empty pools; leave BOOTSEL and start the signed application. No commissioning mutation.")
        report = application_report(serial, blank=True)
        require(report["critical"] & 1 == 0, "secure boot unexpectedly enabled")
        record["observations"].append({"step": "blank_signed_application", "public": report})
        save_record(record_path, record)
        pause("Stop the commissioning daemon, then physically enter BOOTSEL again.")
        require(board.snapshot() == before, "public OTP changed since blank admission")
        if resume:
            board.command("verify", Path(bundle) / ARTIFACTS[0], "-t", "elf")
            record["observations"].append({"step": "resume_signed_image_verified",
                                           "public": record["observations"][1]["public"]})
            save_record(record_path, record)
        digest = bytes.fromhex(expected)
        for index in range(16):
            value = int.from_bytes(digest[2 * index:2 * index + 2], "little")
            wanted = {"row": 0x80 + index, "value": value}
            record_action(record_path, record, f"bootkey0_{index}",
                          lambda index=index, value=value: board.command("otp", "set", f"BOOTKEY0_{index}", hex(value)),
                          lambda index=index: {"row": 0x80 + index,
                                               "value": board.snapshot()["rows"][f"{0x80 + index:04x}"]},
                          wanted, {"register": f"BOOTKEY0_{index}", "row": 0x80 + index,
                                   "physical_copies": 1, "raw_target": value, "postcondition": wanted})
        flags1 = policy["fields"]["BOOT_FLAGS1.KEY_VALID"] | (policy["fields"]["BOOT_FLAGS1.KEY_INVALID"] << 8)
        program_group(record_path, record, board, "BOOT_FLAGS1", 0x4b, 3, flags1)
        ready = board.snapshot()
        public_policy(ready, expected, "prepare")
        require(all(ready["rows"][f"{0x4b+i:04x}"] == 0xe01 for i in range(3)),
                "boot-key mask readback incomplete; do not lock authority pages")
        with tempfile.TemporaryDirectory(prefix="pico2-bound-helper-") as temp:
            helper = Path(temp) / "permissions.elf"
            bind_helper(Path(bundle) / ARTIFACTS[2], helper, serial)
            permissions_expected = {**ready, "rows": dict(ready["rows"])}
            for row in ("0f85", "0fff"):
                permissions_expected["rows"][row] = (lock_byte(ready["rows"][row]) | 0x15) * 0x010101
            record_action(record_path, record, "page2_page63_permissions",
                          lambda: board.command("load", "-v", "-x", helper, "-t", "elf"),
                          board.snapshot, permissions_expected,
                          {"operation": "permission helper", "rows": ["0f85", "0fff"],
                           "physical_copies": 3, "helper_sha256": sha256(bounded_file(helper, MAX_ELF)),
                           "raw_targets": {row: permissions_expected["rows"][row] for row in ("0f85", "0fff")},
                           "postcondition": permissions_expected})
    else:
        record = owner_record(record_path)
        bind_tool(record["tool_identity"])
        require(record["serial"] == serial and record["bootkey_sha256"] == expected
                and record["bundle_sha256"] == sha256(bounded_file(Path(bundle) / "release.json")),
                "record target, authority or bundle mismatch")
        require(record["completed_stage"] == {"enable": "prepare", "lock": "enable"}[stage],
                "stage prerequisites not observed; do not replay")
        observed_steps = {item.get("step") for item in record["observations"] if type(item) is dict}
        required_steps = {"page2_page63_permissions"} if stage == "enable" else {
            "secure_signed_startup", "signed_msd_reinstall", "signed_msd_reinstall_startup"}
        require(required_steps <= observed_steps, "record lacks prerequisite observed substeps")
        pause("Stop the commissioning daemon and physically enter BOOTSEL on the selected board.")
        board = Board(serial)
        public_policy(board.snapshot(), expected, stage)
        board.command("verify", Path(bundle) / ARTIFACTS[0], "-t", "elf")
        if stage == "enable":
            program_group(record_path, record, board, "CRIT1_ENABLE", 0x40, 8,
                          policy["fields"]["CRIT1.SECURE_BOOT_ENABLE"])
            startup = {}
            def observe_startup():
                pause("Start the commissioning daemon after signed application startup.")
                startup.update(application_report(serial, blank=True, expected=expected))
                return {"secure_boot": startup["critical"] & 1}
            record_action(record_path, record, "signed_boot_reboot",
                          lambda: board.command("reboot", "-a"), observe_startup,
                          {"secure_boot": 1}, {"operation": "reboot", "postcondition": {"secure_boot": 1}})
            record["observations"].append({"step": "secure_signed_startup", "public": dict(startup)})
            save_record(record_path, record)
            startup.clear()
            def observe_reinstall():
                pause("Re-enter BOOTSEL on the selected board for read-only verification of the reinstalled image.")
                board.command("verify", Path(bundle) / ARTIFACTS[0], "-t", "elf")
                pause("Leave BOOTSEL, start the signed application and restart the commissioning daemon.")
                startup.update(application_report(serial, blank=True, expected=expected))
                return {"secure_boot": startup["critical"] & 1, "image_verified": True}
            record_action(record_path, record, "signed_msd_reinstall",
                          lambda: msd_copy(serial, bundle, picoboot_available=True),
                          observe_reinstall, {"secure_boot": 1, "image_verified": True},
                          {"operation": "MSD firmware copy",
                           "uf2_sha256": sha256(bounded_file(Path(bundle) / ARTIFACTS[1], 4 * 1024 * 1024)),
                           "postcondition": {"secure_boot": 1, "image_verified": True}})
            record["observations"].append({"step": "signed_msd_reinstall_startup", "public": dict(startup)})
            save_record(record_path, record)
        else:
            flags0 = sum((1 << bit) * policy["fields"]["BOOT_FLAGS0." + name]
                         for name, bit in FLAG0_BITS.items())
            critical = (policy["fields"]["CRIT1.SECURE_BOOT_ENABLE"]
                        | (policy["fields"]["CRIT1.DEBUG_DISABLE"] << 2)
                        | (policy["fields"]["CRIT1.SECURE_DEBUG_DISABLE"] << 1))
            program_group(record_path, record, board, "BOOT_FLAGS0", 0x48, 3, flags0)
            program_group(record_path, record, board, "CRIT1_LOCK", 0x40, 8, critical)
            expected_final = record["observations"][-1]["public"]["snapshot"]
            record_action(record_path, record, "final_rom_readback", lambda: None, board.snapshot,
                          expected_final, {"operation": "independent final policy readback",
                                           "postcondition": expected_final})
            pause("Cold power-cycle the exact board; do not use picotool again. Start the commissioning daemon and query the application.")
            report = application_report(serial, blank=True, expected=expected)
            require(report["profile"] == PROFILE, "final profile/debug locks not observed")
            record["observations"].append({"step": "cold_boot_locked_application", "public": report})
            save_record(record_path, record)
            interfaces = msd_copy(serial, bundle, picoboot_available=False)
            record["observations"].append({"step": "physical_msd_without_picoboot", "public": interfaces})
            print("Reconnect in application mode; commission with fresh receipts/pin using the existing attended workflow. No picotool access remains.")
    record["completed_stage"] = stage
    save_record(record_path, record)
    print({"prepare": "Next: --stage enable; keep the same record/bundle and commissioning configuration.",
           "enable": "Next: --stage lock only after reviewing the observed signed startup and MSD reinstall.",
           "lock": "Provisioning complete; commission operational identity and pools only now."}[stage])
    return record


def erase_state(serial, record_path, apply):
    global WRITES_ATTEMPTED
    WRITES_ATTEMPTED = False
    require(apply is True, "erase-state requires explicit --apply")
    attended(serial, "DESTRUCTIVE initial conversion only: export required artifacts, archive public records, stop/fence producers. This is not secure erasure or revocation. Erase only [0x10100000,0x10308000); never an update/recovery step.")
    require(not os.path.lexists(record_path), "erase record already exists; do not replay")
    board = Board(serial)
    before = board.snapshot()
    require(before["secure_boot"] is False and all(before["rows"][f"{0x40+i:04x}"] == 0 for i in range(8)),
            "state erasure is permitted only while fully unlocked")
    record = {"schema_version": 2, "serial": serial, "profile": PROFILE, "bundle_sha256": None,
              "bootkey_sha256": None, "tool_identity": bind_tool(),
              "completed_stage": None, "pending": None, "actions": [],
              "observations": [{"step": "erase_preflight", "public": before}]}
    save_record(record_path, record, create=True)
    erased = {"erased_range": {"start": FIRMWARE_END, "end": STATE_END}}
    with tempfile.TemporaryDirectory(prefix="pico2-erased-") as directory:
        image = Path(directory) / "erased.bin"
        image.write_bytes(b"\xff" * (STATE_END - FIRMWARE_END))
        def observe_erased():
            board.command("verify", image, "-t", "bin", "-o", hex(FIRMWARE_END))
            return erased
        record_action(record_path, record, "erase_state",
                      lambda: board.command("erase", "-r", hex(FIRMWARE_END), hex(STATE_END)),
                      observe_erased, erased, {"operation": "erase", "postcondition": erased})
    record["completed_stage"] = "erase-state"
    save_record(record_path, record)
    print("Start the verified application with commissioning daemon; fresh blank-at-boot and uncommissioned reports remain mandatory before OTP preparation.")
    return record


def _permission_reconciliation_record(record_path, serial, bundle, manifest):
    record = owner_record(record_path, expected_pending="page2_page63_permissions")
    require(record["completed_stage"] is None and record["serial"] == serial
            and record["bootkey_sha256"] == manifest["bootkey_sha256"]
            and record["bundle_sha256"] == sha256(bounded_file(Path(bundle) / "release.json")),
            "permission reconciliation target, stage, authority or bundle mismatch")
    observations = record["observations"]
    for observation in observations:
        exact_keys(observation, ("step", "public"))
    steps = [observation["step"] for observation in observations]
    prefix = ["public_preparation_preflight", "install_signed_firmware", "blank_signed_application"]
    if steps[3:4] == ["resume_signed_image_verified"]:
        prefix.append("resume_signed_image_verified")
    require(steps == prefix + [f"bootkey0_{index}" for index in range(16)]
            + [f"BOOT_FLAGS1_{index}" for index in range(3)] + ["BOOT_FLAGS1_group_readback"],
            "permission reconciliation requires every preceding prepare observation")
    elf_digest = next(item["sha256"] for item in manifest["artifacts"]
                      if item["name"] == ARTIFACTS[0])
    require(observations[1]["public"] == {"elf_sha256": elf_digest},
            "recorded installed firmware differs from bundle")
    if len(prefix) == 4:
        require(observations[3]["public"] == {"elf_sha256": elf_digest},
                "recorded resume firmware differs from bundle")
    public_policy(observations[0]["public"], manifest["bootkey_sha256"], "prepare")
    blank = observations[2]["public"]
    require(blank.get("usb_serial") == serial and blank.get("storage_blank_at_boot") is True
            and blank.get("critical") == 0, "missing original blank application admission")
    before = observations[-1]["public"]["snapshot"]
    public_policy(before, manifest["bootkey_sha256"], "prepare")
    expected = {**before, "rows": dict(before["rows"])}
    for row in ("0f85", "0fff"):
        expected["rows"][row] = (lock_byte(before["rows"][row]) | 0x15) * 0x010101
    public_policy(expected, manifest["bootkey_sha256"], "enable")
    bind_tool(record["tool_identity"])
    require(record["pending"]["expected"] == expected, "permission pending postcondition changed")
    return record, expected


def reconcile_prepare(serial, bundle, record_path, apply=False):
    """Observe helper postconditions without modifying the incident record or device."""
    global WRITES_ATTEMPTED
    WRITES_ATTEMPTED = False
    if not apply:
        raise ToolError("reconcile-prepare requires --apply for attended read-only observation", 2)
    manifest = verify_bundle(bundle)
    record, expected = _permission_reconciliation_record(record_path, serial, bundle, manifest)
    attended(serial, "READ-ONLY DEVICE RECONCILIATION: observe preparation; preserve the incident record unchanged; never rerun the helper or write OTP.")
    board = Board(serial)
    observed = board.snapshot()
    require(observed == expected, "permission postconditions incomplete or other OTP changed; no repair attempted")
    board.command("verify", Path(bundle) / ARTIFACTS[0], "-t", "elf")
    require(board.snapshot() == observed, "public OTP changed during reconciliation")
    return {"serial": record["serial"], "profile": record["profile"],
            "bootkey_sha256": record["bootkey_sha256"], "completed_stage": record["completed_stage"],
            "pending": record["pending"], "observed": observed,
            "signed_firmware_verified": True, "device_writes": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    policy = commands.add_parser("validate-policy")
    policy.add_argument("policy", type=Path)
    authority = commands.add_parser("authorize")
    authority.add_argument("--public-key", required=True, type=Path)
    authority.add_argument("--out-dir", required=True, type=Path)
    sealing = commands.add_parser("seal")
    for argument in ("elf", "permissions-helper", "key-file", "out-dir"):
        sealing.add_argument("--" + argument, required=True, type=Path)
    sealing.add_argument("--tag", required=True)
    sealing.add_argument("--commit", required=True)
    verifying = commands.add_parser("verify")
    verifying.add_argument("--bundle", required=True, type=Path)
    inspecting = commands.add_parser("inspect")
    inspecting.add_argument("--serial", required=True)
    provisioning = commands.add_parser("provision")
    provisioning.add_argument("--stage", required=True, choices=("prepare", "enable", "lock"))
    provisioning.add_argument("--serial", required=True)
    provisioning.add_argument("--bundle", required=True, type=Path)
    provisioning.add_argument("--record", required=True, type=Path)
    provisioning.add_argument("--apply", action="store_true")
    provisioning.add_argument("--resume", action="store_true",
                              help="resume only the pre-OTP checkpoint after completed firmware installation")
    provisioning.add_argument("--trace-hook", type=Path,
                              help="executable wrapper invoked as HOOK PICOTOOL ARG... for public commands")
    erasing = commands.add_parser("erase-state")
    erasing.add_argument("--serial", required=True)
    erasing.add_argument("--record", required=True, type=Path)
    erasing.add_argument("--apply", required=True, action="store_true")
    erasing.add_argument("--trace-hook", type=Path,
                         help="executable wrapper invoked as HOOK PICOTOOL ARG... for public commands")
    reconciling = commands.add_parser("reconcile-prepare",
                                     help="read-only device reconciliation of a pending permission helper")
    reconciling.add_argument("--serial", required=True)
    reconciling.add_argument("--bundle", required=True, type=Path)
    reconciling.add_argument("--record", required=True, type=Path)
    reconciling.add_argument("--apply", required=True, action="store_true")
    args = parser.parse_args()
    global TRACE_HOOK
    if getattr(args, "trace_hook", None):
        TRACE_HOOK = str(args.trace_hook.resolve(strict=True))
    try:
        if args.command == "authorize":
            result = authorize(args.public_key, args.out_dir)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "seal":
            print(json.dumps(seal(args.elf, args.permissions_helper, args.tag, args.commit,
                                  args.key_file, args.out_dir), sort_keys=True))
        elif args.command == "verify":
            print(json.dumps(verify_bundle(args.bundle), sort_keys=True))
        elif args.command == "inspect":
            print(json.dumps(inspect_device(args.serial), sort_keys=True))
        elif args.command == "provision":
            print(json.dumps(provision(args.stage, args.serial, args.bundle, args.record,
                                       args.apply, resume=args.resume), sort_keys=True))
        elif args.command == "erase-state":
            print(json.dumps(erase_state(args.serial, args.record, args.apply), sort_keys=True))
        elif args.command == "reconcile-prepare":
            print(json.dumps(reconcile_prepare(args.serial, args.bundle, args.record, args.apply),
                             sort_keys=True))
        else:
            validate_policy(read_json(args.policy))
            print("policy valid")
    except ToolError as error:
        parser.exit(6 if WRITES_ATTEMPTED else error.code, f"error: {error}\n")
    except PermissionError as error:
        parser.exit(6 if WRITES_ATTEMPTED else 3, f"permission denied: {error}\n")
    except ValueError as error:
        parser.exit(6 if WRITES_ATTEMPTED else 5, f"rejected: {error}\n")
    except OSError as error:
        parser.exit(6 if WRITES_ATTEMPTED else 7, f"local I/O error: {error}\n")
    except KeyboardInterrupt:
        parser.exit(6 if WRITES_ATTEMPTED else 2, "interrupted; preserve any existing record\n")


if __name__ == "__main__":
    main()
