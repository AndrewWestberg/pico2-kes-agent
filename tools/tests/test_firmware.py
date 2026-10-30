import copy
import importlib.util
import json
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tempfile
from unittest import mock
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("firmware", ROOT / "tools/firmware.py")
firmware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firmware)

def process_adapter(complete):
    """Deterministic process boundary; real files exercise diagnostic retention."""
    class Process:
        pid = 1_000_000_000  # Beyond Linux PID_MAX_LIMIT; no real process group.
        returncode = None
        def __init__(self, command, **kwargs):
            self.command, self.kwargs = command, kwargs
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def communicate(self, input=None, timeout=None):
            self.returncode = complete(self.command, input=input, timeout=timeout,
                                       **self.kwargs).returncode
        def wait(self):
            return self.returncode
    return Process



class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "security/otp-policy.json").read_text())

    def test_preserves_msd_and_state_with_single_authority(self):
        firmware.validate_policy(self.policy)
        stricter = copy.deepcopy(self.policy)
        stricter["page_locks"]["63"]["lock_ns"] = 3
        firmware.validate_policy(stricter)

    def test_rejects_loss_of_recovery_or_protection(self):
        changes = [(field, 0) for field in firmware.SET_FIELDS]
        changes += [(field, 1) for field in firmware.CLEAR_FIELDS]
        changes += [("BOOT_FLAGS1.KEY_VALID", 3), ("BOOT_FLAGS1.KEY_INVALID", 12)]
        for field, value in changes:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.policy)
                altered["fields"][field] = value
                with self.assertRaises(ValueError):
                    firmware.validate_policy(altered)

    def test_rejects_overlap_unknown_fields_and_reserved_locks(self):
        for mutate in (
            lambda p: p["firmware_region"].update(end=0x10101000),
            lambda p: p["state_region"].update(end=0x10304000),
            lambda p: p.update(allow_unsigned=True),
            lambda p: p["fields"].update({"CRIT0.ARM_DISABLE": 1}),
            lambda p: p["page_locks"]["2"].update(lock_ns=2),
            lambda p: p.update(rma=True),
        ):
            altered = copy.deepcopy(self.policy)
            mutate(altered)
            with self.assertRaises(ValueError):
                firmware.validate_policy(altered)


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="firmware-fixture-")
        cls.root = Path(cls.temp.name)
        cls.gnupg = cls.root / "gnupg"
        cls.gnupg.mkdir(mode=0o700)
        cls.env = {**os.environ, "GNUPGHOME": str(cls.gnupg), "LC_ALL": "C"}
        cls.authority = cls.root / "authority"
        cls.authority.mkdir()
        cls.key = cls.root / "key.pem"
        def command(*args):
            return subprocess.run(args, check=True, env=cls.env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE).stdout
        command("openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout", "-out", str(cls.key))
        command("openssl", "pkey", "-in", str(cls.key), "-pubout", "-out",
                str(cls.authority / firmware.PUBLIC_FILES[0]))
        command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "Fixture <fixture@example.invalid>", "rsa2048", "cert", "0")
        listing = command("gpg", "--with-colons", "--list-keys").decode()
        primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-add-key", primary, "rsa2048", "sign", "0")
        listing = command("gpg", "--with-colons", "--list-keys").decode()
        fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        cls.trust = (primary, fingerprints[1])
        (cls.authority / "firmware-key.json").write_text(
            json.dumps(firmware.statement(cls.authority / firmware.PUBLIC_FILES[0]), indent=2) + "\n")
        (cls.authority / "release-authority.asc").write_bytes(
            command("gpg", "--armor", "--export", primary))
        command("gpg", "--batch", "--armor", "--detach-sign", "--local-user", cls.trust[1] + "!",
                "--output", str(cls.authority / "firmware-key.json.asc"),
                str(cls.authority / "firmware-key.json"))
        shutil.copyfile(ROOT / "security/otp-policy.json", cls.authority / "otp-policy.json")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_authority_injection_does_not_change_production_pin(self):
        firmware.verify_authority(self.authority, trust=self.trust)
        with self.assertRaises(ValueError):
            firmware.verify_authority(self.authority)

    def test_modified_authority_rejected(self):
        altered = self.root / "altered-authority"
        shutil.copytree(self.authority, altered)
        statement = altered / "firmware-key.json"
        statement.write_bytes(statement.read_bytes().replace(b"secp256k1", b"secp256r1"))
        with self.assertRaises(ValueError):
            firmware.verify_authority(altered, trust=self.trust)
        shutil.copyfile(self.authority / "firmware-key.json", statement)
        key = altered / firmware.PUBLIC_FILES[0]
        subprocess.run(["openssl", "ecparam", "-name", "secp256k1", "-genkey",
                        "-noout", "-out", str(altered / "other.pem")], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["openssl", "pkey", "-in", str(altered / "other.pem"), "-pubout",
                        "-out", str(key)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaises(ValueError):
            firmware.verify_authority(altered, trust=self.trust)

    def test_real_bundle_and_tampering(self):
        elf = ROOT / "target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware"
        helper = Path(os.environ.get("PICO2_PERMISSIONS_HELPER",
                                     ROOT / "target/otp-permissions/pico2-otp-permissions.elf"))
        if not elf.is_file() or not helper.is_file():
            self.skipTest("build firmware and permission helper first; set PICO2_PERMISSIONS_HELPER")
        offsets = firmware.validate_helper(helper)
        self.assertEqual(set(offsets), {"expected_chipid_low", "expected_chipid_high"})
        altered_helper = self.root / "configured-helper.elf"
        changed_helper = bytearray(helper.read_bytes())
        changed_helper[offsets["expected_chipid_low"]] = 0
        altered_helper.write_bytes(changed_helper)
        with self.assertRaises(ValueError):
            firmware.validate_helper(altered_helper)
        bundle = self.root / "bundle"
        firmware.seal(elf, helper, "vfixture", "a" * 40, self.key, bundle,
                      authority_dir=self.authority, trust=self.trust)
        firmware.verify_bundle(bundle, trust=self.trust)
        with self.assertRaises(ValueError):
            firmware.elf_segments(helper)
        signature = bundle / "release.json.sig"
        original_signature = signature.read_bytes()
        try:
            signature.write_bytes(original_signature[:-1] + bytes([original_signature[-1] ^ 1]))
            with self.assertRaises(ValueError):
                firmware.verify_bundle(bundle, trust=self.trust)
        finally:
            signature.write_bytes(original_signature)
        extra = bundle / "unexpected"
        extra.write_bytes(b"not authenticated")
        with self.assertRaises(ValueError):
            firmware.verify_bundle(bundle, trust=self.trust)
        extra.unlink()
        with self.assertRaises(ValueError):
            firmware.verify_bundle(bundle)
        failed = self.root / "failed-bundle"
        with mock.patch.object(firmware, "verify_bundle", side_effect=ValueError("fixture rejection")):
            with self.assertRaises(ValueError):
                firmware.seal(elf, helper, "vfixture", "a" * 40, self.key, failed,
                              authority_dir=self.authority, trust=self.trust)
        self.assertFalse(failed.exists())
        payload = bundle / firmware.ARTIFACTS[1]
        original = payload.read_bytes()
        try:
            payload.write_bytes(original[:-512])
            with self.assertRaises(ValueError):
                firmware.verify_bundle(bundle, trust=self.trust)
            manifest_path = bundle / "release.json"
            manifest = json.loads(manifest_path.read_text())
            entry = next(item for item in manifest["artifacts"] if item["name"] == payload.name)
            entry["size_bytes"] = payload.stat().st_size
            entry["sha256"] = firmware.sha256(payload.read_bytes())
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key),
                            "-out", str(bundle / "release.json.sig"), str(manifest_path)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.assertRaises(ValueError):
                firmware.verify_bundle(bundle, trust=self.trust)
            payload.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaises(ValueError):
                firmware.verify_bundle(bundle, trust=self.trust)
        finally:
            payload.write_bytes(original)

    def test_page_mapping_and_partial_uf2(self):
        segments = [(firmware.FIRMWARE_START + 4, b"abcd")]
        pages = firmware.expected_pages(segments)
        address, data = next(iter(pages.items()))
        block = struct.pack("<8I", 0x0a324655, 0x9e5d5157, 0x2000, address, 256,
                            0, 1, 0xe48bff59) + data + bytes(220) + struct.pack("<I", 0x0ab16f30)
        path = self.root / "mapping.uf2"
        path.write_bytes(block)
        firmware.validate_uf2(path, segments)
        path.write_bytes(block[:-1])
        with self.assertRaises(ValueError):
            firmware.validate_uf2(path, segments)
        changed = bytearray(block)
        changed[32] = 1
        path.write_bytes(changed)
        with self.assertRaises(ValueError):
            firmware.validate_uf2(path, segments)
        changed = bytearray(block)
        struct.pack_into("<I", changed, 12, firmware.FIRMWARE_END)
        path.write_bytes(changed)
        with self.assertRaises(ValueError):
            firmware.validate_uf2(path, segments)
        changed = bytearray(block)
        changed[288] = 1
        path.write_bytes(changed)
        with self.assertRaises(ValueError):
            firmware.validate_uf2(path, segments)
        with self.assertRaises(ValueError):
            firmware.expected_pages([(firmware.FIRMWARE_END, b"abcd")])

    def test_elf_load_bounds_and_overflow(self):
        path = self.root / "bounds.elf"
        header = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9),
                             2, 40, 1, firmware.FIRMWARE_START + 1, 52, 0, 0,
                             52, 32, 1, 0, 0, 0)
        def check(segment, accepted=False):
            path.write_bytes(header + struct.pack("<8I", *segment) + b"abcd")
            if accepted:
                self.assertEqual(firmware.elf_segments(path), [(firmware.FIRMWARE_START, b"abcd")])
            else:
                with self.assertRaises(ValueError):
                    firmware.elf_segments(path)
        valid = [1, 84, firmware.FIRMWARE_START, firmware.FIRMWARE_START, 4, 4, 5, 4]
        check(valid, accepted=True)
        for index, value in ((1, 0xfffffff0), (3, 0xfffffffc), (3, firmware.FIRMWARE_END),
                             (4, 8), (5, 3)):
            altered = valid.copy()
            altered[index] = value
            check(altered)

    def test_helper_load_and_bss_must_remain_in_xip_sram(self):
        path = self.root / "helper-bounds.elf"
        header = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9),
                             2, 40, 1, 0x13ffc001, 52, 0, 0, 52, 32, 2, 0, 0, 0)
        first = [1, 116, 0x13ffc000, 0x13ffc000, 4, 4, 5, 4]
        bss = [1, 120, 0x13fff800, 0x13fff800, 0, 0x800, 6, 4]
        def write(first_segment, bss_segment):
            path.write_bytes(header + struct.pack("<8I", *first_segment)
                             + struct.pack("<8I", *bss_segment) + b"abcd")
        write(first, bss)
        firmware.elf_segments(path, helper=True)
        for segment, index, value in ((first, 2, 0x10000000), (first, 5, 0x5000),
                                      (bss, 2, 0x14000000), (bss, 3, 0x14000000),
                                      (bss, 5, 0x804)):
            changed = segment.copy()
            changed[index] = value
            write(changed if segment is first else first, changed if segment is bss else bss)
            with self.assertRaises(ValueError):
                firmware.elf_segments(path, helper=True)

    def test_invalid_metadata_loop(self):
        def block(next_offset):
            return struct.pack("<5I", 0xffffded3, 0x10210142, 0x1ff,
                               next_offset & 0xffffffff, 0xab123579)
        original = block(0)
        firmware.image_metadata([(firmware.FIRMWARE_START, original)], False)
        loop = block(20) + block(0)
        with self.assertRaises(ValueError):
            firmware.image_metadata([(firmware.FIRMWARE_START, loop)], False)


class InspectTests(unittest.TestCase):
    def test_bootsel_chipid_is_not_usb_serial(self):
        info = (b"Device Information\n type: RP2350\n revision: A2\n current cpu: ARM\n"
                b" available cpus: ARM, RISC-V\n default cpu: ARM\n"
                b" chipid: 0x00afd9003906a634\n secure boot: 0\n")
        report = firmware.parse_bootsel_info(info, "00afd9003906a634")
        self.assertEqual(report["fitted_flash"], "unavailable")
        self.assertFalse(report["secure_boot"])
        with self.assertRaises(ValueError):
            firmware.parse_bootsel_info(info, "00afd9003906a635")
        with self.assertRaises(ValueError):
            firmware.parse_bootsel_info(info + b" secure boot: 1\n", "00afd9003906a634")

    def test_discovery_rejects_multiple_boards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, vendor, product, address in (
                ("first", "2e8a", "000f", "3"), ("second", "1209", "4b45", "4")
            ):
                device = root / name
                device.mkdir()
                for key, value in (("idVendor", vendor), ("idProduct", product),
                                   ("busnum", "1"), ("devnum", address)):
                    (device / key).write_text(value)
            with self.assertRaises(ValueError):
                firmware.selected_usb_board(root)




class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"path": "/fixture/picotool", "sha256": "aa" * 32,
                         "build_id": "bb", "version": "picotool v2.3.1 (fixture)\n",
                         "libusb": {"path": "/fixture/libusb.so", "sha256": "cc" * 32,
                                    "package": "libusb", "version": "1"}}
        patch = mock.patch.object(firmware, "tool_identity", return_value=self.identity)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(setattr, firmware, "BOUND_TOOL", None)

    def snapshot(self):
        return {"stepping": "A2", "secure_boot": False,
                "rows": {f"{row:04x}": 0 for row in firmware.PUBLIC_ROWS}}

    def test_public_admission_rejects_partial_or_conflicting_otp(self):
        original = self.snapshot()
        firmware.public_policy(original, "11" * 32, "prepare")
        for row, value in (("0040", 1), ("0048", 1 << 17), ("004b", 2),
                           ("0080", 1), ("0090", 1), ("0fff", 0x010001),
                           ("0ffe", 0x808080), ("0f85", 0x020202)):
            altered = copy.deepcopy(original)
            altered["rows"][row] = value
            with self.subTest(row=row), self.assertRaises(ValueError):
                firmware.public_policy(altered, "11" * 32, "prepare")
        with self.assertRaises(ValueError):
            firmware.public_policy(original, "11" * 32, "enable")

    def test_prepared_stage_requires_exact_authority_masks_and_locks(self):
        prepared = self.snapshot()
        for index in range(16):
            prepared["rows"][f"{0x80+index:04x}"] = 0x1111
        for index in range(3):
            prepared["rows"][f"{0x4b+index:04x}"] = 0xe01
        prepared["rows"]["0f85"] = 0x151515
        prepared["rows"]["0fff"] = 0x3d3d3d
        firmware.public_policy(prepared, "11" * 32, "enable")
        prepared["rows"]["0fff"] = 0x111111
        with self.assertRaises(ValueError):
            firmware.public_policy(prepared, "11" * 32, "enable")

    def test_uncertain_write_retains_durable_pending_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            record = {"schema_version": 2, "serial": "00afd9003906a634",
                      "profile": firmware.PROFILE, "bundle_sha256": "11"*32,
                      "bootkey_sha256": "22"*32, "tool_identity": self.identity,
                      "completed_stage": None, "pending": None, "observations": [], "actions": []}
            firmware.save_record(path, record, create=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                firmware.save_record(path, record, create=True)
            def lost_after_write():
                raise OSError("connection lost after potentially applied fuse")
            with self.assertRaises(firmware.ToolError) as caught:
                firmware.record_action(path, record, "enable", lost_after_write, lambda: {},
                                       {}, {"register": "CRIT1"})
            self.assertEqual(caught.exception.code, 6)
            self.assertEqual(json.loads(path.read_text())["pending"]["state"], "uncertain")
            with self.assertRaises(ValueError):
                firmware.owner_record(path)

    def test_public_row_parser_rejects_warnings_duplicates_and_secret_rows(self):
        valid = b"ROW 0x0040: OTP_DATA_CRIT1 (CRIT)\n    VALUE 0x000000\n"
        self.assertEqual(firmware.parse_public_rows(valid, (0x40,)), {0x40: 0})
        for value in (valid + valid, valid.replace(b"VALUE", b"WARNING VALUE"),
                      valid.replace(b"0x0040", b"0x0000"), valid.replace(b"000000", b"-1")):
            with self.assertRaises(ValueError):
                firmware.parse_public_rows(value, (0x40,))

    def _resume_fixture(self, directory):
        bundle = Path(directory) / "bundle"
        bundle.mkdir()
        (bundle / "release.json").write_bytes(b"resume checkpoint fixture")
        shutil.copyfile(ROOT / "security/otp-policy.json", bundle / "otp-policy.json")
        manifest = {"bootkey_sha256": "11" * 32,
                    "artifacts": [{"name": firmware.ARTIFACTS[0], "sha256": "22" * 32}]}
        record = {"schema_version": 2, "serial": "00afd9003906a634",
                  "profile": firmware.PROFILE,
                  "bundle_sha256": firmware.sha256((bundle / "release.json").read_bytes()),
                  "bootkey_sha256": manifest["bootkey_sha256"],
                  "tool_identity": self.identity,
                  "completed_stage": None, "pending": None, "actions": [],
                  "observations": [
                      {"step": "public_preparation_preflight", "public": self.snapshot()},
                      {"step": "install_signed_firmware", "public": {"elf_sha256": "22" * 32}},
                  ]}
        path = Path(directory) / "record.json"
        firmware.save_record(path, record, create=True)
        return bundle, manifest, path, record

    def test_resume_rejects_uncertain_or_different_attempt_without_changing_record(self):
        changes = (
            lambda r: r.update(pending="install_signed_firmware"),
            lambda r: r.update(pending="bootkey0_0"),
            lambda r: r.update(completed_stage="prepare"),
            lambda r: r.update(serial="00afd9003906a635"),
            lambda r: r.update(bundle_sha256="33" * 32),
            lambda r: r.update(bootkey_sha256="33" * 32),
            lambda r: r["tool_identity"].update(sha256="different"),
            lambda r: r["observations"].append({"step": "bootkey0_0", "public": {}}),
            lambda r: r["observations"][1].update(step="bootkey0_0"),
            lambda r: r["observations"][1]["public"].update(elf_sha256="33" * 32),
            lambda r: r["observations"][0]["public"]["rows"].update({"0040": 1}),
        )
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, path, original = self._resume_fixture(directory)
            for index, change in enumerate(changes):
                with self.subTest(case=index):
                    record = copy.deepcopy(original)
                    change(record)
                    firmware.save_record(path, record)
                    before = path.read_bytes()
                    with self.assertRaises(ValueError):
                        firmware._prepare_resume_record(path, original["serial"], bundle, manifest)
                    self.assertEqual(path.read_bytes(), before)

    def test_resume_requires_explicit_applying_prepare(self):
        for stage, apply in (("prepare", False), ("enable", True), ("lock", True)):
            with self.subTest(stage=stage, apply=apply):
                with self.assertRaises(firmware.ToolError) as error:
                    firmware.provision(stage, "00afd9003906a634", "/absent", "/absent",
                                       apply, resume=True)
                self.assertEqual(error.exception.code, 2)

    def test_resume_requires_fresh_otp_and_image_readback_before_first_write(self):
        for failure in ("blank-admission", "otp-changed", "image-mismatch", None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                bundle, manifest, path, original = self._resume_fixture(directory)
                snapshot = self.snapshot()
                if failure == "otp-changed":
                    snapshot["rows"]["0080"] = 1
                commands = []

                class Board:
                    def __init__(self, serial):
                        pass

                    def snapshot(self):
                        return snapshot

                    def command(self, *arguments):
                        commands.append(arguments[0])
                        if arguments[0] == "verify":
                            if failure == "image-mismatch":
                                raise firmware.ToolError("image mismatch", 4)
                            return b"verified"
                        raise RuntimeError("simulated loss at first OTP write")

                report = {"critical": 0, "storage_blank_at_boot": True}
                with mock.patch.object(firmware, "verify_bundle", return_value=manifest), \
                     mock.patch.object(firmware, "attended"), \
                     mock.patch.object(firmware, "pause"), \
                     mock.patch.object(firmware, "inspect_device", return_value={
                         "mode": "application", "security": {"profile": "unlocked"}}), \
                     mock.patch.object(firmware, "application_report",
                                       side_effect=ValueError("not blank") if failure == "blank-admission" else None,
                                       return_value=report), \
                     mock.patch.object(firmware, "Board", Board):
                    with self.assertRaises(ValueError):
                        firmware.provision("prepare", original["serial"], bundle, path,
                                           True, resume=True)
                saved = json.loads(path.read_bytes())
                if failure is None:
                    self.assertEqual(commands, ["verify", "otp"])
                    self.assertEqual(saved["pending"]["step"], "bootkey0_0")
                    self.assertIn("resume_signed_image_verified",
                                  [item["step"] for item in saved["observations"]])
                else:
                    self.assertNotIn("otp", commands)
                    self.assertIsNone(saved["pending"])
                self.assertNotIn("load", commands)

    def _permission_fixture(self, directory):
        bundle, manifest, path, record = self._resume_fixture(directory)
        record["observations"].extend((
            {"step": "blank_signed_application", "public": {
                "usb_serial": record["serial"], "storage_blank_at_boot": True, "critical": 0}},
            {"step": "resume_signed_image_verified", "public": {"elf_sha256": "22" * 32}},
        ))
        snapshot = self.snapshot()
        for index in range(16):
            snapshot["rows"][f"{0x80 + index:04x}"] = 0x1111
            record["observations"].append(
                {"step": f"bootkey0_{index}", "public": copy.deepcopy(snapshot)})
        for index, row in enumerate(("004b", "004c", "004d")):
            snapshot["rows"][row] = 0xe01
            record["observations"].append({"step": f"BOOT_FLAGS1_{index}",
                                           "public": {"row": int(row, 16), "value": 0xe01}})
        record["observations"].append({"step": "BOOT_FLAGS1_group_readback",
                                       "public": {"copies": [0xe01] * 3, "vote": 0xe01,
                                                  "snapshot": copy.deepcopy(snapshot)}})
        expected = copy.deepcopy(snapshot)
        expected["rows"]["0f85"] = expected["rows"]["0fff"] = 0x151515
        record["pending"] = {"step": "page2_page63_permissions", "state": "uncertain",
                             "expected": expected, "processes": []}
        firmware.save_record(path, record)
        return bundle, manifest, path, record

    def test_permission_reconciliation_preserves_audit_and_never_replays_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, path, record = self._permission_fixture(directory)
            with self.assertRaises(ValueError):
                firmware.owner_record(path)
            _, observed = firmware._permission_reconciliation_record(
                path, record["serial"], bundle, manifest)

            class Board:
                def __init__(self, serial):
                    pass

                def snapshot(self):
                    return copy.deepcopy(observed)

                def command(self, *arguments):
                    if arguments[0] != "verify":
                        raise AssertionError("reconciliation attempted a device write")

            before = path.read_bytes()
            with mock.patch.object(firmware, "verify_bundle", return_value=manifest), \
                 mock.patch.object(firmware, "attended"), \
                 mock.patch.object(firmware, "Board", Board):
                result = firmware.reconcile_prepare(record["serial"], bundle, path, True)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(result["observed"], observed)
            self.assertIsNone(result["completed_stage"])
            self.assertEqual(result["pending"]["state"], "uncertain")
            self.assertFalse(firmware.WRITES_ATTEMPTED)

    def test_permission_reconciliation_refuses_partial_changed_or_unstable_readback(self):
        for failure in ("page2-partial", "page63-unlocked", "bootkey", "critical",
                        "other-page", "image", "unstable"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                bundle, manifest, path, record = self._permission_fixture(directory)
                _, observed = firmware._permission_reconciliation_record(
                    path, record["serial"], bundle, manifest)
                changes = {"page2-partial": ("0f85", 0x141415),
                           "page63-unlocked": ("0fff", 0x141414),
                           "bootkey": ("0080", 0), "critical": ("0040", 1),
                           "other-page": ("0ffd", 0x151515)}
                if failure in changes:
                    row, value = changes[failure]
                    observed["rows"][row] = value
                reads = 0

                class Board:
                    def __init__(self, serial):
                        pass

                    def snapshot(self):
                        nonlocal reads
                        reads += 1
                        result = copy.deepcopy(observed)
                        if failure == "unstable" and reads > 1:
                            result["rows"]["0048"] = 1
                        return result

                    def command(self, *arguments):
                        if arguments[0] != "verify":
                            raise AssertionError("reconciliation attempted a device write")
                        if failure == "image":
                            raise firmware.ToolError("image mismatch", 4)

                before = path.read_bytes()
                with mock.patch.object(firmware, "verify_bundle", return_value=manifest), \
                     mock.patch.object(firmware, "attended"), \
                     mock.patch.object(firmware, "Board", Board):
                    with self.assertRaises(ValueError):
                        firmware.reconcile_prepare(record["serial"], bundle, path, True)
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(firmware.WRITES_ATTEMPTED)

    def test_permission_reconciliation_binds_checkpoint_and_preserves_stricter_locks(self):
        changes = (
            lambda r: r.update(pending="bootkey0_15"),
            lambda r: r.update(completed_stage="prepare"),
            lambda r: r.update(serial="00afd9003906a635"),
            lambda r: r.update(bundle_sha256="33" * 32),
            lambda r: r.update(bootkey_sha256="33" * 32),
            lambda r: r["tool_identity"].update(sha256="different"),
            lambda r: r["observations"].pop(),
            lambda r: r["observations"][1]["public"].update(elf_sha256="33" * 32),
            lambda r: r["observations"][2]["public"].update(storage_blank_at_boot=False),
        )
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, path, original = self._permission_fixture(directory)
            for index, change in enumerate(changes):
                with self.subTest(case=index):
                    record = copy.deepcopy(original)
                    change(record)
                    firmware.save_record(path, record)
                    with self.assertRaises(ValueError):
                        firmware._permission_reconciliation_record(
                            path, original["serial"], bundle, manifest)
            stricter = copy.deepcopy(original)
            stricter["observations"][-1]["public"]["snapshot"]["rows"]["0f85"] = 0x3c3c3c
            stricter["pending"]["expected"]["rows"]["0f85"] = 0x3d3d3d
            firmware.save_record(path, stricter)
            _, expected = firmware._permission_reconciliation_record(
                path, original["serial"], bundle, manifest)
            self.assertEqual(expected["rows"]["0f85"], 0x3d3d3d)

    def test_physical_mismatch_is_uncertain_and_never_success(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            with self.assertRaises(firmware.ToolError):
                firmware.record_action(path, record, "row", lambda: None,
                                       lambda: {"row": 64, "value": 0},
                                       {"row": 64, "value": 1},
                                       {"row": 64, "physical_copies": 1, "raw_target": 1})
            saved = json.loads(path.read_text())
            self.assertEqual(saved["pending"]["state"], "uncertain")
            self.assertEqual(saved["pending"]["observed"]["value"], 0)
            self.assertFalse(saved["actions"])
            with self.assertRaises(ValueError):
                firmware.owner_record(path)

    def test_group_writes_one_row_and_reads_before_next(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                _, _, path, record = self._resume_fixture(directory)
                events = []
                snapshot = self.snapshot()
                class Board:
                    def snapshot(self):
                        events.append(("snapshot",))
                        return copy.deepcopy(snapshot)
                    def command(self, *args):
                        events.append(("write", args))
                        row, value = int(args[-2], 16), int(args[-1], 16)
                        if not failed or row == 0x40:
                            snapshot["rows"][f"{row:04x}"] = value
                    def raw_row(self, row):
                        events.append(("read", row))
                        return snapshot["rows"][f"{row:04x}"]
                board = Board()
                if failed:
                    with self.assertRaises(firmware.ToolError):
                        firmware.program_group(path, record, board, "CRIT1", 0x40, 8, 1)
                    self.assertEqual([event[1][-2] for event in events if event[0] == "write"],
                                     ["0x40", "0x41"])
                    self.assertEqual(record["pending"]["state"], "uncertain")
                else:
                    firmware.program_group(path, record, board, "CRIT1", 0x40, 8, 1)
                    calls = [event for event in events if event[0] in ("read", "write")]
                    self.assertEqual(len(calls), 16)
                    for index in range(8):
                        self.assertEqual(calls[index * 2][1][:5], ("otp", "set", "-c", "1", "-r"))
                        self.assertEqual(calls[index * 2 + 1], ("read", 0x40 + index))
                    self.assertEqual(record["observations"][-1]["public"]["copies"], [1] * 8)

    def test_unequal_group_is_never_written(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            snapshot = self.snapshot()
            snapshot["rows"]["0040"] = 1
            board = mock.Mock()
            board.snapshot.return_value = snapshot
            with self.assertRaises(ValueError):
                firmware.program_group(path, record, board, "CRIT1", 0x40, 8, 7)
            board.command.assert_not_called()

    def test_group_final_read_rejects_disagreement_despite_three_of_eight_vote(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            snapshot = self.snapshot()
            snapshots = 0
            class Board:
                def snapshot(self):
                    nonlocal snapshots
                    snapshots += 1
                    result = copy.deepcopy(snapshot)
                    if snapshots == 2:
                        for row in range(0x43, 0x48):
                            result["rows"][f"{row:04x}"] = 0
                    return result
                def command(self, *args):
                    snapshot["rows"][f"{int(args[-2], 16):04x}"] = int(args[-1], 16)
                def raw_row(self, row):
                    return snapshot["rows"][f"{row:04x}"]
            with self.assertRaises(firmware.ToolError):
                firmware.program_group(path, record, Board(), "CRIT1", 0x40, 8, 1)
            pending = json.loads(path.read_text())["pending"]
            self.assertEqual(pending["state"], "uncertain")
            self.assertEqual(pending["observed"]["vote"], 1)
            self.assertEqual(pending["observed"]["copies"][-1], 0)

    def test_public_snapshot_requests_only_whitelisted_rows(self):
        board = firmware.Board("00afd9003906a634")
        selectors_seen = []
        def command(*arguments, selectors=()):
            selectors_seen.extend(int(selector, 16) for selector in selectors)
            return b"".join(f"ROW {int(row, 16):#06x}\n VALUE 0x000000\n".encode()
                            for row in selectors)
        with mock.patch.object(board, "command", side_effect=command), \
             mock.patch.object(board, "identify",
                               return_value={"stepping": "A2", "secure_boot": False}):
            board.snapshot()
        self.assertEqual(set(selectors_seen), set(firmware.PUBLIC_ROWS))
        self.assertFalse(set(selectors_seen) & set(range(0x00, 0x40)))

    def test_legacy_record_is_rejected_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            record["schema_version"] = 1
            firmware.save_record(path, record)
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                firmware.owner_record(path)
            self.assertEqual(before, path.read_bytes())

    def test_completed_process_is_durable_before_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            def process(command, *, stdout, stderr, **kwargs):
                stdout.write(b"programmed physical row")
                stderr.write(b"public diagnostic")
                return subprocess.CompletedProcess(command, 0)
            def observe():
                saved = json.loads(path.read_text())
                self.assertEqual(saved["pending"]["state"], "pending")
                self.assertEqual(saved["pending"]["processes"][0]["stdout"], "programmed physical row")
                raise ConnectionError("readback lost")
            with mock.patch.object(firmware.subprocess, "Popen", process_adapter(process)):
                with self.assertRaises(firmware.ToolError):
                    firmware.record_action(path, record, "physical_row",
                        lambda: firmware.run(["picotool", "otp", "set", "-r", "0x40", "1"]),
                        observe, {"row": 64, "value": 1}, {"row": 64})
            saved = json.loads(path.read_text())
            self.assertEqual(saved["pending"]["state"], "uncertain")
            self.assertEqual(saved["pending"]["processes"][0]["stderr"], "public diagnostic")

    def test_failed_or_interrupted_action_keeps_output_and_cannot_replay(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt), tempfile.TemporaryDirectory() as directory:
                _, _, path, record = self._resume_fixture(directory)
                def process(command, *, stdout, stderr, **kwargs):
                    stdout.write(b"write dispatched")
                    stderr.write(b"last public status")
                    if interrupt:
                        raise KeyboardInterrupt()
                    return subprocess.CompletedProcess(command, 1)
                with mock.patch.object(firmware.subprocess, "Popen", process_adapter(process)):
                    with self.assertRaises(firmware.ToolError) as caught:
                        firmware.record_action(path, record, "physical_row",
                            lambda: firmware.run(["picotool", "otp", "set", "-r", "0x40", "1"]),
                            lambda: self.fail("observed after process failure"), {}, {"row": 64})
                self.assertEqual(caught.exception.code, 6)
                saved = json.loads(path.read_text())
                self.assertEqual(saved["pending"]["processes"][0]["stdout"], "write dispatched")
                self.assertEqual(saved["pending"]["processes"][0]["status"], "interrupted" if interrupt else 1)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    firmware.record_action(path, record, "retry", lambda: self.fail("replayed"),
                                           lambda: {}, {}, {})
                self.assertEqual(path.read_bytes(), before)

    def test_evidence_budget_stops_before_another_write_and_remains_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            record["actions"].append({"stdout": "x" * (firmware.MAX_RECORD - firmware.ACTION_RESERVE)})
            firmware.save_record(path, record)
            self.assertEqual(firmware.owner_record(path)["serial"], record["serial"])
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                firmware.record_action(path, record, "row", lambda: self.fail("write after budget"),
                                       lambda: {}, {}, {})
            self.assertEqual(path.read_bytes(), before)

    def test_independent_group_failure_keeps_subprocess_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path, record = self._resume_fixture(directory)
            snapshot = self.snapshot()
            class Board:
                def snapshot(self):
                    if snapshot["rows"]["0047"] == 1:
                        firmware.run(["picotool", "otp", "get", "-r", "0x40"])
                    return copy.deepcopy(snapshot)
                def command(self, *args):
                    snapshot["rows"][f"{int(args[-2], 16):04x}"] = int(args[-1], 16)
                def raw_row(self, row):
                    return snapshot["rows"][f"{row:04x}"]
            def process(command, *, stdout, stderr, **kwargs):
                stderr.write(b"independent raw snapshot failed")
                return subprocess.CompletedProcess(command, 1)
            with mock.patch.object(firmware.subprocess, "Popen", process_adapter(process)):
                with self.assertRaises(firmware.ToolError):
                    firmware.program_group(path, record, Board(), "CRIT1", 0x40, 8, 1)
            pending = json.loads(path.read_text())["pending"]
            self.assertEqual(pending["step"], "CRIT1_group_readback")
            self.assertEqual(pending["state"], "uncertain")
            self.assertEqual(pending["processes"][0]["stderr"], "independent raw snapshot failed")

    def test_final_lock_readback_cannot_complete_with_one_bad_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, manifest, path, record = self._resume_fixture(directory)
            record["completed_stage"] = "enable"
            record["observations"].extend({"step": step, "public": {}} for step in (
                "secure_signed_startup", "signed_msd_reinstall", "signed_msd_reinstall_startup"))
            firmware.save_record(path, record)
            snapshot = self.snapshot()
            snapshot["secure_boot"] = True
            for row in range(0x80, 0x90):
                snapshot["rows"][f"{row:04x}"] = 0x1111
            for row in range(0x40, 0x48):
                snapshot["rows"][f"{row:04x}"] = 1
            for row in range(0x4b, 0x4e):
                snapshot["rows"][f"{row:04x}"] = 0xe01
            snapshot["rows"]["0f85"], snapshot["rows"]["0fff"] = 0x151515, 0x3d3d3d
            class Board:
                def __init__(self, serial):
                    self.locked_reads = 0
                def snapshot(self):
                    result = copy.deepcopy(snapshot)
                    if all(result["rows"][f"{row:04x}"] == 7 for row in range(0x40, 0x48)):
                        self.locked_reads += 1
                        if self.locked_reads == 2:
                            result["rows"]["0047"] = 5
                    return result
                def command(self, *args):
                    if args[0] == "otp":
                        snapshot["rows"][f"{int(args[-2], 16):04x}"] = int(args[-1], 16)
                def raw_row(self, row):
                    return snapshot["rows"][f"{row:04x}"]
            with mock.patch.object(firmware, "verify_bundle", return_value=manifest), \
                 mock.patch.object(firmware, "attended"), mock.patch.object(firmware, "pause"), \
                 mock.patch.object(firmware, "inspect_device", return_value={"mode": "bootsel"}), \
                 mock.patch.object(firmware, "Board", Board), \
                 mock.patch.object(firmware, "application_report",
                                   side_effect=AssertionError("advanced past failed final readback")):
                with self.assertRaises(firmware.ToolError):
                    firmware.provision("lock", record["serial"], bundle, path, True)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["completed_stage"], "enable")
            self.assertEqual(saved["pending"]["step"], "final_rom_readback")
            self.assertEqual(saved["pending"]["state"], "uncertain")
            self.assertEqual(saved["pending"]["observed"]["rows"]["0047"], 5)


class ToolEvidenceTests(unittest.TestCase):
    def test_tool_identity_rejects_changed_binary_with_same_version(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "picotool"
            library = Path(directory) / "libusb-1.0.so.0"
            executable.write_bytes(b"first")
            library.write_bytes(b"library")
            def fake_run(command, **kwargs):
                if command[0] == str(executable):
                    return b"picotool v2.3.1 (fixture)\nfull version\n", f"123: calling init: {library}\n".encode()
                if command[0] == "readelf":
                    return b"Build ID: abc123\n", b""
                if command[1] == "-S":
                    return b"libusb: /fixture/libusb\n", b""
                return b"1.2.3", b""
            with mock.patch.object(firmware.shutil, "which", return_value=str(executable)), \
                 mock.patch.object(firmware, "run", side_effect=fake_run):
                original = firmware.bind_tool()
                self.assertEqual(original["build_id"], "abc123")
                self.assertEqual(original["libusb"]["sha256"], firmware.sha256(b"library"))
                executable.write_bytes(b"second")
                with self.assertRaises(ValueError):
                    firmware.bind_tool(original)
        firmware.BOUND_TOOL = None

    def test_process_success_and_failure_keep_bounded_output(self):
        for status in (0, 1):
            with self.subTest(status=status):
                calls = []
                def fake_process(command, *, stdout, stderr, **kwargs):
                    stdout.write(b"public output")
                    stderr.write(b"public error")
                    return subprocess.CompletedProcess(command, status)
                with mock.patch.object(firmware.subprocess, "Popen", process_adapter(fake_process)), \
                     mock.patch.object(firmware, "BOUND_TOOL", {"path": "fixture"}):
                    firmware.ACTIVE_ACTION = calls
                    try:
                        if status:
                            with self.assertRaises(firmware.ToolError):
                                firmware.run(["fixture", "write"])
                        else:
                            firmware.run(["fixture", "write"])
                    finally:
                        firmware.ACTIVE_ACTION = None
                self.assertEqual(calls[0]["stdout"], "public output")
                self.assertEqual(calls[0]["stderr"], "public error")
                self.assertEqual(calls[0]["status"], status)

    def test_oversized_output_is_bounded_and_retained(self):
        calls = []
        def fake_process(command, *, stdout, stderr, **kwargs):
            stdout.write(b"x" * (firmware.OUTPUT_LIMIT + 10))
            stderr.write(b"y" * (firmware.OUTPUT_LIMIT + 10))
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(firmware.subprocess, "Popen", process_adapter(fake_process)), \
             mock.patch.object(firmware, "BOUND_TOOL", {"path": "fixture"}):
            firmware.ACTIVE_ACTION = calls
            try:
                with self.assertRaises(firmware.ToolError):
                    firmware.run(["fixture", "write"])
            finally:
                firmware.ACTIVE_ACTION = None
        self.assertEqual(len(calls[0]["stdout"]), firmware.EVIDENCE_OUTPUT_LIMIT)
        self.assertEqual(len(calls[0]["stderr"]), firmware.EVIDENCE_OUTPUT_LIMIT)
        self.assertTrue(calls[0]["stdout_truncated"])
        self.assertTrue(calls[0]["stderr_truncated"])

    def test_timeout_keeps_available_diagnostics(self):
        calls = []
        def process(command, *, stdout, stderr, timeout, **kwargs):
            stdout.write(b"write began")
            stderr.write(b"waiting for acknowledgement")
            raise subprocess.TimeoutExpired(command, timeout)
        with mock.patch.object(firmware.subprocess, "Popen", process_adapter(process)), \
             mock.patch.object(firmware, "BOUND_TOOL", {"path": "fixture"}), \
             mock.patch.object(firmware, "ACTIVE_ACTION", calls):
            with self.assertRaises(firmware.ToolError):
                firmware.run(["fixture", "write"], timeout=1)
        self.assertEqual(calls[0]["status"], "timeout")
        self.assertEqual(calls[0]["stdout"], "write began")
        self.assertEqual(calls[0]["stderr"], "waiting for acknowledgement")

    def test_unrelated_process_output_is_not_retained(self):
        calls = []
        def fake_process(command, *, stdout, stderr, **kwargs):
            stdout.write(b"private-key RANDID secret-page")
            stderr.write(b"private-key RANDID secret-page")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(firmware.subprocess, "Popen", process_adapter(fake_process)), \
             mock.patch.object(firmware, "BOUND_TOOL", {"path": "picotool"}):
            firmware.ACTIVE_ACTION = calls
            try:
                firmware.run(["pico2-kes-agent-cli", "status"])
                firmware.run(["picotool", "info", "--device", "--debug"])
            finally:
                firmware.ACTIVE_ACTION = None
        self.assertEqual(calls, [])


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.modules["firmware"] = firmware
        spec = importlib.util.spec_from_file_location("publisher", ROOT / "tools/publish_release.py")
        cls.publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.publisher)

    def test_partial_duplicate_or_different_assets_cannot_replace_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release.json").write_bytes(b"manifest")
            (root / "firmware.py").write_bytes(b"verifier")
            complete = {"assets": [{"name": path.name, "size": path.stat().st_size}
                                    for path in root.iterdir()]}
            self.publisher.require_asset_set(complete, root)
            for assets in (complete["assets"][:1], complete["assets"] * 2,
                           [{"name": "unexpected", "size": 8}],
                           [{"name": path.name, "size": 0} for path in root.iterdir()]):
                with self.assertRaises(ValueError):
                    self.publisher.require_asset_set({"assets": assets}, root)


if __name__ == "__main__":
    unittest.main()
