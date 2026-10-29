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
            record = {"schema_version": 1, "serial": "00afd9003906a634",
                      "profile": firmware.PROFILE, "bundle_sha256": "11"*32,
                      "bootkey_sha256": "22"*32, "tool_version": "fixture",
                      "completed_stage": None, "pending": None, "observations": []}
            firmware.save_record(path, record, create=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                firmware.save_record(path, record, create=True)
            def lost_after_write():
                raise OSError("connection lost after potentially applied fuse")
            with self.assertRaises(firmware.ToolError) as caught:
                firmware.record_action(path, record, "enable", lost_after_write, lambda: {})
            self.assertEqual(caught.exception.code, 6)
            self.assertEqual(json.loads(path.read_text())["pending"], "enable")
            with self.assertRaises(ValueError):
                firmware.owner_record(path)

    def test_public_row_parser_rejects_warnings_duplicates_and_secret_rows(self):
        valid = b"ROW 0x0040: OTP_DATA_CRIT1 (CRIT)\n    VALUE 0x000000\n"
        self.assertEqual(firmware.parse_public_rows(valid, (0x40,)), {0x40: 0})
        for value in (valid + valid, valid.replace(b"VALUE", b"WARNING VALUE"),
                      valid.replace(b"0x0040", b"0x0000"), valid.replace(b"000000", b"-1")):
            with self.assertRaises(ValueError):
                firmware.parse_public_rows(value, (0x40,))


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
