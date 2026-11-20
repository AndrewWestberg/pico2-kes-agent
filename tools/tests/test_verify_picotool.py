#!/usr/bin/env python3
"""Tests for picotool digest and GNU build ID verification."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_picotool", ROOT / "tools/verify_picotool.py")
verify_picotool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_picotool)


class VerifyPicotoolTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="test-verify-picotool-")
        self.root = Path(self.temp_dir.name)
        self.committed_manifest = ROOT / "security/picotool-checksums.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_committed_manifest_structure(self):
        self.assertTrue(self.committed_manifest.is_file(), "Manifest file must exist")
        data = json.loads(self.committed_manifest.read_text(encoding="utf-8"))
        self.assertEqual(data.get("schema_version"), 1)
        sha256 = data.get("sha256")
        build_id = data.get("build_id")
        self.assertIsInstance(sha256, str)
        self.assertEqual(len(sha256), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in sha256))
        self.assertIsInstance(build_id, str)
        self.assertTrue(len(build_id) > 0)
        self.assertTrue(all(c in "0123456789abcdef" for c in build_id))

    def _create_fixture_binary(self, content=b"elf-test-content", build_id="aabbccddeeff00112233445566778899aabbccdd"):
        binary = self.root / "mock_picotool"
        binary.write_bytes(content)
        sha256 = verify_picotool.compute_sha256(binary)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": 1,
            "sha256": sha256,
            "build_id": build_id,
        }))
        return binary, manifest, sha256, build_id

    def test_valid_binary_passes(self):
        binary, manifest, sha256, build_id = self._create_fixture_binary()
        with mock.patch.object(verify_picotool, "extract_build_id", return_value=build_id):
            self.assertTrue(verify_picotool.verify_picotool(binary, manifest))
            self.assertEqual(verify_picotool.main([str(binary), str(manifest)]), 0)

    def test_tampered_byte_aborts_with_exit_code_1(self):
        binary, manifest, sha256, build_id = self._create_fixture_binary(content=b"original-content-bytes-123456")
        # Tamper one byte
        data = bytearray(binary.read_bytes())
        data[0] ^= 0x01
        binary.write_bytes(data)

        with mock.patch.object(verify_picotool, "extract_build_id", return_value=build_id):
            self.assertFalse(verify_picotool.verify_picotool(binary, manifest))
            self.assertEqual(verify_picotool.main([str(binary), str(manifest)]), 1)

    def test_mismatched_build_id_aborts_with_exit_code_1(self):
        binary, manifest, sha256, build_id = self._create_fixture_binary()
        with mock.patch.object(verify_picotool, "extract_build_id", return_value="deadbeef12345678"):
            self.assertFalse(verify_picotool.verify_picotool(binary, manifest))
            self.assertEqual(verify_picotool.main([str(binary), str(manifest)]), 1)

    def test_missing_binary_aborts_with_exit_code_1(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema_version": 1, "sha256": "aa" * 32, "build_id": "bb" * 20}))
        nonexistent = self.root / "does_not_exist"
        self.assertFalse(verify_picotool.verify_picotool(nonexistent, manifest))
        self.assertEqual(verify_picotool.main([str(nonexistent), str(manifest)]), 1)

    def test_missing_manifest_aborts_with_exit_code_1(self):
        binary = self.root / "binary"
        binary.write_bytes(b"data")
        nonexistent = self.root / "does_not_exist.json"
        self.assertFalse(verify_picotool.verify_picotool(binary, nonexistent))
        self.assertEqual(verify_picotool.main([str(binary), str(nonexistent)]), 1)

    def test_malformed_manifest_aborts_with_exit_code_1(self):
        binary = self.root / "binary"
        binary.write_bytes(b"data")
        manifest = self.root / "bad.json"
        for bad_content in ["not json", "[]", "{}", '{"sha256": ""}', '{"build_id": ""}']:
            manifest.write_text(bad_content)
            self.assertFalse(verify_picotool.verify_picotool(binary, manifest))
            self.assertEqual(verify_picotool.main([str(binary), str(manifest)]), 1)

    def test_extract_build_id_fails_when_no_build_id(self):
        binary = self.root / "no_build_id_binary"
        binary.write_bytes(b"not an elf")
        self.assertIsNone(verify_picotool.extract_build_id(binary))

    def test_never_executes_target_binary(self):
        binary, manifest, sha256, build_id = self._create_fixture_binary()
        executed_commands = []
        original_run = subprocess.run

        def tracking_run(cmd, *args, **kwargs):
            executed_commands.append(cmd)
            # Only readelf is allowed
            if cmd[0] == "readelf":
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=f"  Build ID: {build_id}\n".encode(), stderr=b""
                )
            return original_run(cmd, *args, **kwargs)

        with mock.patch("subprocess.run", side_effect=tracking_run):
            result = verify_picotool.verify_picotool(binary, manifest)
            self.assertTrue(result)
            self.assertEqual(len(executed_commands), 1)
            self.assertEqual(executed_commands[0][0], "readelf")
            self.assertNotIn(str(binary), [c[0] for c in executed_commands])

    def test_against_real_built_picotool_if_present(self):
        candidates = [
            Path("/home/runner/work/pico2-kes-agent/pico2-kes-agent/release-build/toolchain/bin/picotool"),
            ROOT / "release-build/toolchain/bin/picotool",
        ]
        for candidate in candidates:
            if candidate.is_file():
                self.assertTrue(verify_picotool.verify_picotool(candidate, self.committed_manifest))
                break


if __name__ == "__main__":
    unittest.main()
