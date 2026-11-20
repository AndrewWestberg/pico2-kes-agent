#!/usr/bin/env python3
"""Verify picotool artifact digest and GNU build ID against committed manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def extract_build_id(binary_path):
    """Extract GNU build ID using readelf -n without executing the binary."""
    try:
        proc = subprocess.run(
            ["readelf", "-n", str(binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        notes = proc.stdout
    except subprocess.CalledProcessError as err:
        sys.stderr.write(f"readelf failed with exit code {err.returncode}: {err.stderr.decode(errors='replace')}\n")
        return None
    except FileNotFoundError:
        sys.stderr.write("readelf executable not found in PATH\n")
        return None

    ids = re.findall(rb"Build ID:\s*([0-9a-fA-F]+)", notes)
    if len(ids) != 1:
        sys.stderr.write(f"picotool GNU build ID unavailable (found {len(ids)} IDs in notes)\n")
        return None

    return ids[0].decode("ascii").lower()


def compute_sha256(binary_path):
    """Compute cryptographic SHA-256 digest of binary without executing it."""
    hasher = hashlib.sha256()
    with open(binary_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_picotool(binary_path, manifest_path):
    """Verify picotool binary against committed manifest. Return True on success, False on failure."""
    binary_path = Path(binary_path)
    manifest_path = Path(manifest_path)

    if not manifest_path.is_file():
        sys.stderr.write(f"Checksum manifest not found: {manifest_path}\n")
        return False

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as err:
        sys.stderr.write(f"Failed to read/parse checksum manifest {manifest_path}: {err}\n")
        return False

    if isinstance(manifest_data, dict):
        expected_sha256 = (manifest_data.get("sha256") or manifest_data.get("digest") or "").strip().lower()
        expected_build_id = (manifest_data.get("build_id") or manifest_data.get("gnu_build_id") or "").strip().lower()
    else:
        sys.stderr.write("Checksum manifest must be a JSON object\n")
        return False

    if not expected_sha256 or not expected_build_id:
        sys.stderr.write("Checksum manifest missing required 'sha256' or 'build_id' values\n")
        return False

    if not binary_path.is_file():
        sys.stderr.write(f"Target binary not found or not a regular file: {binary_path}\n")
        return False

    actual_sha256 = compute_sha256(binary_path)
    if actual_sha256 != expected_sha256:
        sys.stderr.write(
            f"picotool SHA-256 digest verification failed:\n"
            f"  expected: {expected_sha256}\n"
            f"  actual:   {actual_sha256}\n"
        )
        return False

    actual_build_id = extract_build_id(binary_path)
    if actual_build_id is None:
        sys.stderr.write("Failed to extract GNU build ID from picotool\n")
        return False

    if actual_build_id != expected_build_id:
        sys.stderr.write(
            f"picotool GNU build ID verification failed:\n"
            f"  expected: {expected_build_id}\n"
            f"  actual:   {actual_build_id}\n"
        )
        return False

    sys.stdout.write(
        f"picotool integrity verified successfully:\n"
        f"  path:     {binary_path}\n"
        f"  sha256:   {actual_sha256}\n"
        f"  build_id: {actual_build_id}\n"
    )
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        nargs="?",
        default="release-build/toolchain/bin/picotool",
        type=Path,
        help="Path to picotool executable (default: release-build/toolchain/bin/picotool)",
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        default="security/picotool-checksums.json",
        type=Path,
        help="Path to checksums manifest JSON (default: security/picotool-checksums.json)",
    )
    parser.add_argument("--binary-path", dest="binary_opt", type=Path, help="Explicit path to binary")
    parser.add_argument("--manifest-path", dest="manifest_opt", type=Path, help="Explicit path to manifest")

    args = parser.parse_args(argv)
    binary = args.binary_opt or args.binary
    manifest = args.manifest_opt or args.manifest

    success = verify_picotool(binary, manifest)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
