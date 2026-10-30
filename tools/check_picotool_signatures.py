#!/usr/bin/env python3
"""Exercise the signature converters from the actual built picotool archive."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    args = parser.parse_args()
    executable = args.build.resolve() / "signature-conversion-test"
    subprocess.run([
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        '-DMBEDTLS_CONFIG_FILE="picotool_mbedtls_config.h"',
        "-I", str(args.source / "bintool"),
        "-I", str(args.source / "lib/include"),
        "-I", str(args.sdk / "lib/mbedtls/include"),
        str(Path(__file__).resolve().parent / "tests/picotool_signatures.c"),
        str(args.build / "bintool/libbintool.a"),
        str(args.build / "lib/libmbedtls.a"),
        "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
