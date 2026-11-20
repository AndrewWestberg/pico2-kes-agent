#!/bin/sh
set -eu

# Thin POSIX bootstrapper for pico2-kes-agent.
# Verifies release bundle and delegates installation to p2kesup.

BUNDLE_DIR="${1:-.}"

if command -v apt-get >/dev/null 2>&1; then
    echo "Checking system packages (dry-run):" >/dev/tty 2>/dev/null || true
    apt-get --simulate install -y usbutils >/dev/tty 2>/dev/null || true
    printf "Continue with installation? [y/N]: " >/dev/tty 2>/dev/null || true
    read -r ans </dev/tty || ans="n"
    case "$ans" in
        y|Y|yes|YES) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

if [ -f "$BUNDLE_DIR/release-manifest.json.asc" ] && [ -f "$BUNDLE_DIR/release-keyring.gpg" ]; then
    gpgv --keyring "$BUNDLE_DIR/release-keyring.gpg" \
        "$BUNDLE_DIR/release-manifest.json.asc" \
        "$BUNDLE_DIR/release-manifest.json"
fi

exec sudo "$BUNDLE_DIR/p2kesup" install --bundle "$BUNDLE_DIR"
