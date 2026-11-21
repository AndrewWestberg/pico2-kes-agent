#!/bin/sh
set -eu

# Thin POSIX bootstrapper for pico2-kes-agent.
# Run only from a release bundle authenticated before extraction.

BUNDLE_DIR="${1:-.}"
UPDATER="$BUNDLE_DIR/bin/p2kesup"
if [ ! -f "$UPDATER" ] || [ ! -x "$UPDATER" ]; then
    echo "Expected an authenticated, extracted release bundle at $BUNDLE_DIR" >&2
    exit 1
fi

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

exec sudo -- "$UPDATER" install --bundle "$BUNDLE_DIR"
