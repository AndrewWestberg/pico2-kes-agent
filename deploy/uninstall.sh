#!/bin/sh
set -eu

DESTDIR=${DESTDIR:-}
if [ -n "$DESTDIR" ]; then
    case "$DESTDIR" in
        /*) ;;
        *) echo "DESTDIR must be absolute" >&2; exit 1 ;;
    esac
elif [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root unless DESTDIR is set" >&2
    exit 1
fi

if [ -z "$DESTDIR" ]; then
    systemctl disable --now pico2-kes-agentd.service 2>/dev/null || true
fi
rm -f "$DESTDIR/usr/bin/pico2-kes-agentd" "$DESTDIR/usr/bin/pico2-kes-agent-cli"
rm -f "$DESTDIR/usr/libexec/pico2-kes-agent-host-check"
rm -f "$DESTDIR/usr/lib/systemd/system/pico2-kes-agentd.service"
rm -f "$DESTDIR/usr/lib/udev/rules.d/70-pico2-kes-agent.rules"
if [ -z "$DESTDIR" ]; then
    systemctl daemon-reload
    udevadm control --reload-rules
fi

cat <<MESSAGE
Removed binaries, systemd unit, and udev rule${DESTDIR:+ under $DESTDIR}.
Preserved:
  $DESTDIR/etc/pico2-kes-agent
  $DESTDIR/var/lib/pico2-kes-agent
  pico2-kes-agent user and group
  enrolled device storage
Remove preserved host data manually only after confirming it is no longer needed.
MESSAGE
