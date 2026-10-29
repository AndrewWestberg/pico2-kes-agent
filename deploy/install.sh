#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DESTDIR=${DESTDIR:-}
if [ -n "$DESTDIR" ]; then
    case "$DESTDIR" in
        /*) ;;
        *) echo "DESTDIR must be absolute" >&2; exit 1 ;;
    esac
elif [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root unless DESTDIR is set" >&2
    exit 1
fi

DAEMON="$ROOT/target/release/pico2-kes-agentd"
CLI="$ROOT/target/release/pico2-kes-agent-cli"
for binary in "$DAEMON" "$CLI"; do
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
        echo "missing release binary: $binary" >&2
        echo "run: cargo build --locked --release --bin pico2-kes-agentd --bin pico2-kes-agent-cli" >&2
        exit 1
    fi
done

if [ -z "$DESTDIR" ]; then
    if ! getent group pico2-kes-agent >/dev/null; then
        groupadd --system pico2-kes-agent
    fi
    if ! getent passwd pico2-kes-agent >/dev/null; then
        useradd --system --gid pico2-kes-agent --home-dir /var/lib/pico2-kes-agent \
            --no-create-home --shell /usr/sbin/nologin pico2-kes-agent
    fi
fi

install -D -m 0755 "$DAEMON" "$DESTDIR/usr/bin/pico2-kes-agentd"
install -D -m 0755 "$CLI" "$DESTDIR/usr/bin/pico2-kes-agent-cli"
install -D -m 0755 "$ROOT/deploy/pico2-kes-agent-host-check" "$DESTDIR/usr/libexec/pico2-kes-agent-host-check"
install -D -m 0644 "$ROOT/deploy/pico2-kes-agentd.service" "$DESTDIR/usr/lib/systemd/system/pico2-kes-agentd.service"
install -D -m 0644 "$ROOT/deploy/70-pico2-kes-agent.rules" "$DESTDIR/usr/lib/udev/rules.d/70-pico2-kes-agent.rules"
install -d -m 0750 "$DESTDIR/etc/pico2-kes-agent"
if [ ! -e "$DESTDIR/etc/pico2-kes-agent/config.json" ]; then
    install -m 0640 "$ROOT/deploy/config.example.json" "$DESTDIR/etc/pico2-kes-agent/config.json"
    echo "created /etc/pico2-kes-agent/config.json; install the attended device pin before normal startup"
else
    echo "preserved existing /etc/pico2-kes-agent/config.json"
fi
install -d -m 0700 "$DESTDIR/var/lib/pico2-kes-agent"

if [ -z "$DESTDIR" ]; then
    chown root:pico2-kes-agent /etc/pico2-kes-agent /etc/pico2-kes-agent/config.json
    chown pico2-kes-agent:pico2-kes-agent /var/lib/pico2-kes-agent
    systemctl daemon-reload
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=usb --action=add
    systemctl enable pico2-kes-agentd.service
fi

echo "installed pico2-kes-agentd and pico2-kes-agent-cli${DESTDIR:+ under $DESTDIR}"
if [ -z "$DESTDIR" ]; then
    echo "review /etc/pico2-kes-agent/config.json, then run: systemctl start pico2-kes-agentd"
fi
