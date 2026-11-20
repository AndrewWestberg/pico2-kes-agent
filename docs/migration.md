# Migration Guide: Legacy `pico2-kes-agent-cli` → `p2kes`, `p2kesup`, `p2kes-flash`

| Legacy | New | Notes |
|--------|-----|-------|
| `pico2-kes-agent-cli` | `p2kes` | 10-workflow operator CLI; implicit revision/incarnation/staged-generation resolution; no `--receipt` or `--expected-peer-*` flags |
| `pico2-kes-agent-cli` TUI | Removed | Replaced by `p2kes status` and `p2kesup status` |
| `p2kesup` (old) | `p2kesup` | Atomic `/usr/local` install/update/uninstall/status; never mutates systemd or `/etc/fstab` |
| `tools/firmware.py` | `p2kes-flash` | Native Rust `verify`, `flash`, `wipe`, `otp` (no Python on operator hosts) |
| `p2kes backup restore` (9 flags) | `p2kes backup restore --artifact FILE --key FILE --device-identity FILE --out FILE` | Reads bindings from signed CBOR artifact header |
