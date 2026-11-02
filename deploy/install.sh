#!/bin/sh
set -eu
# The bootstrap authenticates the bundle and stages the manager before privilege handoff.
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$dir/bootstrap/install.sh" ]; then
    exec /bin/sh "$dir/bootstrap/install.sh" "$@"
fi
if [ -f "$dir/../install.sh" ]; then
    exec /bin/sh "$dir/../install.sh" "$@"
fi
echo 'Authenticated bootstrap is unavailable; obtain and independently verify install.sh.' >&2
exit 4
