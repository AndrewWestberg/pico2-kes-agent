#!/bin/sh
set -eu
if [ "$#" -ne 0 ]; then
    echo 'Usage: sh uninstall.sh' >&2
    exit 2
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo 'Uninstall requires an attended manager review.' >&2
    exit 3
fi
echo 'Select components in the manager uninstall review. Configuration, identity, journal, receipts, records, service account, device storage and producer drop-ins are retained; removal does not erase or revoke keys.' >&2
exec /usr/bin/p2kesup
