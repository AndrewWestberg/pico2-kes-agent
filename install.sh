#!/bin/sh
set -eu

die() { printf '%s\n' "$*" >&2; exit 1; }

usage() {
    printf '%s\n' 'Usage: sh install.sh [--version TAG | --bundle VERIFIED_DIRECTORY]'
}

fetch() {
    curl -q --proto '=https' --proto-redir '=https' -fsSL \
        --max-filesize "$3" -o "$2" "$1"
}

main() {
    stable_only=false
    bundle=
    case "$#:${1-}" in
        0:) stable_only=true ;;
        1:--help|1:-h) usage; return ;;
        2:--version) tag=${2:?expected a release tag} ;;
        2:--bundle) bundle=${2:?expected a verified bundle directory} ;;
        1:-*) usage >&2; exit 2 ;;
        1:*) bundle=${1:?expected a verified bundle directory} ;;
        *) usage >&2; exit 2 ;;
    esac

    if [ -n "$bundle" ]; then
        bundle=$(CDPATH='' cd -P -- "$bundle" && pwd) || die 'Verified bundle directory not found.'
    else
        repo=AndrewWestberg/pico2-kes-agent
        work=$(mktemp -d /tmp/p2kesup.XXXXXXXX)
        trap 'rm -rf -- "$work"' 0
        trap 'exit 1' HUP INT TERM
        cd "$work"
        for tool in curl python3 sha256sum gpg gpgv openssl readelf; do
            command -v "$tool" >/dev/null || die "Install prerequisite '$tool' and rerun the launcher."
        done
        if "$stable_only"; then
            code=$(curl -q --proto '=https' --proto-redir '=https' -sSL --max-filesize 1048576 \
                -o latest.json -w '%{http_code}' "https://api.github.com/repos/$repo/releases/latest")
            case "$code" in
                404) die 'No qualified stable release is available. For RC testing, pass --version TAG.' ;;
                200) ;;
                *) die "GitHub release discovery failed (HTTP $code)." ;;
            esac
            tag=$(python3 -I -c '
import json, sys
with open("latest.json") as f:
    r = json.load(f)
if r.get("draft") is not False or r.get("prerelease") is not False or not str(r.get("tag_name")).startswith("qualified-v"):
    sys.exit("No qualified stable release is available.")
print(r["tag_name"])')
        fi
        case "$tag" in
            *[!a-zA-Z0-9._-]*|*..*) die 'Invalid release tag.' ;;
            v[0-9]*|qualified-v[0-9]*) ;;
            *) die 'Invalid release tag.' ;;
        esac
        [ "${#tag}" -le 74 ] || die 'Invalid release tag.'

        printf 'Downloading and verifying %s ...\n' "$tag"
        mkdir assets
        for asset in distribution.json distribution.json.sig distribution-authority.json \
                distribution-authority.json.asc release-authority.asc install.sh install.sh.sig distribution.tar; do
            limit=1048576
            [ "$asset" != distribution.tar ] || limit=1074790400
            fetch "https://github.com/$repo/releases/download/$tag/$asset" "assets/$asset" "$limit"
        done

        # Trust the launcher's verifier pins, never Python supplied by the archive.
        revision=a1317050a2853db4721311485c179eaf12959103
        for verifier in publish_release.py firmware.py; do
            fetch "https://raw.githubusercontent.com/$repo/$revision/tools/$verifier" "$verifier" 1048576
        done
        sha256sum --check --status <<'PINS' || die 'Release verifier checksum mismatch.'
42f1a64c9d1294a96a1d7cc1d61b918f8b8d76c382a6722838146bf03106a484  publish_release.py
f31f101aea54cdaa66fc21b44fb37d6066d9991115da90b7439006caf489318b  firmware.py
PINS
        set -- unpack --assets assets --output bundle --publication-tag "$tag"
        if "$stable_only"; then set -- "$@" --stable-only; fi
        python3 -Es publish_release.py "$@"
        bundle=$work/bundle
    fi

    updater=$bundle/bin/p2kesup
    [ -f "$updater" ] && [ -x "$updater" ] || die "Expected an authenticated, extracted release bundle at $bundle"
    "$updater" --version
    printf 'Install under /usr/local? [y/N] ' >/dev/tty
    IFS= read -r answer </dev/tty || die 'Installation requires confirmation in a terminal.'
    case "$answer" in y|Y|yes|YES) ;; *) die 'Installation cancelled.' ;; esac
    sudo -- "$updater" install --bundle "$bundle" </dev/tty
}

# Keep all side effects after the complete function definition for piped downloads.
main "$@"
