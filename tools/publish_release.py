#!/usr/bin/env python3
"""Publish an already verified bundle; never repair or overwrite a release."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import quote

import firmware

REPOSITORY = "AndrewWestberg/pico2-kes-agent"
NOTES = """Native RP2350 signed firmware; profile rp2350-signed-msd-v1.

Verify the GPG-authorized boot authority and signed manifest before executing
downloaded tooling or copying the signed UF2. Normal updates preserve storage
version 2 and all state at [0x10100000,0x10308000); never erase or recommission.

A2 qualification is scoped to candidate-matching measured security evidence, not
the presence of a signature. A4 is expected-compatible and not physically
validated. A2 interrupted-update recovery covers supported generated images and
qualified transfer interruptions, not arbitrary malformed metadata. Neither
signatures nor secure boot establish live forging or invasive-extraction safety.

GPG authorizes the single boot authority; releases are not individually GPG-signed.
Repository/workflow/tag access is signing authority: every pushed v* tag signs,
without branch, signed-tag, or protected-environment approval gates.
"""


def gh(*arguments):
    return firmware.run(["gh", *arguments], timeout=180)[0]


def release_state(tag):
    # The by-tag REST endpoint omits drafts, even with authenticated access.
    # Enumerate all authenticated pages, projecting only admission fields before
    # the bounded subprocess capture. Multiple matches remain a parse conflict.
    query = (".[] | select(.tag_name == " + json.dumps(tag) + ") | "
             "{tag_name, draft, prerelease, assets: [.assets[] | {name, size}]}")
    data = gh("api", f"repos/{REPOSITORY}/releases", "--paginate", "--jq", query)
    if not data.strip():
        return None
    return json.loads(data, object_pairs_hook=firmware.unique_object)


def require_asset_set(release, bundle):
    assets = release.get("assets")
    firmware.require(type(assets) is list, "missing release assets")
    expected = {path.name: path.stat().st_size for path in bundle.iterdir()}
    actual = {}
    for asset in assets:
        name = asset.get("name")
        firmware.require(type(name) is str and name in expected and name not in actual,
                         "unexpected or duplicate published asset")
        actual[name] = asset.get("size")
    firmware.require(actual == expected, "partial/different release; explicit maintainer action required")


def compare_download(tag, bundle):
    with tempfile.TemporaryDirectory(prefix="pico2-release-download-") as directory:
        gh("release", "download", tag, "--repo", REPOSITORY, "--dir", directory)
        downloaded = Path(directory)
        firmware.verify_bundle(downloaded)
        firmware.require({p.name for p in downloaded.iterdir()} == {p.name for p in bundle.iterdir()},
                         "downloaded asset set differs")
        for path in bundle.iterdir():
            firmware.require(firmware.bounded_file(path, firmware.MAX_ELF)
                             == firmware.bounded_file(downloaded / path.name, firmware.MAX_ELF),
                             "different historical artifact; refusing overwrite")


def publish(bundle, tag, commit):
    bundle = Path(bundle)
    manifest = firmware.verify_bundle(bundle)
    firmware.require(manifest["tag"] == tag and manifest["commit"] == commit,
                     "bundle does not match triggering tag/commit")
    # Commit responses include every changed-file patch; retain only the identity
    # needed here before applying the subprocess diagnostic bound.
    target = json.loads(gh("api", f"repos/{REPOSITORY}/commits/{quote(tag, safe='')}",
                           "--jq", "{sha: .sha}"))
    firmware.require(target.get("sha") == commit, "triggering tag moved or resolves to another commit")
    prerelease = "-" in tag
    classification_args = ("--prerelease", "--latest=false") if prerelease else ()
    existing = release_state(tag)
    if existing is not None:
        firmware.require(existing.get("tag_name") == tag and existing.get("draft") is False,
                         "pre-existing draft/partial release; explicit maintainer action required")
        firmware.require(existing.get("prerelease") is prerelease,
                         "pre-existing release has conflicting prerelease classification")
        require_asset_set(existing, bundle)
        compare_download(tag, bundle)
        print("Identical completed release already exists; no changes.")
        return
    with tempfile.TemporaryDirectory(prefix="pico2-release-notes-") as temporary:
        notes = Path(temporary) / "notes.txt"
        notes.write_text(NOTES, encoding="utf-8")
        gh("release", "create", tag, "--repo", REPOSITORY, "--verify-tag", "--target", commit,
           "--draft", "--title", tag, "--notes-file", notes, *classification_args)
    # Any failure leaves a reported draft, never a published partial bundle.
    gh("release", "upload", tag, "--repo", REPOSITORY,
       *(bundle / name for name in (*firmware.ARTIFACTS, "release.json", "release.json.sig")))
    uploaded = release_state(tag)
    firmware.require(uploaded is not None and uploaded.get("draft") is True, "draft release changed")
    firmware.require(uploaded.get("prerelease") is prerelease, "draft classification changed")
    require_asset_set(uploaded, bundle)
    compare_download(tag, bundle)
    target = json.loads(gh("api", f"repos/{REPOSITORY}/commits/{quote(tag, safe='')}",
                           "--jq", "{sha: .sha}"))
    firmware.require(target.get("sha") == commit, "triggering tag moved during upload; draft retained")
    gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", *classification_args)
    print("Verified complete release published.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    firmware.require(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is unavailable")
    publish(args.bundle, args.tag, args.commit)


if __name__ == "__main__":
    main()
