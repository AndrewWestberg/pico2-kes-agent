#!/usr/bin/env python3
"""Publish an already verified bundle; never repair or overwrite a release."""
import argparse
import json
import os
import hashlib
import shutil
import stat
import selectors
import signal
import subprocess
import time
import sys
import tarfile
from datetime import datetime, timezone
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
        # The tag already pins the source; --target unnecessarily requires workflow-write authority.
        gh("release", "create", tag, "--repo", REPOSITORY, "--verify-tag",
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

PURPOSE = "pico2-kes-agent-distribution-v1"
COMPONENT_PATHS = {
    "manager": "bin/p2kesup",
    "daemon": "bin/pico2-kes-agentd",
    "cli": "bin/pico2-kes-agent-cli",
    "firmware": "firmware/pico2-kes-firmware.signed.uf2",
    "tool": "tools/picotool",
    "deployment": "deploy/install.sh",
}
RUNTIME_PACKAGES = {
    "runtime/libusb-1.0.so.0": "libusb-1.0-0",
    "runtime/libudev.so.1": "libudev1",
    "runtime/libstdc++.so.6": "libstdc++6",
    "runtime/libgcc_s.so.1": "libgcc-s1",
}
REQUIRED_ASSETS = set(COMPONENT_PATHS.values()) | {
    "install.sh", "tools/firmware.py", "deploy/uninstall.sh",
    "deploy/pico2-kes-agentd.service", "deploy/70-pico2-kes-agent.rules",
    "deploy/pico2-kes-agent-host-check", "deploy/cardano-node-memory-hardening.conf",
    "licenses/picotool.txt", "licenses/mbedtls.txt", "licenses/libusb-1.0-0.txt",
    "licenses/libudev1.txt", "licenses/libstdc++6.txt", "licenses/libgcc-s1.txt",
    "runtime/libusb-1.0.so.0", "runtime/libudev.so.1",
    "runtime/libstdc++.so.6", "runtime/libgcc_s.so.1", "runtime/provenance.json",
} | {"firmware/" + n for n in (*firmware.ARTIFACTS, "release.json", "release.json.sig")}
GATES = tuple(f"Q{i}.md" for i in range(1, 12)) + (
    "developer-checks.md", "performance.md", "security-review.md", "acceptance.md")


def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def component_digest(name, artifacts):
    def belongs(path):
        if name in ("manager", "daemon", "cli"):
            return path == COMPONENT_PATHS[name]
        prefixes = {"firmware": ("firmware/",), "tool": ("tools/", "runtime/", "licenses/"),
                    "deployment": ("deploy/",)}
        return path.startswith(prefixes[name]) or (name == "deployment" and path == "install.sh")

    digest = hashlib.sha256()
    for entry in sorted((item for item in artifacts if belongs(item["path"])), key=lambda item: item["path"]):
        digest.update((entry["path"] + "\0" + str(entry["size_bytes"]) + "\0" +
                       entry["sha256"] + "\0" + str(entry["mode"]) + "\n").encode("utf-8"))
    return digest.hexdigest()


def validate_tuples(tuples):
    firmware.require(type(tuples) is list and 0 < len(tuples) <= 256, "invalid compatibility tuples")
    seen = set()
    for tuple_ in tuples:
        firmware.require(type(tuple_) is dict and set(tuple_) == set(COMPONENT_PATHS) and
                         all(type(value) is str and len(value) == 64 and
                             all(c in "0123456789abcdef" for c in value)
                             for value in tuple_.values()), "invalid compatibility tuple")
        key = tuple(tuple_[name] for name in COMPONENT_PATHS)
        firmware.require(key not in seen, "duplicate compatibility tuple")
        seen.add(key)


def host_version(path):
    process = subprocess.Popen([str(path), "--version", "--json"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                               start_new_session=True)
    deadline = time.monotonic() + 10
    output = bytearray()
    selector = selectors.DefaultSelector()
    complete = False
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        eof = False
        while not (eof and process.poll() is not None):
            remaining = deadline - time.monotonic()
            firmware.require(remaining > 0, "host version inspection timed out")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(process.stdout)
                    eof = True
                else:
                    output.extend(chunk)
                    firmware.require(len(output) <= 4096, "host version output too large")
        firmware.require(process.returncode == 0, "host version inspection failed")
        result = json.loads(output, object_pairs_hook=firmware.unique_object)
        firmware.exact_keys(result, ("schema_version", "component", "version", "build_id", "source_commit"))
        firmware.require(type(result["schema_version"]) is int and result["schema_version"] == 1,
                         "unsupported host build identity")
        complete = True
        return result
    finally:
        if not complete:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        selector.close()
        process.stdout.close()


def require_host_builds(root, tag, commit, build_id):
    for name in ("p2kesup", "pico2-kes-agentd", "pico2-kes-agent-cli"):
        identity = host_version(Path(root) / "bin" / name)
        firmware.require(identity == {"schema_version": 1, "component": name, "version": tag,
                                      "build_id": build_id, "source_commit": commit},
                         "host component build identity mismatch")


def payload_files(root):
    root = Path(root)
    firmware.require(root.is_dir() and not root.is_symlink(), "invalid bundle directory")
    files = []
    directories = 0
    def fail(error):
        raise error
    for base, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        directories += len(dirs)
        firmware.require(directories <= 1024, "too many bundle directories")
        firmware.require(base == str(root) or dirs or names, "empty bundle directory")
        for name in dirs:
            path = Path(base) / name
            firmware.require(not path.is_symlink(), "bundle directory link")
        for name in names:
            path = Path(base) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            firmware.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                             "bundle link or special file")
            firmware.require(len(relative.encode()) <= 240 and
                             all(part not in ("", ".", "..") for part in relative.split("/")) and
                             all(32 <= ord(c) < 127 and c != "\\" for c in relative),
                             "invalid artifact path")
            firmware.require(metadata.st_size <= 256 * 1024 * 1024, "artifact too large")
            files.append((relative, path, metadata))
            firmware.require(len(files) <= 258, "too many artifacts")
    firmware.require(sum(item[2].st_size for item in files) <= 1024 ** 3,
                     "bundle too large")
    return sorted(files)


def verify_detached(data, signature, certificate, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    for path, limit in ((data, 256 * 1024 * 1024), (signature, 1024 * 1024),
                        (certificate, 1024 * 1024)):
        metadata = Path(path).lstat()
        firmware.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and
                         metadata.st_size <= limit, "unsafe signature input")
    with tempfile.TemporaryDirectory(prefix="p2kes-distribution-gpg-") as directory:
        keyring = Path(directory) / "authority.gpg"
        firmware.run(["gpg", "--batch", "--no-options", "--dearmor", "--output",
                      keyring, certificate])
        status, _ = firmware.run(["gpgv", "--homedir", directory, "--keyring", keyring,
                                  "--status-fd", "1", signature, data], failure_code=5)
    text = status.decode("ascii")
    valid = [line.split() for line in text.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    firmware.require(len(valid) == 1 and len(valid[0]) == 12 and
                     valid[0][2] == trust[1] and valid[0][11] == trust[0] and
                     not any("[GNUPG:] " + x in text for x in
                             ("REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG")),
                     "unauthorized distribution signature")


def sign_detached(path, certificate, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    signature = path.with_name(path.name + ".asc")
    firmware.require(not os.path.lexists(signature), "signature already exists")
    firmware.run(["gpg", "--batch", "--armor", "--detach-sign", "--local-user",
                  trust[1] + "!", "--output", signature, path], timeout=300)
    verify_detached(path, signature, certificate, trust=trust)
    signature.chmod(0o644)


def require_promotion_identity(candidate, approved):
    firmware.require(candidate["qualification"] == "candidate", "only a candidate may be promoted")
    payloads = {entry["path"]: entry["sha256"] for entry in candidate["artifacts"]}
    firmware.require(len(payloads) == len(candidate["artifacts"]) and
                     approved["source_commit"] == candidate["release"]["source_commit"] and
                     approved["payloads"] == payloads, "promotion source or payload mismatch")


def artifact_class(path):
    prefix = path.split("/", 1)[0]
    return {"bin": "bin", "firmware": "firmware", "tools": "tool",
            "deploy": "deployment", "licenses": "license", "runtime": "runtime"}.get(prefix, "bootstrap")


def prepare_distribution(payload, output, tag, commit, build_id, *, compatible_tuples=None,
                         trust=(firmware.PRIMARY, firmware.SIGNER)):
    payload, output = Path(payload), Path(output)
    files = payload_files(payload)
    firmware.require({name for name, _, _ in files} >= REQUIRED_ASSETS, "missing distribution payload")
    firmware.require(not any(name in ("distribution.json", "distribution.json.asc", "install.sh.asc")
                             for name, _, _ in files), "payload already contains signed metadata")
    firmware.require(not os.path.lexists(output), "output already exists")
    inner = firmware.verify_bundle(payload / "firmware", trust=trust)
    firmware.require(inner["tag"] == tag and inner["commit"] == commit, "firmware source identity differs")
    firmware.require(tag.startswith("v") and 0 < len(tag) <= 64 and
                     len(commit) in (40, 64) and all(c in "0123456789abcdef" for c in commit) and
                     0 < len(build_id) <= 64 and all(32 < ord(c) < 127 for c in build_id),
                     "invalid build identity")
    output.mkdir(mode=0o700)
    try:
        for name, path, metadata in files:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target, follow_symlinks=False)
            target.chmod(0o755 if metadata.st_mode & 0o111 else 0o644)
        require_host_builds(output, tag, commit, build_id)
        # This phase runs only in the no-signing-secret build environment.
        artifacts = [{"path": name, "size_bytes": meta.st_size, "sha256": digest_file(path),
                      "class": artifact_class(name), "mode": stat.S_IMODE(meta.st_mode)}
                     for name, path, meta in payload_files(output)]
        components = [{"name": name, "version": "2.3.1" if name == "tool" else tag,
                       "build_id": build_id, "artifact": path,
                       "digest": component_digest(name, artifacts)} for name, path in COMPONENT_PATHS.items()]
        tuple_ = {c["name"]: c["digest"] for c in components}
        firmware.require(compatible_tuples is None or
                         (type(compatible_tuples) is list and len(compatible_tuples) <= 255),
                         "invalid compatible tuples input")
        additional = []
        for item in compatible_tuples or []:
            firmware.require(type(item) is dict and set(item) == set(COMPONENT_PATHS),
                             "invalid compatible tuple input")
            additional.append({name: tuple_[name] if value == "current" else value
                               for name, value in item.items()})
        tuples = [tuple_, *additional]
        validate_tuples(tuples)
        packages = [{"id": id_, "version": version,
                     "names": ["binutils", "ca-certificates", "curl", "gnupg", "openssl", "pkexec", "python3"]}
                    for id_, version in (("debian", "12"), ("ubuntu", "24.04"))]
        manifest = {
            "schema_version": 1, "purpose": PURPOSE,
            "release": {"tag": tag, "version": tag, "source_commit": commit, "build_id": build_id,
                        "channel": "prerelease" if "-" in tag else "stable",
                        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            "platform": {"target": "x86_64-unknown-linux-gnu", "glibc_min": "2.36",
                         "os": [{"id": p["id"], "version": p["version"]} for p in packages],
                         "systemd": True, "udev": True},
            "components": components, "artifacts": artifacts,
            "compatibility": {"tuples": tuples, "readable_schemas": {
                "config": [1], "journal": [1], "receipt": [1], "installation": [1]},
                "management_actions": ["host.observe", "device.info", "pool.observe"],
                "usb_profiles": ["usb-protocol-1"], "storage_versions": [2],
                "security_profiles": ["unlocked", "rp2350-signed-msd-v1"], "hardware": ["rp2350-a2", "rp2350-a4"]},
            "qualification": "candidate", "promotion": None,
            "prerequisites": [{"operation": "install", "tool": "python3", "version": "3",
                               "packages": packages, "artifact": None},
                              {"operation": "install", "tool": "pkexec", "version": "polkit",
                               "packages": [{"id": p["id"], "version": p["version"], "names": ["pkexec"]} for p in packages], "artifact": None},
                              {"operation": "firmware", "tool": "readelf", "version": "gnu-build-id",
                               "packages": [{"id": p["id"], "version": p["version"], "names": ["binutils"]} for p in packages], "artifact": None},
                              {"operation": "firmware", "tool": "picotool", "version": "2.3.1",
                               "packages": [{"id": p["id"], "version": p["version"], "names": ["binutils", "openssl", "python3"]} for p in packages], "artifact": "tools/picotool"}],
            "preservation": {"firmware_start": 0x10000000, "firmware_end": 0x10100000,
                             "state_start": 0x10100000, "state_end": 0x10308000,
                             "migration": "none", "retained": ["config", "state", "identity", "receipt"]},
        }
        metadata = output / "prepared.json"
        data = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode()
        firmware.require(len(data) <= 1024 * 1024, "manifest too large")
        metadata.write_bytes(data)
        validate_prepared(output, tag, commit, build_id)
    except BaseException:
        shutil.rmtree(output)
        raise
    return manifest


def validate_distribution_manifest(manifest):
    firmware.exact_keys(manifest, ("schema_version", "purpose", "release", "platform", "components",
                                   "artifacts", "compatibility", "qualification", "promotion", "prerequisites", "preservation"))
    firmware.require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and
                     manifest["purpose"] == PURPOSE and manifest["qualification"] in ("candidate", "qualified"),
                     "unsupported distribution")
    promotion = manifest["promotion"]
    if manifest["qualification"] == "candidate":
        firmware.require(promotion is None, "candidate cannot claim promotion")
    else:
        firmware.exact_keys(promotion, ("candidate_sha256", "approval_sha256"))
        firmware.require(all(type(value) is str and len(value) == 64 and
                             all(c in "0123456789abcdef" for c in value)
                             for value in promotion.values()), "invalid promotion linkage")
    release = manifest["release"]
    firmware.exact_keys(release, ("tag", "version", "source_commit", "build_id", "channel", "published_at"))
    firmware.require(all(type(value) is str and value and len(value) <= 255 and
                         all(32 <= ord(c) < 127 for c in value) for value in release.values()) and
                     len(release["source_commit"]) in (40, 64) and
                     all(c in "0123456789abcdef" for c in release["source_commit"]) and
                     release["channel"] in ("stable", "prerelease"), "invalid release")
    timestamp = release["published_at"]
    firmware.require(len(timestamp) == 20 and
                     datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == timestamp,
                     "invalid publication time")
    platform = manifest["platform"]
    firmware.exact_keys(platform, ("target", "glibc_min", "os", "systemd", "udev"))
    firmware.require(platform["target"] == "x86_64-unknown-linux-gnu" and platform["glibc_min"] == "2.36" and
                     platform["systemd"] is True and platform["udev"] is True and
                     type(platform["os"]) is list and len(platform["os"]) == 2, "unsupported platform")
    for item in platform["os"]:
        firmware.exact_keys(item, ("id", "version"))
    firmware.require({(item["id"], item["version"]) for item in platform["os"]} ==
                     {("debian", "12"), ("ubuntu", "24.04")}, "unsupported OS")
    compatibility = manifest["compatibility"]
    firmware.exact_keys(compatibility, ("tuples", "readable_schemas", "management_actions", "usb_profiles",
                                        "storage_versions", "security_profiles", "hardware"))
    schemas = compatibility["readable_schemas"]
    firmware.exact_keys(schemas, ("config", "journal", "receipt", "installation"))
    firmware.require(all(type(values) is list and all(type(v) is int for v in values) and 1 in values
                         for values in schemas.values()), "unsupported readable schemas")
    validate_tuples(compatibility["tuples"])
    firmware.require(type(compatibility["storage_versions"]) is list and
                     all(type(v) is int for v in compatibility["storage_versions"]) and
                     2 in compatibility["storage_versions"], "invalid compatibility")
    for field in ("management_actions", "usb_profiles", "security_profiles", "hardware"):
        values = compatibility[field]
        firmware.require(type(values) is list and values and all(type(v) is str and v for v in values),
                         "missing compatibility profile")
    firmware.require("usb-protocol-1" in compatibility["usb_profiles"], "invalid USB profile")
    preservation = manifest["preservation"]
    firmware.exact_keys(preservation, ("firmware_start", "firmware_end", "state_start", "state_end",
                                        "migration", "retained"))
    firmware.require(all(type(preservation[k]) is int for k in
                         ("firmware_start", "firmware_end", "state_start", "state_end")) and
                     [preservation[k] for k in ("firmware_start", "firmware_end", "state_start", "state_end")] ==
                     [0x10000000, 0x10100000, 0x10100000, 0x10308000] and
                     preservation["migration"] == "none" and type(preservation["retained"]) is list and
                     {"config", "state", "identity", "receipt"} <= set(preservation["retained"]),
                     "invalid preservation policy")
    firmware.require(type(manifest["prerequisites"]) is list and manifest["prerequisites"], "missing prerequisites")
    for prerequisite in manifest["prerequisites"]:
        firmware.exact_keys(prerequisite, ("operation", "tool", "version", "packages", "artifact"))
        firmware.require(all(type(prerequisite[k]) is str and prerequisite[k] for k in
                             ("operation", "tool", "version")) and
                         (prerequisite["artifact"] is None or type(prerequisite["artifact"]) is str) and
                         type(prerequisite["packages"]) is list, "invalid prerequisite")
        for package in prerequisite["packages"]:
            firmware.exact_keys(package, ("id", "version", "names"))
            firmware.require(type(package["id"]) is str and type(package["version"]) is str and
                             type(package["names"]) is list and
                             all(type(name) is str and name for name in package["names"]), "invalid packages")


def validate_runtime_provenance(path, artifacts):
    provenance = json.loads(firmware.bounded_file(path, 1024 * 1024),
                            object_pairs_hook=firmware.unique_object)
    firmware.exact_keys(provenance, ("schema_version", "os", "libraries"))
    firmware.exact_keys(provenance["os"], ("id", "version"))
    firmware.require(type(provenance["schema_version"]) is int and provenance["schema_version"] == 1 and
                     provenance["os"] == {"id": "debian", "version": "12"} and
                     type(provenance["libraries"]) is list and
                     len(provenance["libraries"]) == len(RUNTIME_PACKAGES), "invalid runtime provenance")
    seen = set()
    for library in provenance["libraries"]:
        firmware.exact_keys(library, ("path", "package", "package_version", "sha256"))
        name = library["path"]
        version = library["package_version"]
        firmware.require(type(name) is str and name in RUNTIME_PACKAGES and name not in seen and
                         library["package"] == RUNTIME_PACKAGES[name] and
                         type(version) is str and 0 < len(version) <= 255 and
                         all(32 < ord(c) < 127 for c in version) and
                         type(library["sha256"]) is str and len(library["sha256"]) == 64 and
                         all(c in "0123456789abcdef" for c in library["sha256"]) and
                         name in artifacts and library["sha256"] == artifacts[name]["sha256"],
                         "runtime provenance does not match signed artifact")
        seen.add(name)
    firmware.require(seen == set(RUNTIME_PACKAGES), "incomplete runtime provenance")


def validate_inventory(bundle, manifest, metadata_names, required_names):
    bundle = Path(bundle)
    names = {name for name, _, _ in payload_files(bundle)}
    validate_distribution_manifest(manifest)
    artifacts = manifest["artifacts"]
    firmware.require(type(artifacts) is list and 0 < len(artifacts) <= 256, "invalid artifacts")
    expected = set(metadata_names)
    for entry in artifacts:
        firmware.exact_keys(entry, ("path", "size_bytes", "sha256", "class", "mode"))
        name = entry["path"]
        firmware.require(type(name) is str and name in names and name not in expected, "unexpected artifact")
        expected.add(name)
        path = bundle / name
        firmware.require(type(entry["size_bytes"]) is int and path.stat().st_size == entry["size_bytes"] and
                         type(entry["mode"]) is int and entry["mode"] in (0o644, 0o755) and
                         type(entry["class"]) is str and entry["class"] == artifact_class(name) and
                         type(entry["sha256"]) is str and entry["sha256"] == digest_file(path),
                         "altered artifact")
    firmware.require(names == expected and required_names <= names,
                     "incomplete distribution")
    by_path = {entry["path"]: entry for entry in artifacts}
    validate_runtime_provenance(bundle / "runtime/provenance.json", by_path)
    components = manifest["components"]
    firmware.require(type(components) is list and len(components) == len(COMPONENT_PATHS),
                     "invalid component list")
    tuple_ = {}
    for component in components:
        firmware.exact_keys(component, ("name", "version", "build_id", "artifact", "digest"))
        name = component["name"]
        firmware.require(type(name) is str and name not in tuple_ and name in COMPONENT_PATHS and
                         component["artifact"] == COMPONENT_PATHS[name] and
                         type(component["version"]) is str and component["version"] and
                         type(component["build_id"]) is str and component["build_id"], "invalid component")
        firmware.require(name not in ("manager", "daemon", "cli", "tool") or
                         by_path[component["artifact"]]["mode"] == 0o755, "non-executable component")
        firmware.require(component["digest"] == component_digest(name, artifacts), "component inventory mismatch")
        tuple_[name] = component["digest"]
    firmware.require(tuple_ in manifest["compatibility"]["tuples"], "unauthorized component tuple")
    for prerequisite in manifest["prerequisites"]:
        firmware.require(prerequisite["artifact"] is None or prerequisite["artifact"] in by_path,
                         "undeclared prerequisite artifact")
    firmware.require(by_path["tools/firmware.py"]["sha256"] == by_path["firmware/firmware.py"]["sha256"],
                     "firmware verifier mismatch")
    return by_path


def validate_prepared(bundle, tag, commit, build_id):
    bundle = Path(bundle)
    manifest = json.loads(firmware.bounded_file(bundle / "prepared.json", 1024 * 1024),
                          object_pairs_hook=firmware.unique_object)
    validate_inventory(bundle, manifest, {"prepared.json"}, REQUIRED_ASSETS)
    release = manifest["release"]
    firmware.require(len(manifest["artifacts"]) < 256 and
                     manifest["qualification"] == "candidate" and manifest["promotion"] is None and
                     release["tag"] == tag and release["version"] == tag and
                     release["source_commit"] == commit and release["build_id"] == build_id,
                     "prepared release identity mismatch")
    for component in manifest["components"]:
        firmware.require(component["build_id"] == build_id and
                         component["version"] == ("2.3.1" if component["name"] == "tool" else tag),
                         "prepared component identity mismatch")
    return manifest


def sign_prepared(prepared, output, tag, commit, build_id, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    prepared, output = Path(prepared), Path(output)
    validate_prepared(prepared, tag, commit, build_id)
    firmware.require(not os.path.lexists(output), "signing output already exists")
    shutil.copytree(prepared, output, symlinks=False)
    try:
        manifest = validate_prepared(output, tag, commit, build_id)
        certificate = output / "firmware/release-authority.asc"
        sign_detached(output / "install.sh", certificate, trust=trust)
        signature = output / "install.sh.asc"
        manifest["artifacts"].append({"path": "install.sh.asc", "size_bytes": signature.stat().st_size,
                                      "sha256": digest_file(signature), "class": "bootstrap", "mode": 0o644})
        (output / "prepared.json").unlink()
        metadata = output / "distribution.json"
        data = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode()
        firmware.require(len(data) <= 1024 * 1024, "manifest too large")
        metadata.write_bytes(data)
        sign_detached(metadata, certificate, trust=trust)
        verified = verify_signed_metadata(output, trust=trust)
        firmware.require(verified == manifest, "signed metadata changed")
    except BaseException:
        shutil.rmtree(output)
        raise
    return manifest




def verify_signed_metadata(bundle, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    bundle = Path(bundle)
    certificate = bundle / "firmware/release-authority.asc"
    verify_detached(bundle / "distribution.json", bundle / "distribution.json.asc", certificate, trust=trust)
    manifest = json.loads(firmware.bounded_file(bundle / "distribution.json", 1024 * 1024),
                          object_pairs_hook=firmware.unique_object)
    validate_inventory(bundle, manifest, {"distribution.json", "distribution.json.asc"},
                       REQUIRED_ASSETS | {"install.sh.asc"})
    verify_detached(bundle / "install.sh", bundle / "install.sh.asc", certificate, trust=trust)
    return manifest


def verify_distribution(bundle, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    bundle = Path(bundle)
    manifest = verify_signed_metadata(bundle, trust=trust)
    previous_path = os.environ.get("PATH")
    previous_library_path = os.environ.get("LD_LIBRARY_PATH")
    try:
        os.environ["PATH"] = str((bundle / "tools").resolve()) + ":/usr/bin:/bin"
        os.environ["LD_LIBRARY_PATH"] = str((bundle / "runtime").resolve())
        inner = firmware.verify_bundle(bundle / "firmware", trust=trust)
    finally:
        if previous_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous_path
        if previous_library_path is None:
            os.environ.pop("LD_LIBRARY_PATH", None)
        else:
            os.environ["LD_LIBRARY_PATH"] = previous_library_path
    firmware.require(inner["tag"] == manifest["release"]["tag"] and
                     inner["commit"] == manifest["release"]["source_commit"], "inner identity mismatch")
    return manifest


def read_promotion_approval(approval, certificate, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    approval = Path(approval)
    verify_detached(approval, approval.with_name(approval.name + ".asc"), certificate, trust=trust)
    evidence = json.loads(firmware.bounded_file(approval, 1024 * 1024),
                          object_pairs_hook=firmware.unique_object)
    firmware.exact_keys(evidence, ("schema_version", "candidate_sha256", "source_commit",
                                   "payloads", "evidence", "approved"))
    firmware.require(type(evidence["schema_version"]) is int and evidence["schema_version"] == 1 and evidence["approved"] is True and
                     type(evidence["evidence"]) is dict and set(evidence["evidence"]) == set(GATES),
                     "incomplete promotion approval")
    for name in GATES:
        path = approval.parent / name
        firmware.require(path.is_file() and not path.is_symlink() and
                         0 < path.stat().st_size <= 8 * 1024 * 1024 and
                         digest_file(path) == evidence["evidence"][name], "missing or altered acceptance evidence")
    return evidence


def check_promotion(candidate, approval, commit, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    candidate, approval = Path(candidate), Path(approval)
    manifest = verify_distribution(candidate, trust=trust)
    evidence = read_promotion_approval(approval, candidate / "firmware/release-authority.asc", trust=trust)
    firmware.require(evidence["candidate_sha256"] == digest_file(candidate / "distribution.json"),
                     "candidate metadata mismatch")
    require_promotion_identity(manifest, evidence)
    firmware.require(manifest["release"]["source_commit"] == commit, "promotion source mismatch")
    return manifest


def sign_promotion(candidate, output, approval, commit, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    candidate, output, approval = Path(candidate), Path(output), Path(approval)
    manifest = verify_signed_metadata(candidate, trust=trust)
    evidence = read_promotion_approval(approval, candidate / "firmware/release-authority.asc", trust=trust)
    firmware.require(evidence["candidate_sha256"] == digest_file(candidate / "distribution.json") and
                     manifest["release"]["source_commit"] == commit, "promotion source or candidate mismatch")
    require_promotion_identity(manifest, evidence)
    firmware.require(not os.path.lexists(output), "promotion output already exists")
    shutil.copytree(candidate, output, symlinks=False)
    try:
        (output / "distribution.json.asc").unlink()
        manifest["qualification"] = "qualified"
        manifest["promotion"] = {"candidate_sha256": evidence["candidate_sha256"],
                                 "approval_sha256": digest_file(approval)}
        metadata = output / "distribution.json"
        metadata.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        sign_detached(metadata, output / "firmware/release-authority.asc", trust=trust)
        promoted = verify_signed_metadata(output, trust=trust)
        firmware.require(promoted == manifest, "promotion changed authorized metadata")
    except BaseException:
        shutil.rmtree(output)
        raise
    return manifest




def require_archive_member(member, entries, seen):
    firmware.require(member.isfile() and member.name in entries and member.name not in seen and
                     member.size == entries[member.name]["size_bytes"] and
                     0 <= member.size <= 256 * 1024 * 1024 and
                     member.name and len(member.name.encode()) <= 240 and
                     all(part not in ("", ".", "..") for part in member.name.split("/")) and
                     not member.name.startswith("/") and
                     all(32 <= ord(c) < 127 and c != "\\" for c in member.name),
                     "invalid, duplicate or undeclared archive member")


def unpack_distribution_assets(assets, output, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    assets, output = Path(assets), Path(output)
    metadata = assets / "distribution.json"
    signature = assets / "distribution.json.asc"
    certificate = assets / "release-authority.asc"
    verify_detached(metadata, signature, certificate, trust=trust)
    manifest = json.loads(firmware.bounded_file(metadata, 1024 * 1024),
                          object_pairs_hook=firmware.unique_object)
    validate_distribution_manifest(manifest)
    artifacts = manifest["artifacts"]
    firmware.require(type(artifacts) is list and 0 < len(artifacts) <= 256, "invalid artifact count")
    entries = {}
    for entry in artifacts:
        firmware.exact_keys(entry, ("path", "size_bytes", "sha256", "class", "mode"))
        firmware.require(type(entry["path"]) is str and entry["path"] not in entries and
                         type(entry["size_bytes"]) is int and 0 <= entry["size_bytes"] <= 256 * 1024 * 1024 and
                         type(entry["mode"]) is int and entry["mode"] in (0o644, 0o755), "invalid archive declaration")
        entries[entry["path"]] = entry
    firmware.require(sum(e["size_bytes"] for e in entries.values()) <= 1024 ** 3, "archive expansion too large")
    archive = assets / "distribution.tar"
    firmware.require(archive.is_file() and not archive.is_symlink() and
                     archive.stat().st_size <= 1024 ** 3 + 1024 * 1024, "invalid archive")
    firmware.require(not os.path.lexists(output), "archive output exists")
    output.mkdir(mode=0o700)
    try:
        seen = set()
        with tarfile.open(archive, mode="r:") as tar:
            for member in tar:
                require_archive_member(member, entries, seen)
                seen.add(member.name)
                target = output / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                firmware.require(source is not None, "missing archive member")
                h = hashlib.sha256()
                copied = 0
                with target.open("xb") as destination:
                    while True:
                        chunk = source.read(65536)
                        if not chunk:
                            break
                        copied += len(chunk)
                        firmware.require(copied <= member.size, "archive member overflow")
                        h.update(chunk)
                        destination.write(chunk)
                firmware.require(copied == member.size and h.hexdigest() == entries[member.name]["sha256"],
                                 "archive member hash mismatch")
                target.chmod(entries[member.name]["mode"])
        firmware.require(seen == set(entries), "missing archive member")
        shutil.copyfile(metadata, output / "distribution.json")
        shutil.copyfile(signature, output / "distribution.json.asc")
        firmware.require(digest_file(certificate) == digest_file(output / "firmware/release-authority.asc"),
                         "archive authority mismatch")
        for name in ("install.sh", "install.sh.asc"):
            firmware.require(digest_file(assets / name) == digest_file(output / name),
                             "standalone bootstrap differs from signed bundle")
        verify_distribution(output, trust=trust)
    except BaseException:
        shutil.rmtree(output)
        raise
    return manifest


def pack_distribution_assets(bundle, assets, evidence=None, *, trust=(firmware.PRIMARY, firmware.SIGNER)):
    bundle, assets = Path(bundle), Path(assets)
    manifest = verify_distribution(bundle, trust=trust)
    firmware.require(not os.path.lexists(assets), "asset output exists")
    assets.mkdir(mode=0o700)
    try:
        with tarfile.open(assets / "distribution.tar", mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for entry in sorted(manifest["artifacts"], key=lambda item: item["path"]):
                info = tarfile.TarInfo(entry["path"])
                info.size, info.mode, info.mtime = entry["size_bytes"], entry["mode"], 0
                with (bundle / entry["path"]).open("rb") as source:
                    tar.addfile(info, source)
        for name in ("distribution.json", "distribution.json.asc", "install.sh", "install.sh.asc"):
            shutil.copyfile(bundle / name, assets / name)
        shutil.copyfile(bundle / "firmware/release-authority.asc", assets / "release-authority.asc")
        if manifest["qualification"] == "qualified":
            firmware.require(evidence is not None, "qualified publication requires retained evidence")
            approval = Path(evidence) / "approval.json"
            approved = read_promotion_approval(approval, bundle / "firmware/release-authority.asc", trust=trust)
            link = manifest["promotion"]
            firmware.require(link["approval_sha256"] == digest_file(approval) and
                             link["candidate_sha256"] == approved["candidate_sha256"] and
                             approved["source_commit"] == manifest["release"]["source_commit"] and
                             approved["payloads"] == {a["path"]: a["sha256"] for a in manifest["artifacts"]},
                             "promotion approval does not match qualified metadata")
            for name in ("approval.json", "approval.json.asc", *GATES):
                shutil.copyfile(Path(evidence) / name, assets / name)
        else:
            firmware.require(evidence is None, "candidate publication must not include promotion evidence")
        with tempfile.TemporaryDirectory(prefix="p2kes-roundtrip-") as temporary:
            unpack_distribution_assets(assets, Path(temporary) / "bundle", trust=trust)
    except BaseException:
        shutil.rmtree(assets)
        raise


def publish_distribution(bundle, tag, commit, evidence=None):
    manifest = verify_distribution(bundle)
    firmware.require(manifest["release"]["source_commit"] == commit, "release commit mismatch")
    publication_tag = ("qualified-" if manifest["qualification"] == "qualified" else "") + manifest["release"]["tag"]
    firmware.require(tag == publication_tag,
                     "publication tag must match the signed release, prefixed with qualified- only for promotion")
    prerelease = manifest["qualification"] != "qualified" or manifest["release"]["channel"] != "stable"
    classification = ("--prerelease", "--latest=false") if prerelease else ("--prerelease=false", "--latest=true")
    target = json.loads(gh("api", f"repos/{REPOSITORY}/commits/{quote(tag, safe='')}", "--jq", "{sha: .sha}"))
    firmware.require(target.get("sha") == commit, "publication tag does not identify candidate source")
    with tempfile.TemporaryDirectory(prefix="p2kes-publish-") as temporary:
        assets = Path(temporary) / "assets"
        pack_distribution_assets(bundle, assets, evidence)
        existing = release_state(tag)
        if existing is None:
            gh("release", "create", tag, "--repo", REPOSITORY, "--verify-tag", "--draft",
               *classification, "--title", tag,
               "--notes", "Install: https://github.com/AndrewWestberg/pico2-kes-agent#install-p2kesup\n"
               "Existing installations: p2kesup upgrade\n"
               "Authenticated distribution; qualification is recorded in signed metadata.")
        else:
            firmware.require(existing.get("tag_name") == tag and existing.get("draft") is False and
                             existing.get("prerelease") is prerelease,
                             "existing release state conflicts")
            require_asset_set(existing, assets)
        if existing is None:
            gh("release", "upload", tag, "--repo", REPOSITORY, *sorted(assets.iterdir()))
            uploaded = release_state(tag)
            firmware.require(uploaded is not None and uploaded.get("draft") is True and
                             uploaded.get("prerelease") is prerelease, "draft or classification changed")
            require_asset_set(uploaded, assets)
        downloaded = Path(temporary) / "downloaded"
        downloaded.mkdir()
        gh("release", "download", tag, "--repo", REPOSITORY, "--dir", downloaded)
        firmware.require({p.name for p in downloaded.iterdir()} == {p.name for p in assets.iterdir()},
                         "downloaded asset set differs")
        for path in assets.iterdir():
            firmware.require(digest_file(path) == digest_file(downloaded / path.name),
                             "different historical distribution asset")
        unpack_distribution_assets(downloaded, Path(temporary) / "roundtrip")
        target = json.loads(gh("api", f"repos/{REPOSITORY}/commits/{quote(tag, safe='')}", "--jq", "{sha: .sha}"))
        firmware.require(target.get("sha") == commit, "publication tag changed")
        if existing is None:
            gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false",
               *classification)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("check-promotion", "sign-promotion"):
        command = sys.argv[1]
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--candidate", required=True, type=Path)
        parser.add_argument("--approval", required=True, type=Path)
        parser.add_argument("--commit", required=True)
        if command == "sign-promotion":
            parser.add_argument("--output", required=True, type=Path)
        args = parser.parse_args(sys.argv[2:])
        if command == "check-promotion":
            check_promotion(args.candidate, args.approval, args.commit)
        else:
            sign_promotion(args.candidate, args.output, args.approval, args.commit)
        return
    if len(sys.argv) > 1 and sys.argv[1] in ("prepare", "sign-prepared"):
        command = sys.argv[1]
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--payload" if command == "prepare" else "--prepared", required=True, type=Path)
        parser.add_argument("--output", required=True, type=Path)
        parser.add_argument("--tag", required=True)
        parser.add_argument("--commit", required=True)
        parser.add_argument("--build-id", required=True)
        if command == "prepare":
            parser.add_argument("--compatible-tuples", type=Path)
        args = parser.parse_args(sys.argv[2:])
        if command == "prepare":
            compatible_tuples = None
            if args.compatible_tuples is not None:
                compatible_tuples = json.loads(firmware.bounded_file(args.compatible_tuples, 1024 * 1024),
                                               object_pairs_hook=firmware.unique_object)
            prepare_distribution(args.payload, args.output, args.tag, args.commit, args.build_id,
                                 compatible_tuples=compatible_tuples)
        else:
            sign_prepared(args.prepared, args.output, args.tag, args.commit, args.build_id)
        return
    if len(sys.argv) > 1 and sys.argv[1] == "unpack":
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--assets", required=True, type=Path)
        parser.add_argument("--output", required=True, type=Path)
        args = parser.parse_args(sys.argv[2:])
        unpack_distribution_assets(args.assets, args.output)
        return
    if len(sys.argv) > 1 and sys.argv[1] == "publish-distribution":
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--bundle", required=True, type=Path)
        parser.add_argument("--tag", required=True)
        parser.add_argument("--commit", required=True)
        parser.add_argument("--evidence", type=Path)
        args = parser.parse_args(sys.argv[2:])
        firmware.require(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is unavailable")
        publish_distribution(args.bundle, args.tag, args.commit, args.evidence)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    firmware.require(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is unavailable")
    publish(args.bundle, args.tag, args.commit)


if __name__ == "__main__":
    main()
