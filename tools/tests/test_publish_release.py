import hashlib
import json
import os
import subprocess
from pathlib import Path
import shutil
import sys
import tempfile
import tarfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import publish_release as publisher


def write_host_fixture(root, tag, commit, build_id):
    for name in ("p2kesup", "pico2-kes-agentd", "pico2-kes-agent-cli"):
        path = root / "bin" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        identity = json.dumps({"schema_version": 1, "component": name, "version": tag,
                               "source_commit": commit, "build_id": build_id})
        path.write_text("#!/usr/bin/python3\nimport sys\n"
                        "assert sys.argv[1:] == ['--version', '--json']\n"
                        f"print({identity!r})\n", encoding="utf-8")
        path.chmod(0o755)


class GithubBoundary:
    def __init__(self, bundle, tag, commit, existing=None, fail=None):
        self.bundle, self.tag, self.commit = bundle, tag, commit
        self.existing, self.fail = existing, fail
        self.calls = []
        self.uploaded = False
        self.api_calls = 0
        self.prerelease = False
        self.published = False
        self.latest = False

    def state(self, tag):
        if self.existing is not None:
            return self.existing
        if not self.uploaded:
            return None
        return {
            "tag_name": tag, "draft": not self.published, "prerelease": self.prerelease,
            "assets": [{"name": p.name, "size": p.stat().st_size}
                       for p in self.bundle.iterdir()],
        }

    def gh(self, *args):
        self.calls.append(args)
        if args[0] == "api":
            self.api_calls += 1
            return json.dumps({"sha": "moved" if self.fail == "moved" and self.api_calls == 2 else self.commit})
        operation = args[1]
        if operation == "create" and "--target" in args:
            raise ValueError("fixture target changes workflows; contents-only token cannot target it")
        if operation == self.fail:
            raise ValueError("injected GitHub failure")
        if operation == "create":
            self.prerelease = "--prerelease" in args
        if operation == "edit":
            self.published = "--draft=false" in args
            self.latest = "--latest=true" in args
        if operation == "upload":
            self.uploaded = True
        if operation == "download":
            destination = Path(args[args.index("--dir") + 1])
            for path in self.bundle.iterdir():
                shutil.copyfile(path, destination / path.name)
            if self.fail == "different download":
                (destination / "release.json").write_text("changed")
        return ""


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        for name in (*publisher.firmware.ARTIFACTS, "release.json", "release.json.sig"):
            (self.bundle / name).write_text(name)
        self.commit = "a" * 40

    def invoke(self, tag, existing=None, fail=None):
        boundary = GithubBoundary(self.bundle, tag, self.commit, existing, fail)
        def verify(path):
            if fail == "verify" or (fail == "download verification" and Path(path) != self.bundle):
                raise ValueError("injected verification failure")
            return {"tag": tag, "commit": self.commit}
        with mock.patch.object(publisher.firmware, "verify_bundle", side_effect=verify), \
             mock.patch.object(publisher, "release_state", side_effect=boundary.state), \
             mock.patch.object(publisher, "gh", side_effect=boundary.gh):
            try:
                publisher.publish(self.bundle, tag, self.commit)
            except ValueError:
                if fail is None and existing is None:
                    raise
                return boundary, False
        return boundary, True

    def test_classification_at_create_and_final_publish(self):
        for tag, prerelease in (("v0.1.0-rc.1", True), ("vqualification-example", True),
                                ("v1.2.3", False)):
            with self.subTest(tag=tag):
                boundary, success = self.invoke(tag)
                self.assertTrue(success)
                for operation in ("create", "edit"):
                    call = next(c for c in boundary.calls if c[:2] == ("release", operation))
                    self.assertEqual("--prerelease" in call, prerelease)
                    self.assertEqual("--latest=false" in call, prerelease)

    def test_conflicting_completed_release_is_never_mutated(self):
        for tag, recorded in (("v0.1.0-rc.1", False), ("v1.0.0", True)):
            with self.subTest(tag=tag):
                existing = {"tag_name": tag, "draft": False, "prerelease": recorded}
                boundary, success = self.invoke(tag, existing=existing)
                self.assertFalse(success)
                self.assertFalse(any(c[0] == "release" for c in boundary.calls))

    def test_failures_never_publish(self):
        for failure in ("verify", "upload", "download", "download verification",
                        "different download", "moved"):
            with self.subTest(failure=failure):
                boundary, success = self.invoke("v0.1.0-rc.1", fail=failure)
                self.assertFalse(success)
                self.assertFalse(any(c[:2] == ("release", "edit") for c in boundary.calls))

    def test_identical_existing_release_is_read_only(self):
        tag = "v0.1.0-rc.1"
        existing = {
            "tag_name": tag, "draft": False, "prerelease": True,
            "assets": [{"name": p.name, "size": p.stat().st_size}
                       for p in self.bundle.iterdir()],
        }
        boundary, success = self.invoke(tag, existing=existing)
        self.assertTrue(success)
        self.assertFalse(any(c[:2] in (("release", "create"), ("release", "upload"),
                                      ("release", "edit")) for c in boundary.calls))

    def test_existing_draft_requires_explicit_maintainer_handling(self):
        boundary, success = self.invoke(
            "v0.1.0-rc.2",
            existing={"tag_name": "v0.1.0-rc.2", "draft": True, "prerelease": True})
        self.assertFalse(success)
        self.assertFalse(any(c[0] == "release" for c in boundary.calls))

    def test_incomplete_and_duplicate_assets_are_rejected(self):
        assets = [{"name": p.name, "size": p.stat().st_size}
                  for p in self.bundle.iterdir()]
        altered = [dict(asset) for asset in assets]
        altered[0]["size"] += 1
        for invalid in (assets[:-1], assets + [assets[0]], altered,
                        assets + [{"name": "unexpected", "size": 1}]):
            with self.subTest(assets=invalid):
                with self.assertRaises(ValueError):
                    publisher.require_asset_set({"assets": invalid}, self.bundle)

    def test_runtime_provenance_refuses_duplicate_unknown_and_mismatched_entries(self):
        entries = [{"path": path, "package": package, "package_version": "1.2-3",
                    "sha256": "a" * 64} for path, package in publisher.RUNTIME_PACKAGES.items()]
        artifacts = {entry["path"]: {"sha256": entry["sha256"]} for entry in entries}
        path = self.bundle / "provenance.json"
        def check(libraries):
            path.write_text(json.dumps({"schema_version": 1, "os": {"id": "debian", "version": "12"},
                                        "libraries": libraries}), encoding="utf-8")
            publisher.validate_runtime_provenance(path, artifacts)
        check(entries)
        for bad in (entries + [entries[0]], entries[:-1],
                    [{**entries[0], "unexpected": True}, *entries[1:]],
                    [{**entries[0], "sha256": "b" * 64}, *entries[1:]],
                    [{**entries[0], "path": "../libusb"}, *entries[1:]]):
            with self.subTest(libraries=bad), self.assertRaises(ValueError):
                check(bad)
        path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaises(ValueError):
            publisher.validate_runtime_provenance(path, artifacts)

    def test_host_builds_reject_stale_or_mismatched_identity(self):
        write_host_fixture(self.bundle, "vfixture", self.commit, "f" * 64)
        publisher.require_host_builds(self.bundle, "vfixture", self.commit, "f" * 64)
        for field, value in (("version", "vold"), ("source_commit", "b" * 40),
                             ("build_id", "c" * 64), ("component", "wrong"),
                             ("schema_version", True), ("unexpected", "extra")):
            path = self.bundle / "bin/p2kesup"
            identity = {"schema_version": 1, "component": "p2kesup", "version": "vfixture",
                        "source_commit": self.commit, "build_id": "f" * 64}
            identity[field] = value
            path.write_text("#!/usr/bin/python3\nprint(" + repr(json.dumps(identity)) + ")\n")
            path.chmod(0o755)
            with self.subTest(field=field), self.assertRaises(ValueError):
                publisher.require_host_builds(self.bundle, "vfixture", self.commit, "f" * 64)
            write_host_fixture(self.bundle, "vfixture", self.commit, "f" * 64)

    def test_component_inventory_digest_and_tuple_validation(self):
        entries = [
            {"path": "deploy/z", "size_bytes": 2, "sha256": "b" * 64, "mode": 0o755},
            {"path": "install.sh", "size_bytes": 1, "sha256": "a" * 64, "mode": 0o644},
            {"path": "install.sh.sig", "size_bytes": 3, "sha256": "c" * 64, "mode": 0o644},
        ]
        encoded = ("deploy/z\0" + "2\0" + "b" * 64 + "\0" + "493\n" +
                   "install.sh\0" + "1\0" + "a" * 64 + "\0" + "420\n").encode()
        self.assertEqual(publisher.component_digest("deployment", entries), hashlib.sha256(encoded).hexdigest())
        self.assertEqual(publisher.component_digest("deployment", entries),
                         publisher.component_digest("deployment", list(reversed(entries))))
        changed = [dict(entry) for entry in entries]
        changed[0]["mode"] = 0o644
        self.assertNotEqual(publisher.component_digest("deployment", entries),
                            publisher.component_digest("deployment", changed))
        valid = {name: "a" * 64 for name in publisher.COMPONENT_PATHS}
        publisher.validate_tuples([valid])
        for tuples in ([valid, valid], [{**valid, "tool": "A" * 64}],
                       [{**valid, "extra": "a" * 64}], [{k: v for k, v in valid.items() if k != "cli"}]):
            with self.subTest(tuples=tuples), self.assertRaises(ValueError):
                publisher.validate_tuples(tuples)

    def test_promotion_preserves_source_and_all_payloads(self):
        candidate = {"qualification": "candidate", "release": {"source_commit": "a" * 40},
                     "artifacts": [{"path": "bin/p2kesup", "sha256": "b" * 64}]}
        approved = {"source_commit": "a" * 40, "payloads": {"bin/p2kesup": "b" * 64}}
        publisher.require_promotion_identity(candidate, approved)
        for changed in ({"source_commit": "c" * 40, "payloads": approved["payloads"]},
                        {"source_commit": approved["source_commit"], "payloads": {"bin/p2kesup": "d" * 64}},
                        {"source_commit": approved["source_commit"], "payloads": {}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                publisher.require_promotion_identity(candidate, changed)

    def test_archive_rejects_traversal_links_and_duplicates(self):
        entries = {"firmware/image": {"size_bytes": 1}}
        valid = tarfile.TarInfo("firmware/image")
        valid.size = 1
        publisher.require_archive_member(valid, entries, set())
        for name, kind, seen in (("../image", tarfile.REGTYPE, set()),
                                 ("firmware/image", tarfile.SYMTYPE, set()),
                                 ("firmware/image", tarfile.LNKTYPE, set()),
                                 ("firmware/image", tarfile.REGTYPE, {"firmware/image"})):
            member = tarfile.TarInfo(name)
            member.type, member.size = kind, 1
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                publisher.require_archive_member(member, entries, seen)

    def test_real_disposable_authority_rejects_tamper_and_wrong_pin(self):
        home = self.bundle / "gnupg"
        home.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {"GNUPGHOME": str(home)}):
            def gpg(*args):
                return subprocess.check_output(["gpg", "--batch", *args])
            gpg("--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "Release Test <release-test@example.invalid>", "ed25519", "cert", "0")
            listing = gpg("--with-colons", "--list-keys").decode()
            primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            gpg("--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-add-key", primary, "ed25519", "sign", "0")
            listing = gpg("--with-colons", "--list-keys").decode()
            fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
            certificate = self.bundle / "authority.asc"
            certificate.write_bytes(gpg("--armor", "--export", primary))
            data = self.bundle / "approval.json"
            data.write_bytes(b"authenticated bytes")
            trust = (primary, fingerprints[1])
            publisher.sign_detached(data, certificate, trust=trust)
            publisher.verify_detached(data, self.bundle / "approval.json.asc", certificate, trust=trust)
            with self.assertRaises(ValueError):
                publisher.verify_detached(data, self.bundle / "approval.json.asc", certificate)
            data.write_bytes(b"altered bytes")
            with self.assertRaises(ValueError):
                publisher.verify_detached(data, self.bundle / "approval.json.asc", certificate, trust=trust)
            key_file = self.bundle / "distribution-key.pem"
            subprocess.run(["openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout",
                            "-out", str(key_file)], check=True)
            key_file.chmod(0o600)
            public_key = subprocess.check_output(["openssl", "pkey", "-in", str(key_file), "-pubout"])
            wrong_key = self.bundle / "wrong-key.pem"
            subprocess.run(["openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout",
                            "-out", str(wrong_key)], check=True)
            wrong_key.chmod(0o600)
            authority_dir = self.bundle / "authority"
            authority_dir.mkdir()
            public_path = authority_dir / publisher.firmware.PUBLIC_FILES[0]
            public_path.write_bytes(public_key)
            (authority_dir / "release-authority.asc").write_bytes(certificate.read_bytes())
            firmware_statement = authority_dir / "firmware-key.json"
            firmware_statement.write_text(json.dumps(publisher.firmware.statement(public_path), indent=2) + "\n")
            gpg("--armor", "--detach-sign", "--local-user", fingerprints[1] + "!",
                "--output", str(authority_dir / "firmware-key.json.asc"), str(firmware_statement))
            publisher.authorize_distribution(authority_dir, trust=trust)
            auth_names = ("distribution-authority.json", "distribution-authority.json.asc")
            authorization = [(authority_dir / name).read_bytes() for name in auth_names]
            self.assertEqual(publisher.firmware.verify_distribution_authority(
                authority_dir / auth_names[0], authority_dir / auth_names[1],
                authority_dir / "release-authority.asc", trust=trust), public_key)
            self.assertTrue(all((authority_dir / name).stat().st_mode & 0o777 == 0o644 for name in auth_names))
            with self.assertRaises(ValueError):
                publisher.authorize_distribution(authority_dir, trust=trust)
            self.assertEqual([(authority_dir / name).read_bytes() for name in auth_names], authorization)
            payload = self.bundle / "payload"
            for name in publisher.REQUIRED_ASSETS:
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"same verifier" if name in ("firmware/firmware.py", "tools/firmware.py")
                                 else certificate.read_bytes() if name == "firmware/release-authority.asc"
                                 else public_key if name == "firmware/firmware-signing-public.pem"
                                 else (authority_dir / name).read_bytes() if name in auth_names
                                 else name.encode())
                if name in ("bin/p2kesup", "bin/pico2-kes-agentd", "bin/pico2-kes-agent-cli", "tools/picotool"):
                    path.chmod(0o755)
            (payload / "runtime/provenance.json").write_text(json.dumps({
                "schema_version": 1, "os": {"id": "debian", "version": "12"},
                "libraries": [{"path": path, "package": package, "package_version": "1.2-3",
                               "sha256": publisher.digest_file(payload / path)}
                              for path, package in publisher.RUNTIME_PACKAGES.items()]}), encoding="utf-8")
            write_host_fixture(payload, "vfixture", self.commit, "f" * 64)
            candidate, qualified = self.bundle / "candidate", self.bundle / "qualified"
            inner = {"tag": "vfixture", "commit": self.commit}
            with mock.patch.object(publisher.firmware, "verify_bundle", return_value=inner):
                prepared = self.bundle / "prepared"
                mixed = {name: "current" for name in publisher.COMPONENT_PATHS}
                mixed["daemon"] = "b" * 64
                publisher.prepare_distribution(payload, prepared, "vfixture", self.commit, "f" * 64,
                                               compatible_tuples=[mixed], trust=trust)
                prepared_metadata = prepared / "prepared.json"
                prepared_bytes = prepared_metadata.read_bytes()
                declared = json.loads(prepared_bytes)
                expected_os = {("debian", "12"), ("ubuntu", "24.04"), ("ubuntu", "26.04")}
                self.assertEqual({(item["id"], item["version"]) for item in declared["platform"]["os"]},
                                 expected_os)
                for prerequisite in declared["prerequisites"]:
                    self.assertEqual({(item["id"], item["version"]) for item in prerequisite["packages"]},
                                     expected_os)
                install = [item for item in declared["prerequisites"] if item["operation"] == "install"]
                self.assertIn("sudo", {item["tool"] for item in install})
                for prerequisite in install:
                    for package in prerequisite["packages"]:
                        self.assertIn("sudo", package["names"])
                        self.assertNotIn("pkexec", package["names"])
                        self.assertNotIn("polkit", package["names"])
                publisher.validate_distribution_manifest(declared)
                historical = json.loads(prepared_bytes)
                historical["platform"]["os"] = historical["platform"]["os"][:2]
                publisher.validate_distribution_manifest(historical)
                self.assertNotIn({"id": "ubuntu", "version": "26.04"}, historical["platform"]["os"])
                for invalid in ([*historical["platform"]["os"], historical["platform"]["os"][1]],
                                [*historical["platform"]["os"], {"id": "ubuntu", "version": "25.04"}],
                                [{"id": "ubuntu", "version": "24.04"},
                                 {"id": "ubuntu", "version": "26.04"}]):
                    declared["platform"]["os"] = invalid
                    with self.subTest(os=invalid), self.assertRaises(ValueError):
                        publisher.validate_distribution_manifest(declared)
                altered = json.loads(prepared_bytes)
                altered["components"][0]["digest"] = "0" * 64
                prepared_metadata.write_text(json.dumps(altered), encoding="utf-8")
                with self.assertRaises(ValueError):
                    publisher.sign_prepared(prepared, self.bundle / "bad-inventory", "vfixture",
                                            self.commit, "f" * 64, key_file, trust=trust)
                prepared_metadata.write_bytes(prepared_bytes)
                with mock.patch.object(publisher, "host_version", side_effect=AssertionError("signer ran host binary")), \
                     mock.patch.object(publisher.firmware, "verify_bundle", side_effect=AssertionError("signer ran firmware")):
                    with self.assertRaises(ValueError):
                        publisher.sign_prepared(prepared, self.bundle / "bad-source", "vfixture", "b" * 40, "f" * 64, key_file, trust=trust)
                    artifact = prepared / "bin/p2kesup"
                    original = artifact.read_bytes()
                    artifact.write_bytes(original + b"altered")
                    with self.assertRaises(ValueError):
                        publisher.sign_prepared(prepared, self.bundle / "bad-payload", "vfixture", self.commit, "f" * 64, key_file, trust=trust)
                    artifact.write_bytes(original)
                    with self.assertRaises(ValueError):
                        publisher.sign_prepared(prepared, self.bundle / "bad-key", "vfixture", self.commit, "f" * 64, wrong_key, trust=trust)
                    manifest = publisher.sign_prepared(prepared, candidate, "vfixture", self.commit, "f" * 64, key_file, trust=trust)
                self.assertIn("unlocked", manifest["compatibility"]["security_profiles"])
                tuples = manifest["compatibility"]["tuples"]
                self.assertEqual(len(tuples), 2)
                self.assertEqual(tuples[1]["daemon"], "b" * 64)
                self.assertEqual(tuples[1]["deployment"], tuples[0]["deployment"])
                assets = self.bundle / "assets"
                publisher.pack_distribution_assets(candidate, assets, trust=trust)
                unpacked = self.bundle / "unpacked"
                self.assertEqual(publisher.unpack_distribution_assets(assets, unpacked, trust=trust), manifest)
                for name in ("distribution-authority.json", "distribution-authority.json.asc",
                             "release-authority.asc", "install.sh", "install.sh.sig",
                             "distribution.json", "distribution.json.sig"):
                    path = assets / name
                    original = path.read_bytes()
                    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                    with self.subTest(asset=name), self.assertRaises(ValueError):
                        publisher.unpack_distribution_assets(assets, self.bundle / ("bad-" + name), trust=trust)
                    path.write_bytes(original)
                self.assertEqual({c["name"]: c["digest"] for c in manifest["components"]}, tuples[0])
                evidence_dir = self.bundle / "evidence"
                evidence_dir.mkdir()
                evidence_hashes = {}
                for name in publisher.GATES:
                    path = evidence_dir / name
                    path.write_text("reviewed fixture", encoding="utf-8")
                    evidence_hashes[name] = publisher.digest_file(path)
                approval = evidence_dir / "approval.json"
                approval.write_text(json.dumps({"schema_version": 1, "approved": True,
                    "candidate_sha256": publisher.digest_file(candidate / "distribution.json"),
                    "source_commit": self.commit,
                    "payloads": {a["path"]: a["sha256"] for a in manifest["artifacts"]},
                    "evidence": evidence_hashes}), encoding="utf-8")
                publisher.sign_detached(approval, certificate, trust=trust)
                publisher.check_promotion(candidate, approval, self.commit, trust=trust)
                with mock.patch.object(publisher.firmware, "verify_bundle", side_effect=AssertionError("signer ran firmware")), \
                     mock.patch.object(publisher, "host_version", side_effect=AssertionError("signer ran host binary")):
                    with self.assertRaises(ValueError):
                        publisher.sign_promotion(candidate, self.bundle / "bad-promotion-key", approval, self.commit, wrong_key, trust=trust)
                    publisher.sign_promotion(candidate, qualified, approval, self.commit, key_file, trust=trust)
                promoted = publisher.verify_distribution(qualified, trust=trust)
                self.assertEqual(promoted["qualification"], "qualified")
                self.assertEqual(promoted["artifacts"], manifest["artifacts"])
                self.assertEqual(promoted["release"], manifest["release"])
                self.assertEqual(promoted["components"], manifest["components"])
                self.assertEqual(promoted["compatibility"], manifest["compatibility"])
                artifact = candidate / "bin/p2kesup"
                original = artifact.read_bytes()
                artifact.write_bytes(original + b"altered")
                with self.assertRaises(ValueError):
                    publisher.verify_distribution(candidate, trust=trust)
                artifact.write_bytes(original)
                metadata, signature = candidate / "distribution.json", candidate / "distribution.json.sig"
                original_metadata, original_signature = metadata.read_bytes(), signature.read_bytes()
                signature.unlink()
                publisher.sign_distribution(metadata, key_file, public_key, purpose=publisher.firmware.BOOTSTRAP_PURPOSE)
                with self.assertRaises(ValueError):
                    publisher.verify_distribution(candidate, trust=trust)
                signature.unlink()
                for field, value in (("purpose", "wrong-purpose"), ("qualification", "unknown")):
                    altered = dict(manifest)
                    altered[field] = value
                    metadata.write_text(json.dumps(altered), encoding="utf-8")
                    if signature.exists():
                        signature.unlink()
                    publisher.sign_distribution(metadata, key_file, public_key, purpose=publisher.firmware.DISTRIBUTION_PURPOSE)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        publisher.verify_distribution(candidate, trust=trust)
                metadata.write_bytes(original_metadata)
                signature.write_bytes(original_signature)
                with self.assertRaises(ValueError):
                    publisher.sign_promotion(candidate, qualified, approval, self.commit, key_file, trust=trust)
                (evidence_dir / "Q1.md").write_text("tampered", encoding="utf-8")
                with self.assertRaises(ValueError):
                    publisher.sign_promotion(candidate, self.bundle / "bad", approval, self.commit, key_file, trust=trust)


class DistributionPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / "assets"
        self.bundle.mkdir()
        for name in ("distribution.json", "distribution.json.sig", "distribution.tar",
                     "distribution-authority.json", "distribution-authority.json.asc",
                     "release-authority.asc", "install.sh", "install.sh.sig"):
            (self.bundle / name).write_bytes(name.encode())
        self.commit = "a" * 40

    def publish(self, qualification, channel, tag=None):
        source_tag = "v1.2.3" if channel == "stable" else "v1.2.3-rc.1"
        tag = tag or (("qualified-" if qualification == "qualified" else "") + source_tag)
        manifest = {"qualification": qualification, "release": {
            "tag": source_tag, "channel": channel, "source_commit": self.commit}}
        boundary = GithubBoundary(self.bundle, tag, self.commit)
        with mock.patch.object(publisher, "verify_distribution", return_value=manifest), \
             mock.patch.object(publisher, "pack_distribution_assets",
                               side_effect=lambda bundle, output, evidence: shutil.copytree(bundle, output)), \
             mock.patch.object(publisher, "unpack_distribution_assets", return_value=manifest), \
             mock.patch.object(publisher, "release_state", side_effect=boundary.state), \
             mock.patch.object(publisher, "gh", side_effect=boundary.gh):
            publisher.publish_distribution(self.bundle, tag, self.commit)
        return boundary

    def test_only_qualified_stable_distribution_is_visible_as_latest(self):
        for qualification in ("candidate", "qualified"):
            for channel in ("stable", "prerelease"):
                with self.subTest(qualification=qualification, channel=channel):
                    release = self.publish(qualification, channel)
                    stable = qualification == "qualified" and channel == "stable"
                    self.assertTrue(release.published)
                    self.assertEqual(release.prerelease, not stable)
                    self.assertEqual(release.latest, stable)
                    self.assertFalse(release.state(release.tag)["draft"])

    def test_promotion_cannot_impersonate_another_release_tag(self):
        with self.assertRaisesRegex(ValueError, "publication tag"):
            self.publish("qualified", "stable", tag="qualified-v2.0.0")


class ReleaseInspectionTests(unittest.TestCase):
    def test_duplicate_matching_releases_fail_closed(self):
        release = json.dumps({"tag_name": "v0.1.0-rc.2", "draft": True,
                              "prerelease": True, "assets": []}).encode()
        with mock.patch.object(publisher, "gh", return_value=release + b"\n" + release):
            with self.assertRaises(ValueError):
                publisher.release_state("v0.1.0-rc.2")

    def test_api_failure_is_not_absence(self):
        with mock.patch.object(publisher, "gh", side_effect=ValueError("API unavailable")):
            with self.assertRaises(ValueError):
                publisher.release_state("v0.1.0-rc.2")
