import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import publish_release as publisher


class GithubBoundary:
    def __init__(self, bundle, tag, commit, existing=None, fail=None):
        self.bundle, self.tag, self.commit = bundle, tag, commit
        self.existing, self.fail = existing, fail
        self.calls = []
        self.uploaded = False
        self.api_calls = 0

    def state(self, tag):
        if self.existing is not None:
            return self.existing
        if not self.uploaded:
            return None
        return {
            "tag_name": tag, "draft": True, "prerelease": "-" in tag,
            "assets": [{"name": p.name, "size": p.stat().st_size}
                       for p in self.bundle.iterdir()],
        }

    def gh(self, *args):
        self.calls.append(args)
        if args[0] == "api":
            self.api_calls += 1
            return json.dumps({"sha": "moved" if self.fail == "moved" and self.api_calls == 2 else self.commit})
        operation = args[1]
        if operation == self.fail:
            raise ValueError("injected GitHub failure")
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
