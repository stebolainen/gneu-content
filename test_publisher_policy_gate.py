#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


publisher_gate = load_module("publisher_gate", ROOT / "publisher_gate.py")
publisher_policy_gate = load_module(
    "publisher_policy_gate",
    ROOT / "publisher_policy_gate.py",
)
PolicyGateError = publisher_policy_gate.publisher_gate.GateError
# publisher_policy_gate imports publisher_gate itself, so assertions about
# gate classes must use that same module object, not the one loaded above.
PolicyGate = publisher_policy_gate.publisher_gate


PRIOR_EVENT = {
    "id": "uk-ncsc:CVE-2025-11111",
    "type": "vulnerability",
    "publication_class": "A",
    "occurred_at": "2026-08-17T00:00:00Z",
    "updated_at": "2026-08-17T00:00:00Z",
    "title": "Tidigare publicerat testevent",
    "summary": "Ett tidigare verifierat testevent.",
    "action": "Följ primärkällans åtgärd.",
    "cves": ["CVE-2025-11111"],
    "sources": [
        {
            "id": "uk-ncsc",
            "url": "https://www.ncsc.gov.uk/news/prior-event",
        }
    ],
    "confidence": "verified",
}

NEW_EVENT = {
    "id": "uk-ncsc:CVE-2026-12345",
    "type": "vulnerability",
    "publication_class": "A",
    "occurred_at": "2026-08-29T00:00:00Z",
    "updated_at": "2026-08-29T00:00:00Z",
    "title": "Nytt verifierat testevent",
    "summary": "Ett nytt verifierat testevent.",
    "action": "Följ primärkällans åtgärd.",
    "cves": ["CVE-2026-12345"],
    "sources": [
        {
            "id": "uk-ncsc",
            "url": "https://www.ncsc.gov.uk/news/new-event",
        }
    ],
    "confidence": "verified",
}

EMPTY_AIHOT = {
    "generated": "2026-08-29T00:00:00Z",
    "editions": [],
    "articles": [],
}


class Args:
    pass


class PolicyFixture:
    def __init__(self, root: Path):
        self.root = root
        self.base_sha = "a" * 40
        self.head_sha = "b" * 40
        self.base_events = {
            "schema": "gneu-content-events-v1",
            "generation": 2,
            "events": [deepcopy(PRIOR_EVENT)],
        }
        self.head_events = {
            "schema": "gneu-content-events-v1",
            "generation": 3,
            "events": [deepcopy(PRIOR_EVENT), deepcopy(NEW_EVENT)],
        }
        self.pr = {
            "number": 7,
            "state": "open",
            "draft": False,
            "base": {
                "ref": "published",
                "sha": self.base_sha,
                "repo": {"full_name": "stebolainen/gneu-content"},
            },
            "head": {
                "ref": "adam/gen3-test-event",
                "sha": self.head_sha,
                "repo": {"full_name": "stebolainen/gneu-content"},
            },
        }
        self.files = [
            {"filename": "events.json", "status": "modified"},
            {"filename": "manifest.json", "status": "modified"},
        ]
        self.compare = {"status": "ahead", "behind_by": 0, "ahead_by": 1}
        self.aihot = deepcopy(EMPTY_AIHOT)
        self.write()

    def write_json(self, name: str, value: object) -> None:
        (self.root / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def manifest(self, events_name: str, generation: int, count: int) -> dict:
        raw = (self.root / events_name).read_bytes()
        return {
            "schema": "gneu-content-manifest-v1",
            "generation": generation,
            "generated_at": "2026-08-29T00:00:00Z",
            "events_sha256": hashlib.sha256(raw).hexdigest(),
            "event_count": count,
        }

    def write(self) -> None:
        self.write_json("base-events.json", self.base_events)
        self.write_json("head-events.json", self.head_events)
        self.write_json(
            "base-manifest.json",
            self.manifest("base-events.json", self.base_events["generation"], len(self.base_events["events"])),
        )
        self.write_json(
            "head-manifest.json",
            self.manifest("head-events.json", self.head_events["generation"], len(self.head_events["events"])),
        )
        self.write_json("pr.json", self.pr)
        self.write_json("files.json", self.files)
        self.write_json("compare.json", self.compare)
        self.write_json("aihot.json", self.aihot)
        (self.root / "head-policy-workflow.yml").write_text(
            (ROOT / ".github/workflows/publisher-policy.yml").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )

    def args(self) -> Args:
        args = Args()
        args.repository = "stebolainen/gneu-content"
        args.current_base_sha = self.base_sha
        args.pr = self.root / "pr.json"
        args.files = self.root / "files.json"
        args.compare = self.root / "compare.json"
        args.base_events = self.root / "base-events.json"
        args.base_manifest = self.root / "base-manifest.json"
        args.head_events = self.root / "head-events.json"
        args.head_manifest = self.root / "head-manifest.json"
        args.aihot_coverage = self.root / "aihot.json"
        args.trusted_validator = ROOT / "validate_content.py"
        args.head_policy_workflow = self.root / "head-policy-workflow.yml"
        args.trusted_policy_workflow = (
            ROOT / ".github/workflows/publisher-policy.yml"
        )
        return args


class PublisherPolicyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="publisher-policy-test-")
        self.fixture = PolicyFixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def validate(self) -> dict:
        self.fixture.write()
        return publisher_policy_gate.validate(self.fixture.args())

    def assert_blocked(self, reason: str) -> None:
        with self.assertRaises(PolicyGateError) as caught:
            self.validate()
        self.assertIn(reason, str(caught.exception))

    def test_legitimate_adam_class_a_passes(self) -> None:
        self.assertEqual(self.validate()["decision"], "PASS_AUTOPUBLISH")

    def test_native_sources_block(self) -> None:
        cases = [
            (
                "msrc",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
                "msrc",
            ),
            ("cert-se", "https://www.cert.se/2026/08/test.html", "cert-se"),
            (
                "cisa-kev",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "cisa-kev",
            ),
        ]
        for source_id, source_url, expected in cases:
            with self.subTest(source=source_id):
                self.fixture.head_events["events"][-1]["sources"] = [
                    {"id": source_id, "url": source_url}
                ]
                self.assert_blocked(
                    f"native source already covered by gneu.se: {expected}"
                )
                self.fixture.head_events["events"][-1] = deepcopy(NEW_EVENT)

    def test_published_cve_duplicate_blocks(self) -> None:
        self.fixture.head_events["events"][-1]["cves"] = ["CVE-2025-11111"]
        self.assert_blocked("CVE already covered by published content: CVE-2025-11111")

    def test_published_normalized_url_duplicate_blocks(self) -> None:
        self.fixture.head_events["events"][-1]["sources"][0]["url"] = (
            "https://www.ncsc.gov.uk/news/prior-event/"
        )
        self.assert_blocked("primary source URL already covered by published content")

    def test_aihot_url_cve_and_advisory_duplicates_block(self) -> None:
        cases = [
            (
                {
                    "id": "aihot-url",
                    "title": "Existing article",
                    "sources": [
                        {
                            "url": "https://www.ncsc.gov.uk/news/new-event/",
                        }
                    ],
                },
                "primary source URL already covered by AI-hot",
            ),
            (
                {
                    "id": "aihot-cve",
                    "title": "Existing CVE-2026-12345 article",
                    "sources": [],
                },
                "CVE already covered by AI-hot: CVE-2026-12345",
            ),
            (
                {
                    "id": "aihot-advisory",
                    "title": "Existing AA26-999A article",
                    "sources": [],
                },
                "advisory already covered by AI-hot: AA26-999A",
            ),
        ]
        for article, reason in cases:
            with self.subTest(reason=reason):
                self.fixture.aihot["articles"] = [article]
                if "advisory" in reason:
                    self.fixture.head_events["events"][-1]["id"] = "cisa:AA26-999A"
                self.assert_blocked(reason)
                self.fixture.aihot = deepcopy(EMPTY_AIHOT)
                self.fixture.head_events["events"][-1] = deepcopy(NEW_EVENT)

    def test_stale_base_needs_a_human_and_still_blocks(self) -> None:
        self.fixture.pr["base"]["sha"] = "c" * 40
        with self.assertRaises(PolicyGateError) as caught:
            self.validate()
        self.assertIsInstance(caught.exception, PolicyGate.GateOutcome)
        self.assertEqual(
            caught.exception.outcome, PolicyGate.OUTCOME_NEEDS_HUMAN
        )
        self.assertEqual(caught.exception.reason_code, "STALE_BASE")
        self.assertIn("needs a rebase", str(caught.exception))

    def test_altered_existing_event_blocks(self) -> None:
        self.fixture.head_events["events"][0]["title"] = "Ändrad titel"
        self.assert_blocked("existing published events are immutable in autopublish")

    def test_more_than_one_appended_event_needs_a_human(self) -> None:
        extra = deepcopy(NEW_EVENT)
        extra["id"] = "uk-ncsc:CVE-2026-12346"
        extra["cves"] = ["CVE-2026-12346"]
        extra["sources"][0]["url"] = "https://www.ncsc.gov.uk/news/another-event"
        self.fixture.head_events["events"].append(extra)
        with self.assertRaises(PolicyGateError) as caught:
            self.validate()
        self.assertIsInstance(caught.exception, PolicyGate.GateOutcome)
        self.assertEqual(
            caught.exception.outcome, PolicyGate.OUTCOME_NEEDS_HUMAN
        )
        self.assertEqual(caught.exception.reason_code, "MULTIPLE_EVENTS")

    def test_invalid_and_unrecognized_branches_block(self) -> None:
        for branch in ("adam/not-a-generation", "feature/human-change"):
            with self.subTest(branch=branch):
                self.fixture.pr["head"]["ref"] = branch
                self.assert_blocked("head branch is not an allowed publication path")

    def test_forvaltare_content_maintenance_passes_explicitly(self) -> None:
        self.fixture.pr["head"]["ref"] = "forvaltare/remove-event"
        self.fixture.head_events["events"] = []
        result = self.validate()
        self.assertEqual(result["decision"], "PASS_EDITORIAL_MAINTENANCE")
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["event_count"], 0)

    def test_pr_code_or_workflow_changes_block(self) -> None:
        for branch in ("adam/gen3-test-event", "forvaltare/editorial-change"):
            with self.subTest(branch=branch):
                self.fixture.pr["head"]["ref"] = branch
                self.fixture.files.append(
                    {
                        "filename": ".github/workflows/publisher-policy.yml",
                        "status": "modified",
                    }
                )
                self.assert_blocked(
                    "changed files must be exactly events.json and manifest.json"
                )
                self.fixture.files.pop()

    def test_exact_trusted_workflow_install_has_narrow_explicit_pass(self) -> None:
        self.fixture.pr["head"]["ref"] = (
            "forvaltare/install-publisher-policy-check"
        )
        self.fixture.files = [
            {
                "filename": ".github/workflows/publisher-policy.yml",
                "status": "added",
            }
        ]
        result = self.validate()
        self.assertEqual(result["decision"], "PASS_TRUSTED_WORKFLOW_INSTALL")

        self.fixture.write()
        (self.fixture.root / "head-policy-workflow.yml").write_text(
            "name: untrusted-replacement\n",
            encoding="utf-8",
        )
        with self.assertRaises(PolicyGateError) as mismatch:
            publisher_policy_gate.validate(self.fixture.args())
        self.assertIn("workflow does not match trusted main", str(mismatch.exception))

    def test_aihot_failure_modes_block_adam(self) -> None:
        self.fixture.write()
        (self.fixture.root / "aihot.json").unlink()
        with self.assertRaises(PolicyGateError) as missing:
            publisher_policy_gate.validate(self.fixture.args())
        self.assertIn("AI-hot coverage missing", str(missing.exception))

        self.fixture.write()
        (self.fixture.root / "aihot.json").write_text("{broken", encoding="utf-8")
        with self.assertRaises(PolicyGateError) as malformed:
            publisher_policy_gate.validate(self.fixture.args())
        self.assertIn("invalid JSON", str(malformed.exception))

        self.fixture.write()
        (self.fixture.root / "aihot.json").write_bytes(
            b" " * (publisher_gate.MAX_AIHOT_BYTES + 1)
        )
        with self.assertRaises(PolicyGateError) as oversized:
            publisher_policy_gate.validate(self.fixture.args())
        self.assertIn("AI-hot coverage too large", str(oversized.exception))

    def test_published_workflow_never_executes_pr_head(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher-policy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request_target:", workflow)
        self.assertIn("ref: main", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("\n  pull_request:\n", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("checks: write", workflow)
        self.assertNotIn("github.event.pull_request.head.sha }}", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
