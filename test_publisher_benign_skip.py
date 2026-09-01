#!/usr/bin/env python3
"""Regression tests for the deterministic publisher outcome contract.

Every fixture is offline and self-contained. PR #43, #44 and #45 are used only
as a shape model; nothing here depends on those PRs still existing.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
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


gate = load_module("publisher_gate", ROOT / "publisher_gate.py")

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40

# Shape model for PR #43/#44: a CISA KEV proposal that gneu.se already covers
# natively through its own KEV ingestion.
KEV_EVENT = {
    "id": "cisa-kev:CVE-2026-11111",
    "type": "vulnerability",
    "publication_class": "A",
    "occurred_at": "2026-08-29T00:00:00Z",
    "updated_at": "2026-08-29T00:00:00Z",
    "title": "Två PaperCut-sårbarheter tillagda i CISA KEV",
    "summary": "CISA har lagt till två PaperCut-sårbarheter i KEV.",
    "action": "Tillämpa leverantörens åtgärder.",
    "cves": ["CVE-2026-11111"],
    "sources": [{
        "id": "cisa-kev",
        "url": (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
    }],
    "confidence": "verified",
}

PRIOR_EVENT = {
    "id": "uk-ncsc:CVE-2025-90001",
    "type": "vulnerability",
    "publication_class": "A",
    "occurred_at": "2026-08-01T00:00:00Z",
    "updated_at": "2026-08-01T00:00:00Z",
    "title": "Tidigare publicerat testevent",
    "summary": "Ett tidigare verifierat testevent.",
    "action": "Följ primärkällans åtgärd.",
    "cves": ["CVE-2025-90001"],
    "sources": [{
        "id": "uk-ncsc",
        "url": "https://www.ncsc.gov.uk/news/prior-event",
    }],
    "confidence": "verified",
}

CLEAN_EVENT = {
    "id": "uk-ncsc:CVE-2026-22222",
    "type": "vulnerability",
    "publication_class": "A",
    "occurred_at": "2026-08-30T00:00:00Z",
    "updated_at": "2026-08-30T00:00:00Z",
    "title": "Nytt verifierat testevent",
    "summary": "Ett nytt verifierat testevent.",
    "action": "Följ primärkällans åtgärd.",
    "cves": ["CVE-2026-22222"],
    "sources": [{
        "id": "uk-ncsc",
        "url": "https://www.ncsc.gov.uk/news/new-advisory",
    }],
    "confidence": "verified",
}

EMPTY_AIHOT = {
    "generated": "2026-08-30T00:00:00+00:00",
    "editions": [],
    "articles": [],
}


class Args:
    pass


class Candidate:
    """One offline PR candidate rooted in its own directory."""

    def __init__(self, root: Path, *, head_ref: str, number: int, head_sha: str):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.number = number
        self.head_sha = head_sha
        self.base_events = {
            "schema": "gneu-content-events-v1",
            "generation": 2,
            "events": [deepcopy(PRIOR_EVENT)],
        }
        self.head_events = {
            "schema": "gneu-content-events-v1",
            "generation": 3,
            "events": [deepcopy(PRIOR_EVENT), deepcopy(CLEAN_EVENT)],
        }
        self.pr = {
            "number": number,
            "state": "open",
            "draft": False,
            "base": {
                "ref": "published",
                "sha": BASE_SHA,
                "repo": {"full_name": "stebolainen/gneu-content"},
            },
            "head": {
                "ref": head_ref,
                "sha": head_sha,
                "repo": {"full_name": "stebolainen/gneu-content"},
            },
        }
        self.files = [
            {"filename": "events.json", "status": "modified"},
            {"filename": "manifest.json", "status": "modified"},
        ]
        self.compare = {"status": "ahead", "behind_by": 0, "ahead_by": 1}
        self.checks = {"check_runs": [{
            "name": "validate",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "github-actions"},
        }]}
        self.aihot = deepcopy(EMPTY_AIHOT)

    def append_event(self, event: dict) -> None:
        self.head_events["events"] = [
            deepcopy(PRIOR_EVENT),
            deepcopy(event),
        ]

    def make_noop(self) -> None:
        """Model PR #45: commit plus revert, so the net diff is empty."""
        self.head_events = deepcopy(self.base_events)
        self.files = []
        self.compare = {
            "status": "ahead",
            "behind_by": 0,
            "ahead_by": 2,
            "files": [],
        }

    def _write_json(self, name: str, value: object) -> None:
        (self.root / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _manifest(self, events_name: str, events: dict) -> dict:
        raw = (self.root / events_name).read_bytes()
        return {
            "schema": "gneu-content-manifest-v1",
            "generation": events["generation"],
            "generated_at": "2026-08-30T00:00:00Z",
            "events_sha256": hashlib.sha256(raw).hexdigest(),
            "event_count": len(events["events"]),
        }

    def write(self) -> "Candidate":
        self._write_json("base-events.json", self.base_events)
        self._write_json("head-events.json", self.head_events)
        self._write_json(
            "base-manifest.json",
            self._manifest("base-events.json", self.base_events),
        )
        self._write_json(
            "head-manifest.json",
            self._manifest("head-events.json", self.head_events),
        )
        self._write_json("pr.json", self.pr)
        self._write_json("files.json", self.files)
        self._write_json("compare.json", self.compare)
        self._write_json("checks.json", self.checks)
        self._write_json("aihot.json", self.aihot)
        return self

    def args(self) -> Args:
        args = Args()
        args.repository = "stebolainen/gneu-content"
        args.current_base_sha = BASE_SHA
        args.pr = self.root / "pr.json"
        args.files = self.root / "files.json"
        args.checks = self.root / "checks.json"
        args.compare = self.root / "compare.json"
        args.base_events = self.root / "base-events.json"
        args.base_manifest = self.root / "base-manifest.json"
        args.head_events = self.root / "head-events.json"
        args.head_manifest = self.root / "head-manifest.json"
        args.aihot_coverage = self.root / "aihot.json"
        args.trusted_validator = ROOT / "validate_content.py"
        args.json_out = self.root / "decision.json"
        return args

    def run_cli(self) -> tuple[int, dict]:
        """Run the real gate entry point and return (exit code, decision)."""
        args = self.args()
        proc = subprocess.run(
            [
                sys.executable, str(ROOT / "publisher_gate.py"),
                "--repository", args.repository,
                "--current-base-sha", args.current_base_sha,
                "--pr", str(args.pr),
                "--files", str(args.files),
                "--checks", str(args.checks),
                "--compare", str(args.compare),
                "--base-events", str(args.base_events),
                "--base-manifest", str(args.base_manifest),
                "--head-events", str(args.head_events),
                "--head-manifest", str(args.head_manifest),
                "--aihot-coverage", str(args.aihot_coverage),
                "--trusted-validator", str(args.trusted_validator),
                "--json-out", str(args.json_out),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        decision = {}
        if proc.stdout.strip():
            decision = json.loads(proc.stdout.strip().splitlines()[-1])
        return proc.returncode, decision


def run_publisher_queue(candidates: list[Candidate]) -> dict:
    """Model the workflow queue exactly as publisher.yml wires exit codes.

    ACTIONABLE stops the queue, NOOP_STALE and POLICY_SKIP advance to the next
    candidate, and anything else fails closed without evaluating the rest.
    """
    skipped: list[int] = []
    for candidate in candidates:
        code, decision = candidate.run_cli()
        if code == gate.EXIT_ACTIONABLE:
            return {
                "result": "published",
                "pr_number": decision["pr_number"],
                "head_sha": decision["head_sha"],
                "skipped": skipped,
            }
        if code in (gate.EXIT_NOOP_STALE, gate.EXIT_POLICY_SKIP):
            skipped.append(candidate.number)
            continue
        return {
            "result": "failed",
            "pr_number": candidate.number,
            "exit_code": code,
            "skipped": skipped,
        }
    return {"result": "no_actionable_candidate", "skipped": skipped}


class OutcomeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="benign-skip-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self, name: str, *, number: int, head_sha: str = HEAD_SHA) -> Candidate:
        return Candidate(
            self.root / name,
            head_ref=f"adam/gen3-{name}",
            number=number,
            head_sha=head_sha,
        )

    # 1. A real allowed append-only content diff.
    def test_append_only_content_diff_is_actionable(self) -> None:
        candidate = self.candidate("clean", number=50).write()
        result = gate.validate(candidate.args())
        self.assertEqual(result["decision"], "PASS_AUTOPUBLISH")
        self.assertEqual(result["outcome"], gate.OUTCOME_ACTIONABLE)

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_ACTIONABLE)
        self.assertEqual(decision["head_sha"], HEAD_SHA)
        self.assertEqual(decision["pr_number"], 50)

    # 2. Commits that cancel out, so the net diff against published is empty.
    def test_empty_net_diff_is_noop_stale(self) -> None:
        candidate = self.candidate("noop", number=45)
        candidate.make_noop()
        candidate.write()

        with self.assertRaises(gate.GateSkip) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_NOOP_STALE)

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_NOOP_STALE)
        self.assertEqual(decision["outcome"], gate.OUTCOME_NOOP_STALE)
        self.assertEqual(decision["pr_number"], 45)

    def test_noop_stale_is_a_gate_error_subclass(self) -> None:
        # Any consumer that does not know the outcome contract must still
        # fail closed rather than treat a skip as permission to publish.
        self.assertTrue(issubclass(gate.GateSkip, gate.GateError))

    # 3. A CISA KEV proposal already covered natively by gneu.se.
    def test_native_kev_coverage_is_policy_skip(self) -> None:
        candidate = self.candidate("kev", number=43)
        candidate.append_event(KEV_EVENT)
        candidate.write()

        with self.assertRaises(gate.GateSkip) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_POLICY_SKIP)
        self.assertIn(
            "native source already covered by gneu.se: cisa-kev",
            str(caught.exception),
        )

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_POLICY_SKIP)
        self.assertEqual(decision["outcome"], gate.OUTCOME_POLICY_SKIP)

    def test_all_coverage_decisions_are_policy_skip(self) -> None:
        cases = {
            "published CVE": (
                lambda c: c.append_event({
                    **deepcopy(CLEAN_EVENT),
                    "id": "uk-ncsc:other-id",
                    "cves": ["CVE-2025-90001"],
                }),
                "CVE already covered by published content",
            ),
            "published source URL": (
                lambda c: c.append_event({
                    **deepcopy(CLEAN_EVENT),
                    "id": "uk-ncsc:other-id",
                    "cves": [],
                    "sources": [{
                        "id": "uk-ncsc",
                        "url": "https://www.ncsc.gov.uk/news/prior-event/",
                    }],
                }),
                "primary source URL already covered by published content",
            ),
        }
        for label, (mutate, reason) in cases.items():
            with self.subTest(label):
                candidate = self.candidate(f"cov-{len(label)}", number=60)
                mutate(candidate)
                candidate.write()
                with self.assertRaises(gate.GateSkip) as caught:
                    gate.validate(candidate.args())
                self.assertEqual(
                    caught.exception.outcome, gate.OUTCOME_POLICY_SKIP
                )
                self.assertIn(reason, str(caught.exception))

    def test_aihot_cross_surface_overlap_is_policy_skip(self) -> None:
        candidate = self.candidate("aihot", number=61)
        candidate.aihot = deepcopy(EMPTY_AIHOT)
        candidate.aihot["articles"] = [{
            "id": "2026-w99-covered",
            "title": "Redan täckt: CVE-2026-22222",
            "sources": [],
        }]
        candidate.write()

        with self.assertRaises(gate.GateSkip) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_POLICY_SKIP)
        self.assertIn("CVE already covered by AI-hot", str(caught.exception))


class QueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="benign-queue-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self, name: str, *, number: int, head_sha: str) -> Candidate:
        return Candidate(
            self.root / name,
            head_ref=f"adam/gen3-{name}",
            number=number,
            head_sha=head_sha,
        )

    # 4. First candidate POLICY_SKIP, second ACTIONABLE.
    def test_policy_skip_does_not_block_next_candidate(self) -> None:
        first = self.candidate("kev", number=43, head_sha="c" * 40)
        first.append_event(KEV_EVENT)
        first.write()
        second = self.candidate("clean", number=44, head_sha="d" * 40).write()

        result = run_publisher_queue([first, second])
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 44)
        self.assertEqual(result["head_sha"], "d" * 40)
        self.assertEqual(result["skipped"], [43])

    # 5. First candidate NOOP_STALE, second ACTIONABLE.
    def test_noop_stale_does_not_block_next_candidate(self) -> None:
        first = self.candidate("noop", number=45, head_sha="c" * 40)
        first.make_noop()
        first.write()
        second = self.candidate("clean", number=46, head_sha="d" * 40).write()

        result = run_publisher_queue([first, second])
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 46)
        self.assertEqual(result["skipped"], [45])

    # 6. A real validator/security failure must stop the queue, fail closed.
    def test_real_failures_stop_the_queue(self) -> None:
        later = self.candidate("clean", number=99, head_sha="d" * 40).write()

        cases = {
            "mutated published event": lambda c: c.head_events["events"][0].update(
                {"title": "MUTATED"}
            ),
            "manifest hash mismatch": lambda c: None,
            "fork head repository": lambda c: c.pr["head"]["repo"].update(
                {"full_name": "attacker/fork"}
            ),
            "failed validate check": lambda c: c.checks["check_runs"][0].update(
                {"conclusion": "failure"}
            ),
            "disallowed changed file": lambda c: c.files.append(
                {"filename": "AGENTS.md", "status": "modified"}
            ),
            "unknown branch namespace": lambda c: c.pr["head"].update(
                {"ref": "attacker/gen3-evil"}
            ),
            "validator rejects head": lambda c: c.head_events["events"][-1].update(
                {"type": "not-a-valid-type"}
            ),
        }

        for label, mutate in cases.items():
            with self.subTest(label):
                broken = self.candidate(
                    f"broken-{len(label)}", number=98, head_sha="c" * 40
                )
                mutate(broken)
                broken.write()
                if label == "manifest hash mismatch":
                    manifest = json.loads(
                        (broken.root / "head-manifest.json").read_text()
                    )
                    manifest["events_sha256"] = "0" * 64
                    (broken.root / "head-manifest.json").write_text(
                        json.dumps(manifest) + "\n", encoding="utf-8"
                    )

                result = run_publisher_queue([broken, later])
                self.assertEqual(result["result"], "failed", label)
                self.assertEqual(result["exit_code"], gate.EXIT_BLOCKED)
                self.assertEqual(result["pr_number"], 98)
                # The queue must not walk past an unresolved failure.
                self.assertEqual(result["skipped"], [])

    def test_aihot_unavailable_is_a_hard_failure_not_a_skip(self) -> None:
        # We cannot safely decide whether the candidate is legitimate, so this
        # must stay fail-closed rather than become a benign skip.
        candidate = self.candidate("aihot-gone", number=97, head_sha="c" * 40).write()
        (candidate.root / "aihot.json").unlink()

        code, _ = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_BLOCKED)

    def test_empty_files_payload_with_changed_content_is_a_hard_failure(self) -> None:
        # Contradictory untrusted API data is never a benign no-op.
        candidate = self.candidate("liar", number=96, head_sha="c" * 40)
        candidate.files = []
        candidate.compare = {
            "status": "ahead", "behind_by": 0, "ahead_by": 1, "files": [],
        }
        candidate.write()

        code, _ = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_BLOCKED)


class NotifierContractTests(unittest.TestCase):
    """7. The notifier contract carried in the machine-readable decision."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="benign-notify-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self, name: str, number: int) -> Candidate:
        return Candidate(
            self.root / name,
            head_ref=f"adam/gen3-{name}",
            number=number,
            head_sha=HEAD_SHA,
        )

    def test_noop_stale_must_not_notify(self) -> None:
        candidate = self.candidate("noop", 45)
        candidate.make_noop()
        candidate.write()
        _, decision = candidate.run_cli()
        self.assertIs(decision["notify_human"], False)
        self.assertEqual(decision["outcome"], gate.OUTCOME_NOOP_STALE)

    def test_policy_skip_must_not_notify(self) -> None:
        candidate = self.candidate("kev", 43)
        candidate.append_event(KEV_EVENT)
        candidate.write()
        _, decision = candidate.run_cli()
        self.assertIs(decision["notify_human"], False)
        self.assertEqual(decision["outcome"], gate.OUTCOME_POLICY_SKIP)

    def test_actionable_decision_carries_the_contract(self) -> None:
        candidate = self.candidate("clean", 50).write()
        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_ACTIONABLE)
        self.assertEqual(decision["outcome"], gate.OUTCOME_ACTIONABLE)
        self.assertIn("notify_human", decision)

    def test_blocked_decision_writes_no_benign_payload(self) -> None:
        # A real failure must never leave a decision file a notifier or a
        # merge step could mistake for a passing result.
        candidate = self.candidate("broken", 98)
        candidate.pr["head"]["repo"]["full_name"] = "attacker/fork"
        candidate.write()
        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_BLOCKED)
        self.assertEqual(decision, {})
        self.assertFalse((candidate.root / "decision.json").exists())


class WorkflowWiringTests(unittest.TestCase):
    """The queue and skip semantics must actually be wired in the workflows."""

    def test_publisher_workflow_walks_the_candidate_queue(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("candidates=${candidates[*]}", workflow)
        self.assertIn("for pr in $CANDIDATES; do", workflow)
        self.assertIn("NOOP_STALE: PR #$pr has no net diff", workflow)
        self.assertIn("POLICY_SKIP: PR #$pr declined by content policy", workflow)
        self.assertIn("Publisher gate failed for PR #$pr (exit $rc)", workflow)
        self.assertIn("Gate decision does not match evaluated candidate", workflow)

    def test_publisher_workflow_preserves_the_trust_boundary(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )
        # Trusted control plane only; PR head is never checked out.
        self.assertIn("ref: main", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("github.event.pull_request.head.sha", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)

        # The Publisher App token is minted only after an ACTIONABLE decision,
        # and the merge is locked to the exact SHA the gate validated.
        mint = workflow.index("Mint short-lived publisher token")
        merge = workflow.index("Merge exact validated head")
        queue = workflow.index("Evaluate candidate queue")
        self.assertLess(queue, mint)
        self.assertLess(mint, merge)
        self.assertIn(
            "steps.queue.outputs.actionable == 'true' &&", workflow[mint:merge]
        )
        self.assertIn(
            "HEAD_SHA: ${{ steps.queue.outputs.head_sha }}", workflow[merge:]
        )
        self.assertIn('--match-head-commit "$HEAD_SHA"', workflow[merge:])

    def test_policy_workflow_passes_only_noop_stale(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher-policy.yml").read_text(
            encoding="utf-8"
        )
        # Exit 3 (NOOP_STALE) is green; everything else, POLICY_SKIP included,
        # keeps the required check red so the PR cannot be merged manually.
        self.assertIn("NOOP_STALE: no net diff against current published", workflow)
        self.assertIn("publisher-policy blocked this PR (exit $rc)", workflow)

        case_block = workflow[workflow.index('case "$rc" in'):]
        arms = re.findall(r"^\s{12}(\S+)\)$", case_block, re.M)
        self.assertEqual(arms, ["0", "3", "*"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
