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

    def make_stale_base(self) -> None:
        """Valid metadata, but the candidate sits on an older published base."""
        self.pr["base"]["sha"] = "e" * 40
        self.compare = {"status": "diverged", "behind_by": 3, "ahead_by": 1}

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

    ACTIONABLE stops the queue; NOOP_STALE, POLICY_SKIP and NEEDS_HUMAN all
    advance to the next candidate; anything else fails closed without
    evaluating the rest.
    """
    skipped: list[int] = []
    notified: list[int] = []
    evaluated: list[int] = []
    for candidate in candidates:
        evaluated.append(candidate.number)
        code, decision = candidate.run_cli()
        if code == gate.EXIT_ACTIONABLE:
            if decision.get("outcome") != gate.OUTCOME_ACTIONABLE:
                return {
                    "result": "failed",
                    "pr_number": candidate.number,
                    "exit_code": code,
                    "skipped": skipped,
                    "notified": notified,
                    "evaluated": evaluated,
                }
            return {
                "result": "published",
                "pr_number": decision["pr_number"],
                "head_sha": decision["head_sha"],
                "skipped": skipped,
                "notified": notified,
                "evaluated": evaluated,
            }
        if code in (
            gate.EXIT_NOOP_STALE,
            gate.EXIT_POLICY_SKIP,
            gate.EXIT_NEEDS_HUMAN,
        ):
            skipped.append(candidate.number)
            if decision.get("notify_human"):
                notified.append(candidate.number)
            continue
        return {
            "result": "failed",
            "pr_number": candidate.number,
            "exit_code": code,
            "skipped": skipped,
            "notified": notified,
            "evaluated": evaluated,
        }
    return {
        "result": "no_actionable_candidate",
        "skipped": skipped,
        "notified": notified,
        "evaluated": evaluated,
    }


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

        with self.assertRaises(gate.GateOutcome) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_NOOP_STALE)

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_NOOP_STALE)
        self.assertEqual(decision["outcome"], gate.OUTCOME_NOOP_STALE)
        self.assertEqual(decision["pr_number"], 45)

    def test_noop_stale_is_a_gate_error_subclass(self) -> None:
        # Any consumer that does not know the outcome contract must still
        # fail closed rather than treat a skip as permission to publish.
        self.assertTrue(issubclass(gate.GateOutcome, gate.GateError))

    # 3. A CISA KEV proposal already covered natively by gneu.se.
    def test_native_kev_coverage_is_policy_skip(self) -> None:
        candidate = self.candidate("kev", number=43)
        candidate.append_event(KEV_EVENT)
        candidate.write()

        with self.assertRaises(gate.GateOutcome) as caught:
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
                with self.assertRaises(gate.GateOutcome) as caught:
                    gate.validate(candidate.args())
                self.assertEqual(
                    caught.exception.outcome, gate.OUTCOME_POLICY_SKIP
                )
                self.assertIn(reason, str(caught.exception))

    def test_draft_pr_is_a_silent_policy_skip(self) -> None:
        # A draft is the author saying "not ready for review yet". It must not
        # publish, must not fail the workflow and must not notify anyone.
        candidate = self.candidate("draft", number=62)
        candidate.pr["draft"] = True
        candidate.write()

        with self.assertRaises(gate.GateOutcome) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_POLICY_SKIP)
        self.assertEqual(caught.exception.reason_code, "DRAFT_PR")

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_POLICY_SKIP)
        self.assertIs(decision["notify_human"], False)
        self.assertIs(decision["technical_error"], False)

    def test_draft_pr_does_not_block_next_candidate(self) -> None:
        first = self.candidate("draft-first", number=63)
        first.pr["draft"] = True
        first.write()
        second = self.candidate("clean-after-draft", number=64)
        second.head_sha = "d" * 40
        second.pr["head"]["sha"] = second.head_sha
        second.checks["check_runs"][0]["head_sha"] = second.head_sha
        second.write()

        result = run_publisher_queue([first, second])
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 64)
        self.assertEqual(result["notified"], [])

    def test_malformed_draft_flag_is_blocked(self) -> None:
        candidate = self.candidate("draft-bad", number=65)
        candidate.pr["draft"] = "yes"
        candidate.write()
        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_BLOCKED)
        self.assertIs(decision["technical_error"], True)

    def test_aihot_cross_surface_overlap_is_policy_skip(self) -> None:
        candidate = self.candidate("aihot", number=61)
        candidate.aihot = deepcopy(EMPTY_AIHOT)
        candidate.aihot["articles"] = [{
            "id": "2026-w99-covered",
            "title": "Redan täckt: CVE-2026-22222",
            "sources": [],
        }]
        candidate.write()

        with self.assertRaises(gate.GateOutcome) as caught:
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

    def test_blocked_decision_is_a_technical_error(self) -> None:
        # A real failure must never leave a decision a notifier or a merge
        # step could mistake for a passing result.
        candidate = self.candidate("broken", 98)
        candidate.pr["head"]["repo"]["full_name"] = "attacker/fork"
        candidate.write()
        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_BLOCKED)
        self.assertEqual(decision["outcome"], gate.OUTCOME_BLOCKED)
        self.assertIs(decision["technical_error"], True)
        self.assertIs(decision["notify_human"], True)
        self.assertNotEqual(decision["outcome"], gate.OUTCOME_ACTIONABLE)


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

    def test_policy_workflow_passes_only_actionable_and_noop_stale(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher-policy.yml").read_text(
            encoding="utf-8"
        )
        enforce = workflow[workflow.index("  publisher-policy:"):]
        case_block = enforce[enforce.index('case "$OUTCOME" in'):]
        arms = re.findall(r"^\s{12}(\S+)\)$", case_block, re.M)
        self.assertEqual(
            arms,
            ["ACTIONABLE", "NOOP_STALE", "POLICY_SKIP", "NEEDS_HUMAN", "BLOCKED", "*"],
        )
        # Only ACTIONABLE and NOOP_STALE may leave the required check green.
        for arm in ("POLICY_SKIP", "NEEDS_HUMAN", "BLOCKED", "*"):
            body = case_block.split(f"\n            {arm})\n", 1)[1]
            self.assertIn("exit 1", body.split(";;", 1)[0])
        for arm in ("ACTIONABLE", "NOOP_STALE"):
            body = case_block.split(f"\n            {arm})\n", 1)[1]
            self.assertNotIn("exit 1", body.split(";;", 1)[0])

        # A skipped required check counts as satisfied, so the enforcement job
        # must run even when classification failed.
        self.assertIn("if: ${{ always() }}", enforce)
        self.assertIn(
            'if [[ "$CLASSIFY_RESULT" != "success" ]]; then', enforce
        )


class NeedsHumanTests(unittest.TestCase):
    """NEEDS_HUMAN: understood, not publishable, a person must act."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="needs-human-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self, name: str, *, number: int = 70) -> Candidate:
        return Candidate(
            self.root / name,
            head_ref=f"adam/gen3-{name}",
            number=number,
            head_sha=HEAD_SHA,
        )

    def assert_needs_human(self, candidate: Candidate, reason_code: str) -> dict:
        with self.assertRaises(gate.GateOutcome) as caught:
            gate.validate(candidate.args())
        self.assertEqual(caught.exception.outcome, gate.OUTCOME_NEEDS_HUMAN)
        self.assertEqual(caught.exception.reason_code, reason_code)

        code, decision = candidate.run_cli()
        self.assertEqual(code, gate.EXIT_NEEDS_HUMAN)
        self.assertEqual(code, 5)
        self.assertEqual(decision["outcome"], gate.OUTCOME_NEEDS_HUMAN)
        self.assertEqual(decision["reason_code"], reason_code)
        self.assertIs(decision["notify_human"], True)
        self.assertIs(decision["technical_error"], False)
        return decision

    # 1. Explicit human-review policy.
    def test_class_b_needs_human(self) -> None:
        candidate = self.candidate("classb")
        candidate.append_event({
            **deepcopy(CLEAN_EVENT), "publication_class": "B",
        })
        candidate.write()
        self.assert_needs_human(candidate, "CLASS_B_EDITORIAL")

    def test_confidence_below_threshold_needs_human(self) -> None:
        candidate = self.candidate("confidence")
        candidate.append_event({
            **deepcopy(CLEAN_EVENT),
            "confidence": "corroborated",
            "sources": [
                {"id": "uk-ncsc", "url": "https://www.ncsc.gov.uk/news/a"},
                {"id": "cert-eu", "url": "https://cert.europa.eu/news/b"},
            ],
        })
        candidate.write()
        self.assert_needs_human(candidate, "UNVERIFIED_CONFIDENCE")

    def test_multiple_appended_events_needs_human(self) -> None:
        candidate = self.candidate("multi")
        extra = {
            **deepcopy(CLEAN_EVENT),
            "id": "uk-ncsc:CVE-2026-33333",
            "cves": ["CVE-2026-33333"],
            "sources": [{
                "id": "uk-ncsc",
                "url": "https://www.ncsc.gov.uk/news/second-advisory",
            }],
        }
        candidate.head_events["events"] = [
            deepcopy(PRIOR_EVENT), deepcopy(CLEAN_EVENT), extra,
        ]
        candidate.write()
        self.assert_needs_human(candidate, "MULTIPLE_EVENTS")


    # 2. Stale but otherwise valid PR.
    def test_stale_base_needs_human_and_is_benign_for_the_workflow(self) -> None:
        candidate = self.candidate("stale", number=71)
        candidate.make_stale_base()
        candidate.write()
        decision = self.assert_needs_human(candidate, "STALE_BASE")
        self.assertEqual(decision["pr_number"], 71)

        # Benign for the workflow: the queue continues, and neither a token
        # nor a merge can follow a non-zero exit code.
        result = run_publisher_queue([candidate])
        self.assertEqual(result["result"], "no_actionable_candidate")
        self.assertEqual(result["notified"], [71])

    # 3. Malformed base metadata is never a review case.
    def test_malformed_base_metadata_is_blocked(self) -> None:
        cases = {
            "missing base sha": lambda c: c.pr["base"].pop("sha"),
            "short base sha": lambda c: c.pr["base"].update({"sha": "abc"}),
            "non-hex base sha": lambda c: c.pr["base"].update({"sha": "z" * 40}),
            "base sha not a string": lambda c: c.pr["base"].update({"sha": 12345}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                candidate = self.candidate(f"bad-{len(label)}", number=72)
                mutate(candidate)
                candidate.write()
                code, decision = candidate.run_cli()
                self.assertEqual(code, gate.EXIT_BLOCKED)
                self.assertEqual(decision["outcome"], gate.OUTCOME_BLOCKED)
                self.assertIs(decision["technical_error"], True)

    def test_unknown_values_are_blocked_not_needs_human(self) -> None:
        # "We do not recognise this" is never "a human should review this".
        cases = {
            "unknown publication_class": lambda c: c.append_event({
                **deepcopy(CLEAN_EVENT), "publication_class": "C",
            }),
            "unknown confidence": lambda c: c.append_event({
                **deepcopy(CLEAN_EVENT), "confidence": "probably-fine",
            }),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                candidate = self.candidate(f"unknown-{len(label)}", number=73)
                mutate(candidate)
                candidate.write()
                code, decision = candidate.run_cli()
                self.assertEqual(code, gate.EXIT_BLOCKED)
                self.assertIs(decision["technical_error"], True)

    def test_removing_or_rewriting_published_events_is_blocked(self) -> None:
        # Integrity violations are never an editorial review case, even
        # though a multi-event append is.
        cases = {
            "published event removed": lambda c: c.head_events.update(
                {"events": [deepcopy(CLEAN_EVENT)]}
            ),
            "published event rewritten": lambda c: c.head_events["events"][0].update(
                {"title": "MUTATED"}
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                candidate = self.candidate(f"integrity-{len(label)}", number=74)
                mutate(candidate)
                candidate.write()
                code, decision = candidate.run_cli()
                self.assertEqual(code, gate.EXIT_BLOCKED)
                self.assertIs(decision["technical_error"], True)


class QueueOrderTests(unittest.TestCase):
    """Queue behaviour across the full outcome contract."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="queue-order-test-")
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

    def needs_human_candidate(self, name: str, number: int, sha: str) -> Candidate:
        candidate = self.candidate(name, number=number, head_sha=sha)
        candidate.append_event({
            **deepcopy(CLEAN_EVENT), "publication_class": "B",
        })
        candidate.write()
        return candidate

    def policy_skip_candidate(self, name: str, number: int, sha: str) -> Candidate:
        candidate = self.candidate(name, number=number, head_sha=sha)
        candidate.append_event(KEV_EVENT)
        candidate.write()
        return candidate

    # 4. NEEDS_HUMAN must not head-of-line block an unrelated ACTIONABLE PR.
    def test_needs_human_does_not_block_next_candidate(self) -> None:
        first = self.needs_human_candidate("classb", 80, "c" * 40)
        second = self.candidate("clean", number=81, head_sha="d" * 40).write()

        result = run_publisher_queue([first, second])
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 81)
        self.assertEqual(result["skipped"], [80])
        self.assertEqual(result["notified"], [80])

    # 5. POLICY_SKIP then NEEDS_HUMAN then ACTIONABLE.
    def test_queue_walks_past_both_benign_and_human_outcomes(self) -> None:
        first = self.policy_skip_candidate("kev", 82, "c" * 40)
        second = self.needs_human_candidate("classb", 83, "d" * 40)
        third = self.candidate("clean", number=84, head_sha="e" * 40).write()

        result = run_publisher_queue([first, second, third])
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 84)
        self.assertEqual(result["skipped"], [82, 83])
        # Only the human-review candidate raises a person.
        self.assertEqual(result["notified"], [83])

    # 6. A hard failure before an ACTIONABLE candidate stops everything.
    def test_hard_failure_stops_queue_before_actionable(self) -> None:
        broken = self.candidate("broken", number=85, head_sha="c" * 40)
        broken.pr["head"]["repo"]["full_name"] = "attacker/fork"
        broken.write()
        actionable = self.candidate("clean", number=86, head_sha="d" * 40).write()

        result = run_publisher_queue([broken, actionable])
        self.assertEqual(result["result"], "failed")
        self.assertEqual(result["pr_number"], 85)
        self.assertEqual(result["exit_code"], gate.EXIT_BLOCKED)
        # The later ACTIONABLE candidate was never evaluated or published.
        self.assertEqual(result["evaluated"], [85])
        self.assertNotIn(86, result["evaluated"])

    # 7. More candidates than the old hard-coded limit of 10.
    def test_more_than_ten_candidates_have_no_silent_starvation(self) -> None:
        candidates = [
            self.policy_skip_candidate(f"kev{i}", 100 + i, f"{i:040x}")
            for i in range(12)
        ]
        actionable = self.candidate(
            "clean", number=200, head_sha="f" * 40
        ).write()
        candidates.append(actionable)

        result = run_publisher_queue(candidates)
        self.assertEqual(result["result"], "published")
        self.assertEqual(result["pr_number"], 200)
        self.assertEqual(len(result["skipped"]), 12)
        self.assertEqual(len(result["evaluated"]), 13)

    # 8. An unknown exit code must fail closed.
    def test_unknown_exit_code_fails_closed(self) -> None:
        codes = [1, 6, 42, 127]
        for code in codes:
            with self.subTest(code=code):
                self.assertNotIn(code, gate.NON_ACTIONABLE_EXIT_CODES.values())
                self.assertNotEqual(code, gate.EXIT_ACTIONABLE)

        workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )
        case_block = workflow[workflow.index('case "$rc" in'):]
        arms = re.findall(r"^\s{14}(\S+)\)$", case_block, re.M)
        self.assertEqual(arms, ["0", "3", "4", "5", "*"])
        self.assertIn("Publisher gate failed for PR #$pr (exit $rc)", case_block)


class QueueBoundTests(unittest.TestCase):
    """Truncation must be explicit, never silent starvation."""

    def setUp(self) -> None:
        self.workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )

    def test_listing_bound_is_detected_and_blocks(self) -> None:
        self.assertIn("LIST_LIMIT=100", self.workflow)
        self.assertIn("MAX_CANDIDATES=25", self.workflow)
        self.assertIn(
            "open PR listing hit the $LIST_LIMIT bound and may be truncated",
            self.workflow,
        )
        self.assertIn(
            "exceeds the $MAX_CANDIDATES evaluation bound", self.workflow
        )

    def test_no_silent_cap_remains(self) -> None:
        # The old silent break at candidate 10 must be gone.
        self.assertNotIn("(( ${#candidates[@]} >= 10 ))", self.workflow)
        self.assertNotIn("candidates[@]} >= 10", self.workflow)

    def test_bound_breach_stops_before_any_candidate_is_evaluated(self) -> None:
        pick = self.workflow[
            self.workflow.index("List Adam candidates oldest first"):
            self.workflow.index("Fetch public AI-hot coverage")
        ]
        # Both bound checks live in the listing step, before any gate runs.
        self.assertIn("may be truncated", pick)
        self.assertIn("evaluation bound", pick)
        self.assertNotIn("publisher_gate.py", pick)


class NotifyContractTests(unittest.TestCase):
    """9-12: exactly which outcomes reach a person, and when a token may exist."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="notify-contract-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def candidate(self, name: str, number: int = 90) -> Candidate:
        return Candidate(
            self.root / name,
            head_ref=f"adam/gen3-{name}",
            number=number,
            head_sha=HEAD_SHA,
        )

    def test_notify_matrix(self) -> None:
        noop = self.candidate("noop")
        noop.make_noop()
        noop.write()

        skip = self.candidate("kev")
        skip.append_event(KEV_EVENT)
        skip.write()

        human = self.candidate("classb")
        human.append_event({**deepcopy(CLEAN_EVENT), "publication_class": "B"})
        human.write()

        actionable = self.candidate("clean").write()

        expected = [
            ("NOOP_STALE", noop, gate.EXIT_NOOP_STALE, False),
            ("POLICY_SKIP", skip, gate.EXIT_POLICY_SKIP, False),
            ("NEEDS_HUMAN", human, gate.EXIT_NEEDS_HUMAN, True),
            ("ACTIONABLE", actionable, gate.EXIT_ACTIONABLE, False),
        ]
        for label, candidate, exit_code, notify in expected:
            with self.subTest(label):
                code, decision = candidate.run_cli()
                self.assertEqual(code, exit_code)
                self.assertEqual(decision["outcome"], label)
                self.assertIs(decision["notify_human"], notify)
                self.assertIs(decision["technical_error"], False)

    def test_only_needs_human_notifies_among_non_actionable(self) -> None:
        self.assertEqual(gate.NOTIFY_OUTCOMES, {gate.OUTCOME_NEEDS_HUMAN})

    # 12. A Publisher token may only exist after an ACTIONABLE decision.
    def test_token_is_gated_on_the_actionable_decision(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )
        queue = workflow.index("Evaluate candidate queue")
        mint = workflow.index("Mint short-lived publisher token")
        merge = workflow.index("Merge exact validated head")
        self.assertLess(queue, mint)
        self.assertLess(mint, merge)

        # actionable is only ever set true on the exit-0 arm, which also
        # verifies the decision says ACTIONABLE for this exact candidate.
        queue_step = workflow[queue:mint]
        self.assertIn("Gate exited 0 without an ACTIONABLE decision", queue_step)
        self.assertIn("Gate decision does not match evaluated candidate", queue_step)
        self.assertEqual(queue_step.count('echo "actionable=true"'), 1)

        mint_step = workflow[mint:merge]
        self.assertIn("steps.queue.outputs.actionable == 'true' &&", mint_step)
        self.assertIn("PUBLISHER_APP_PRIVATE_KEY", mint_step)
        # No token material may appear before the gate has run.
        self.assertNotIn("PUBLISHER_APP_PRIVATE_KEY", workflow[:queue])
        self.assertNotIn("app-token", workflow[:queue])


if __name__ == "__main__":
    unittest.main(verbosity=2)
