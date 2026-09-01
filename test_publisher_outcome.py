#!/usr/bin/env python3
"""Regression tests for the trusted publisher-outcome contract.

Covers the classifier that turns a gate run into a bounded (outcome,
reason_code) pair, and the workflow wiring that publishes it as a check-run
name bound to the exact PR head SHA. Everything is offline.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY_WORKFLOW = ROOT / ".github/workflows/publisher-policy.yml"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


gate = load_module("publisher_gate", ROOT / "publisher_gate.py")
outcome_mod = load_module("publisher_outcome", ROOT / "publisher_outcome.py")


def payload(outcome: str, reason_code: str) -> dict:
    return {
        "decision": outcome,
        "outcome": outcome,
        "reason_code": reason_code,
        "notify_human": (
            outcome in gate.NOTIFY_OUTCOMES or outcome == gate.OUTCOME_BLOCKED
        ),
        "technical_error": outcome == gate.OUTCOME_BLOCKED,
        "pr_number": 43,
        "head_sha": "b" * 40,
    }


class ClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="outcome-test-")
        self.root = Path(self.temp.name)
        self.decision = self.root / "decision.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, exit_code: int, raw: str | None) -> tuple[int, str, dict]:
        if raw is not None:
            self.decision.write_text(raw, encoding="utf-8")
        github_output = self.root / "github-output"
        github_output.write_text("", encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, str(ROOT / "publisher_outcome.py"),
                "--exit-code", str(exit_code),
                "--decision", str(self.decision),
                "--github-output", str(github_output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        emitted = {}
        for line in github_output.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                emitted[key] = value
        return proc.returncode, (proc.stdout + proc.stderr), emitted

    def test_every_outcome_classifies(self) -> None:
        cases = [
            (gate.OUTCOME_ACTIONABLE, "APPEND_ONLY", 0),
            (gate.OUTCOME_NOOP_STALE, "NO_NET_DIFF", 3),
            (gate.OUTCOME_POLICY_SKIP, "NATIVE_SOURCE_COVERED", 4),
            (gate.OUTCOME_POLICY_SKIP, "DRAFT_PR", 4),
            (gate.OUTCOME_NEEDS_HUMAN, "STALE_BASE", 5),
            (gate.OUTCOME_NEEDS_HUMAN, "CLASS_B_EDITORIAL", 5),
            (gate.OUTCOME_BLOCKED, "GATE_BLOCKED", 2),
        ]
        for outcome, reason, exit_code in cases:
            with self.subTest(f"{outcome}/{reason}"):
                code, _, emitted = self.run_cli(
                    exit_code, json.dumps(payload(outcome, reason))
                )
                self.assertEqual(code, 0)
                self.assertEqual(emitted["outcome"], outcome)
                self.assertEqual(emitted["reason_code"], reason)

    def test_exit_code_must_agree_with_the_payload(self) -> None:
        # A payload that disagrees with the process result is exactly the
        # "we do not know what happened" case.
        code, err, emitted = self.run_cli(
            0, json.dumps(payload(gate.OUTCOME_NEEDS_HUMAN, "STALE_BASE"))
        )
        self.assertEqual(code, 1)
        self.assertIn("CLASSIFIER_FAILURE", err)
        self.assertEqual(emitted, {})

    def test_unknown_exit_code_fails_closed(self) -> None:
        for exit_code in (1, 6, 42, 127):
            with self.subTest(exit_code=exit_code):
                code, err, emitted = self.run_cli(
                    exit_code,
                    json.dumps(payload(gate.OUTCOME_ACTIONABLE, "APPEND_ONLY")),
                )
                self.assertEqual(code, 1)
                self.assertIn("unknown gate exit code", err)
                self.assertEqual(emitted, {})

    def test_reason_code_outside_the_registry_fails_closed(self) -> None:
        cases = [
            (gate.OUTCOME_POLICY_SKIP, "STALE_BASE"),        # right shape, wrong outcome
            (gate.OUTCOME_NEEDS_HUMAN, "TOTALLY_MADE_UP"),
            (gate.OUTCOME_ACTIONABLE, "lowercase_code"),
            (gate.OUTCOME_ACTIONABLE, "A"),
            (gate.OUTCOME_ACTIONABLE, "X" * 64),
        ]
        for outcome, reason in cases:
            with self.subTest(f"{outcome}/{reason}"):
                body = payload(outcome, reason)
                exit_code = gate.OUTCOME_EXIT_CODES[outcome]
                code, err, emitted = self.run_cli(exit_code, json.dumps(body))
                self.assertEqual(code, 1)
                self.assertIn("CLASSIFIER_FAILURE", err)
                self.assertEqual(emitted, {})

    def test_untrusted_text_can_never_reach_a_check_name(self) -> None:
        # A hostile PR title smuggled into the payload must not be emitted.
        hostile = [
            "ACTIONABLE / APPEND_ONLY",
            "APPEND_ONLY\nreason_code=EVIL",
            "APPEND_ONLY; rm -rf /",
            "../../etc/passwd",
        ]
        for reason in hostile:
            with self.subTest(reason=reason):
                body = payload(gate.OUTCOME_ACTIONABLE, reason)
                code, _, emitted = self.run_cli(0, json.dumps(body))
                self.assertEqual(code, 1)
                self.assertEqual(emitted, {})

    def test_malformed_payloads_fail_closed(self) -> None:
        cases = {
            "not json": "{broken",
            "not an object": "[1, 2, 3]",
            "empty": "",
            "missing outcome": json.dumps({"reason_code": "APPEND_ONLY"}),
            "missing reason_code": json.dumps({"outcome": "ACTIONABLE"}),
            "null outcome": json.dumps(
                {**payload("ACTIONABLE", "APPEND_ONLY"), "outcome": None}
            ),
            "numeric reason": json.dumps(
                {**payload("ACTIONABLE", "APPEND_ONLY"), "reason_code": 7}
            ),
        }
        for label, raw in cases.items():
            with self.subTest(label):
                code, err, emitted = self.run_cli(0, raw)
                self.assertEqual(code, 1)
                self.assertIn("CLASSIFIER_FAILURE", err)
                self.assertEqual(emitted, {})

    def test_missing_payload_fails_closed(self) -> None:
        code, err, emitted = self.run_cli(0, None)
        self.assertEqual(code, 1)
        self.assertIn("CLASSIFIER_FAILURE", err)
        self.assertEqual(emitted, {})

    def test_notify_and_technical_flags_must_match_the_outcome(self) -> None:
        cases = {
            "policy skip claiming notify": (
                gate.OUTCOME_POLICY_SKIP, "DRAFT_PR", {"notify_human": True}
            ),
            "needs human claiming silence": (
                gate.OUTCOME_NEEDS_HUMAN, "STALE_BASE", {"notify_human": False}
            ),
            "actionable claiming technical error": (
                gate.OUTCOME_ACTIONABLE, "APPEND_ONLY", {"technical_error": True}
            ),
            "blocked hiding technical error": (
                gate.OUTCOME_BLOCKED, "GATE_BLOCKED", {"technical_error": False}
            ),
        }
        for label, (outcome, reason, override) in cases.items():
            with self.subTest(label):
                body = {**payload(outcome, reason), **override}
                exit_code = gate.OUTCOME_EXIT_CODES[outcome]
                code, _, emitted = self.run_cli(exit_code, json.dumps(body))
                self.assertEqual(code, 1)
                self.assertEqual(emitted, {})


class ReasonRegistryTests(unittest.TestCase):
    """The registry must stay the single source of truth."""

    def test_every_reason_code_in_the_gate_is_registered(self) -> None:
        source = (ROOT / "publisher_gate.py").read_text(encoding="utf-8")
        used = set(re.findall(r'(?:policy_skip|needs_human)\(\s*"([A-Z_0-9]+)"', source))
        used.update(re.findall(r'require_policy\(\s*[^,]+,\s*\n\s*"([A-Z_0-9]+)"', source))
        used.update(re.findall(r'"reason_code": "([A-Z_0-9]+)"', source))
        used.update(re.findall(r'GateOutcome\(\s*\n\s*\w+,\s*\n\s*"([A-Z_0-9]+)"', source))

        registered = set()
        for codes in gate.REASON_CODES.values():
            registered.update(codes)

        self.assertTrue(used, "no reason codes discovered in publisher_gate.py")
        self.assertEqual(used - registered, set())

    def test_policy_gate_reason_codes_are_registered(self) -> None:
        source = (ROOT / "publisher_policy_gate.py").read_text(encoding="utf-8")
        used = set(re.findall(r'"reason_code": "([A-Z_0-9]+)"', source))
        registered = gate.REASON_CODES[gate.OUTCOME_ACTIONABLE]
        self.assertTrue(used)
        self.assertEqual(used - registered, set())

    def test_registry_shape_is_bounded(self) -> None:
        for outcome, codes in gate.REASON_CODES.items():
            self.assertIn(outcome, gate.OUTCOME_EXIT_CODES)
            for code in codes:
                self.assertRegex(code, r"^[A-Z][A-Z0-9_]{2,39}$")
                self.assertTrue(gate.valid_reason_code(outcome, code))

    def test_codes_are_not_shared_across_outcomes(self) -> None:
        # A check name must identify the outcome unambiguously.
        seen: dict[str, str] = {}
        for outcome, codes in gate.REASON_CODES.items():
            for code in codes:
                self.assertNotIn(code, seen, f"{code} also used by {seen.get(code)}")
                seen[code] = outcome

    def test_gate_refuses_an_unregistered_code(self) -> None:
        with self.assertRaises(gate.GateError):
            gate.GateOutcome(gate.OUTCOME_NEEDS_HUMAN, "NOT_A_REAL_CODE", "x")
        with self.assertRaises(gate.GateError):
            gate.GateOutcome(gate.OUTCOME_NEEDS_HUMAN, "DRAFT_PR", "x")


class OutcomeWorkflowTests(unittest.TestCase):
    """The carrier job must publish the classification without opening merge."""

    def setUp(self) -> None:
        self.workflow = POLICY_WORKFLOW.read_text(encoding="utf-8")

    def job(self, header: str) -> str:
        start = self.workflow.index(header)
        rest = self.workflow[start + len(header):]
        nxt = re.search(r"\n  [a-z][a-z0-9-]*:\n", rest)
        return header + (rest[:nxt.start()] if nxt else rest)

    def test_outcome_check_name_is_built_only_from_trusted_outputs(self) -> None:
        job = self.job("  publisher-outcome:\n")
        self.assertIn(
            "name: publisher-outcome / "
            "${{ needs.classify.outputs.outcome }} / "
            "${{ needs.classify.outputs.reason_code }}",
            job,
        )
        # Nothing untrusted may appear in the name or the job.
        for untrusted in (
            "pull_request.title",
            "pull_request.body",
            "pull_request.labels",
            "pull_request.head.ref",
            "github.head_ref",
        ):
            self.assertNotIn(untrusted, job)

    def test_outcome_job_is_guarded_and_inert(self) -> None:
        job = self.job("  publisher-outcome:\n")
        self.assertIn("needs: classify", job)
        self.assertIn("needs.classify.result == 'success'", job)
        self.assertIn("needs.classify.outputs.outcome != ''", job)
        self.assertIn("needs.classify.outputs.reason_code != ''", job)
        # Read-only: no gh calls, no writes, no secrets, no checkout.
        for forbidden in ("gh api", "gh pr", "secrets.", "actions/checkout", "curl "):
            self.assertNotIn(forbidden, job)

    def test_outcome_check_is_not_the_required_check(self) -> None:
        # The required context is the literal name "publisher-policy"; the
        # carrier's name always starts with "publisher-outcome / ".
        self.assertIn("    name: publisher-policy\n", self.workflow)
        self.assertIn("name: publisher-outcome / ", self.workflow)
        self.assertNotIn("name: publisher-policy / ", self.workflow)

    def test_classifier_is_fail_closed_in_the_workflow(self) -> None:
        job = self.job("  classify:\n")
        self.assertIn("publisher_outcome.py", job)
        self.assertIn("--exit-code", job)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', job)
        # The classifier call is NOT tolerated with || rc=$?, so a classifier
        # failure fails the job and publishes no outcome check.
        tail = job[job.index("python3 publisher_outcome.py"):]
        self.assertNotIn("|| rc=", tail)
        self.assertNotIn("|| true", tail)

    def test_no_new_permissions_anywhere(self) -> None:
        self.assertIn("permissions:\n  contents: read\n  pull-requests: read\n",
                      self.workflow)
        for write in ("contents: write", "pull-requests: write",
                      "checks: write", "statuses: write", "issues: write"):
            self.assertNotIn(write, self.workflow)
        self.assertNotIn("secrets.", self.workflow)

    def test_head_sha_binding_comes_from_the_event(self) -> None:
        # pull_request_target check runs attach to the PR head SHA, so the
        # carrier needs no SHA plumbing of its own and must not check out head.
        self.assertIn("pull_request_target:", self.workflow)
        self.assertIn("ref: main", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertNotIn("github.event.pull_request.head.sha }}", self.workflow)


class EndToEndClassificationTests(unittest.TestCase):
    """Gate output feeds the classifier without any hand-written payload."""

    def test_gate_payloads_classify_cleanly(self) -> None:
        import test_publisher_benign_skip as fixtures

        with tempfile.TemporaryDirectory(prefix="e2e-outcome-") as td:
            root = Path(td)

            def build(name: str, mutate=None):
                candidate = fixtures.Candidate(
                    root / name,
                    head_ref=f"adam/gen3-{name}",
                    number=43,
                    head_sha="b" * 40,
                )
                if mutate:
                    mutate(candidate)
                candidate.write()
                return candidate

            from copy import deepcopy

            cases = {
                "clean": (None, "ACTIONABLE", "APPEND_ONLY"),
                "kev": (
                    lambda c: c.append_event(fixtures.KEV_EVENT),
                    "POLICY_SKIP", "NATIVE_SOURCE_COVERED",
                ),
                "draft": (
                    lambda c: c.pr.update({"draft": True}),
                    "POLICY_SKIP", "DRAFT_PR",
                ),
                "noop": (lambda c: c.make_noop(), "NOOP_STALE", "NO_NET_DIFF"),
                "stale": (lambda c: c.make_stale_base(), "NEEDS_HUMAN", "STALE_BASE"),
                "classb": (
                    lambda c: c.append_event({
                        **deepcopy(fixtures.CLEAN_EVENT), "publication_class": "B",
                    }),
                    "NEEDS_HUMAN", "CLASS_B_EDITORIAL",
                ),
                "fork": (
                    lambda c: c.pr["head"]["repo"].update(
                        {"full_name": "attacker/fork"}
                    ),
                    "BLOCKED", "GATE_BLOCKED",
                ),
            }

            for name, (mutate, expected_outcome, expected_reason) in cases.items():
                with self.subTest(name):
                    candidate = build(name, mutate)
                    exit_code, decision = candidate.run_cli()
                    decision_path = candidate.root / "decision.json"
                    self.assertTrue(decision_path.is_file())

                    github_output = candidate.root / "github-output"
                    github_output.write_text("", encoding="utf-8")
                    proc = subprocess.run(
                        [
                            sys.executable, str(ROOT / "publisher_outcome.py"),
                            "--exit-code", str(exit_code),
                            "--decision", str(decision_path),
                            "--github-output", str(github_output),
                        ],
                        cwd=ROOT, text=True, capture_output=True, timeout=30,
                        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    emitted = dict(
                        line.split("=", 1)
                        for line in github_output.read_text().splitlines()
                        if "=" in line
                    )
                    self.assertEqual(emitted["outcome"], expected_outcome)
                    self.assertEqual(emitted["reason_code"], expected_reason)
                    self.assertEqual(decision["outcome"], expected_outcome)


if __name__ == "__main__":
    unittest.main(verbosity=2)
