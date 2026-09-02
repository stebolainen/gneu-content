#!/usr/bin/env python3
"""Offline trust-boundary tests for the publisher lifecycle component."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

import publisher_gate
import publisher_lifecycle as lifecycle
from test_publisher_benign_skip import Candidate, KEV_EVENT

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/publisher-lifecycle.yml"

REPOSITORY = "stebolainen/gneu-content"
PUBLISHED_SHA = "a" * 40
HEAD_SHA = "b" * 40
CONTROL_SHA = "c" * 40
HEAD_REF = "adam/gen3-lifecycle-fixture"


def decision(outcome: str, reason_code: str, *, pr: int = 48) -> dict:
    return {
        "decision": outcome,
        "outcome": outcome,
        "reason_code": reason_code,
        "notify_human": (
            outcome in publisher_gate.NOTIFY_OUTCOMES
            or outcome == publisher_gate.OUTCOME_BLOCKED
        ),
        "technical_error": outcome == publisher_gate.OUTCOME_BLOCKED,
        "pr_number": pr,
        "head_sha": HEAD_SHA,
        "head_ref": HEAD_REF,
    }


def binding(outcome: str, reason_code: str, *, pr: int = 48) -> dict:
    return lifecycle.create_binding(
        exit_code=publisher_gate.OUTCOME_EXIT_CODES[outcome],
        decision=decision(outcome, reason_code, pr=pr),
        repository=REPOSITORY,
        pr_number=pr,
        head_sha=HEAD_SHA,
        head_ref=HEAD_REF,
        base_sha=PUBLISHED_SHA,
        published_sha=PUBLISHED_SHA,
        control_sha=CONTROL_SHA,
        workflow=lifecycle.TRUSTED_WORKFLOW,
        workflow_ref=lifecycle.TRUSTED_WORKFLOW_REF,
    )


def current_pr(*, pr: int = 48) -> dict:
    return {
        "number": pr,
        "state": "open",
        "draft": False,
        "base": {
            "ref": "published",
            "sha": PUBLISHED_SHA,
            "repo": {"full_name": REPOSITORY},
        },
        "head": {
            "ref": HEAD_REF,
            "sha": HEAD_SHA,
            "repo": {"full_name": REPOSITORY},
        },
    }


def verify(bound: dict, metadata: dict, *, published_sha: str = PUBLISHED_SHA) -> dict:
    return lifecycle.verify_preclose(
        bound,
        metadata,
        current_published_sha=published_sha,
        repository=REPOSITORY,
        control_sha=CONTROL_SHA,
    )


class LifecycleOutcomeMatrixTests(unittest.TestCase):
    def test_only_the_two_exact_pairs_close(self) -> None:
        cases = [
            ("ACTIONABLE", "APPEND_ONLY", "KEEP_OPEN"),
            ("POLICY_SKIP", "NATIVE_SOURCE_COVERED", "CLOSE"),
            ("NOOP_STALE", "NO_NET_DIFF", "CLOSE"),
            ("POLICY_SKIP", "DRAFT_PR", "KEEP_OPEN"),
            ("POLICY_SKIP", "CVE_COVERED_PUBLISHED", "KEEP_OPEN"),
            ("POLICY_SKIP", "SOURCE_URL_COVERED_AIHOT", "KEEP_OPEN"),
            ("NEEDS_HUMAN", "STALE_BASE", "KEEP_OPEN"),
            ("BLOCKED", "GATE_BLOCKED", "BLOCKED"),
        ]
        for outcome, reason_code, expected in cases:
            with self.subTest(outcome=outcome, reason=reason_code):
                self.assertEqual(
                    lifecycle.lifecycle_action(outcome, reason_code),
                    expected,
                )

    def test_unknown_outcome_or_reason_fails_closed(self) -> None:
        cases = [
            ("UNKNOWN", "NO_NET_DIFF"),
            ("POLICY_SKIP", "UNKNOWN_REASON"),
            ("NOOP_STALE", "NATIVE_SOURCE_COVERED"),
        ]
        for outcome, reason_code in cases:
            with self.subTest(outcome=outcome, reason=reason_code):
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.lifecycle_action(outcome, reason_code)

    def test_exit_code_must_match_fresh_gate_decision(self) -> None:
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.create_binding(
                exit_code=publisher_gate.EXIT_ACTIONABLE,
                decision=decision("POLICY_SKIP", "NATIVE_SOURCE_COVERED"),
                repository=REPOSITORY,
                pr_number=48,
                head_sha=HEAD_SHA,
                head_ref=HEAD_REF,
                base_sha=PUBLISHED_SHA,
                published_sha=PUBLISHED_SHA,
                control_sha=CONTROL_SHA,
                workflow=lifecycle.TRUSTED_WORKFLOW,
                workflow_ref=lifecycle.TRUSTED_WORKFLOW_REF,
            )

    def test_old_outcome_cannot_override_fresh_actionable_gate(self) -> None:
        # Model an old publisher-outcome saying terminal POLICY_SKIP. Lifecycle
        # never consumes it: the newly supplied trusted gate result wins.
        old = decision("POLICY_SKIP", "NATIVE_SOURCE_COVERED")
        fresh = decision("ACTIONABLE", "APPEND_ONLY")
        self.assertNotEqual(old["outcome"], fresh["outcome"])
        bound = lifecycle.create_binding(
            exit_code=publisher_gate.EXIT_ACTIONABLE,
            decision=fresh,
            repository=REPOSITORY,
            pr_number=48,
            head_sha=HEAD_SHA,
            head_ref=HEAD_REF,
            base_sha=PUBLISHED_SHA,
            published_sha=PUBLISHED_SHA,
            control_sha=CONTROL_SHA,
            workflow=lifecycle.TRUSTED_WORKFLOW,
            workflow_ref=lifecycle.TRUSTED_WORKFLOW_REF,
        )
        self.assertEqual(bound["action"], "KEEP_OPEN")

    def test_realistic_pr_48_native_shape_would_close(self) -> None:
        # PR #48 is only a fixture shape. This test never contacts GitHub.
        with tempfile.TemporaryDirectory(prefix="lifecycle-pr48-") as temp:
            candidate = Candidate(
                Path(temp),
                head_ref=HEAD_REF,
                number=48,
                head_sha=HEAD_SHA,
            )
            candidate.append_event(KEV_EVENT)
            candidate.write()
            exit_code, fresh = candidate.run_cli()

        bound = lifecycle.create_binding(
            exit_code=exit_code,
            decision=fresh,
            repository=REPOSITORY,
            pr_number=48,
            head_sha=HEAD_SHA,
            head_ref=HEAD_REF,
            base_sha=PUBLISHED_SHA,
            published_sha=PUBLISHED_SHA,
            control_sha=CONTROL_SHA,
            workflow=lifecycle.TRUSTED_WORKFLOW,
            workflow_ref=lifecycle.TRUSTED_WORKFLOW_REF,
        )
        self.assertEqual(
            (bound["outcome"], bound["reason_code"], bound["action"]),
            ("POLICY_SKIP", "NATIVE_SOURCE_COVERED", "CLOSE"),
        )

    def test_realistic_pr_45_noop_shape_would_close(self) -> None:
        # PR #45 is likewise an offline shape for a commit-plus-revert no-op.
        with tempfile.TemporaryDirectory(prefix="lifecycle-pr45-") as temp:
            candidate = Candidate(
                Path(temp),
                head_ref=HEAD_REF,
                number=45,
                head_sha=HEAD_SHA,
            )
            candidate.make_noop()
            candidate.write()
            exit_code, fresh = candidate.run_cli()

        bound = lifecycle.create_binding(
            exit_code=exit_code,
            decision=fresh,
            repository=REPOSITORY,
            pr_number=45,
            head_sha=HEAD_SHA,
            head_ref=HEAD_REF,
            base_sha=PUBLISHED_SHA,
            published_sha=PUBLISHED_SHA,
            control_sha=CONTROL_SHA,
            workflow=lifecycle.TRUSTED_WORKFLOW,
            workflow_ref=lifecycle.TRUSTED_WORKFLOW_REF,
        )
        self.assertEqual(
            (bound["outcome"], bound["reason_code"], bound["action"]),
            ("NOOP_STALE", "NO_NET_DIFF", "CLOSE"),
        )


class ExactBindingAndRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bound = binding("POLICY_SKIP", "NATIVE_SOURCE_COVERED")

    def test_exact_unchanged_binding_allows_close(self) -> None:
        result = verify(self.bound, current_pr())
        self.assertEqual(result["action"], "CLOSE")
        self.assertEqual(result["action_reason"], "EXACT_BINDING_VERIFIED")

    def test_head_change_defers(self) -> None:
        metadata = current_pr()
        metadata["head"]["sha"] = "d" * 40
        self.assertEqual(verify(self.bound, metadata)["action_reason"], "HEAD_CHANGED")

    def test_published_change_defers(self) -> None:
        result = verify(self.bound, current_pr(), published_sha="d" * 40)
        self.assertEqual(result["action_reason"], "PUBLISHED_CHANGED")

    def test_already_closed_is_benign(self) -> None:
        metadata = current_pr()
        metadata["state"] = "closed"
        self.assertEqual(verify(self.bound, metadata)["action"], "BENIGN_SKIP")

    def test_draft_now_stays_open(self) -> None:
        metadata = current_pr()
        metadata["draft"] = True
        result = verify(self.bound, metadata)
        self.assertEqual((result["action"], result["action_reason"]),
                         ("KEEP_OPEN", "DRAFT_NOW"))

    def test_base_change_defers(self) -> None:
        metadata = current_pr()
        metadata["base"]["ref"] = "main"
        self.assertEqual(verify(self.bound, metadata)["action_reason"], "BASE_CHANGED")

    def test_head_ref_change_defers(self) -> None:
        metadata = current_pr()
        metadata["head"]["ref"] = "adam/gen3-different"
        self.assertEqual(verify(self.bound, metadata)["action_reason"], "HEAD_REF_CHANGED")

    def test_base_sha_change_defers(self) -> None:
        metadata = current_pr()
        metadata["base"]["sha"] = "d" * 40
        self.assertEqual(verify(self.bound, metadata)["action_reason"], "BASE_SHA_CHANGED")

    def test_base_that_was_already_stale_at_classification_defers(self) -> None:
        stale = deepcopy(self.bound)
        stale["base_sha"] = "d" * 40
        metadata = current_pr()
        metadata["base"]["sha"] = "d" * 40
        result = verify(stale, metadata)
        self.assertEqual(result["action_reason"], "CLASSIFIED_BASE_NOT_CURRENT")

    def test_fork_or_base_repository_mismatch_blocks(self) -> None:
        for side in ("head", "base"):
            with self.subTest(side=side):
                metadata = current_pr()
                metadata[side]["repo"]["full_name"] = "attacker/fork"
                result = verify(self.bound, metadata)
                self.assertEqual(result["action"], "BLOCKED")

    def test_namespace_mismatch_blocks(self) -> None:
        metadata = current_pr()
        metadata["head"]["ref"] = "feature/not-adam"
        result = verify(self.bound, metadata)
        self.assertEqual(
            (result["action"], result["action_reason"]),
            ("BLOCKED", "HEAD_NAMESPACE_MISMATCH"),
        )

    def test_malformed_metadata_fails_closed(self) -> None:
        cases = []
        missing_repo = current_pr()
        del missing_repo["head"]["repo"]
        cases.append(missing_repo)
        bad_head_sha = current_pr()
        bad_head_sha["head"]["sha"] = "not-a-sha"
        cases.append(bad_head_sha)
        bad_base_sha = current_pr()
        bad_base_sha["base"]["sha"] = None
        cases.append(bad_base_sha)
        for malformed in cases:
            with self.subTest(metadata=malformed):
                with self.assertRaises(lifecycle.LifecycleError):
                    verify(self.bound, malformed)

    def test_binding_is_tied_to_trusted_repo_workflow_and_control_sha(self) -> None:
        cases = [
            {"repository": "attacker/fork", "control_sha": CONTROL_SHA},
            {"repository": REPOSITORY, "control_sha": "d" * 40},
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.verify_preclose(
                        self.bound,
                        current_pr(),
                        current_published_sha=PUBLISHED_SHA,
                        **case,
                    )

        tampered = deepcopy(self.bound)
        tampered["workflow"] = "untrusted-workflow"
        with self.assertRaises(lifecycle.LifecycleError):
            verify(tampered, current_pr())

        tampered = deepcopy(self.bound)
        tampered["workflow_ref"] = "attacker/fork/.github/workflows/evil.yml@main"
        with self.assertRaises(lifecycle.LifecycleError):
            verify(tampered, current_pr())

    def test_non_allowlisted_binding_stays_open_after_exact_recheck(self) -> None:
        for outcome, reason_code in [
            ("ACTIONABLE", "APPEND_ONLY"),
            ("POLICY_SKIP", "DRAFT_PR"),
            ("NEEDS_HUMAN", "STALE_BASE"),
        ]:
            with self.subTest(outcome=outcome, reason=reason_code):
                result = verify(binding(outcome, reason_code), current_pr())
                self.assertEqual(result["action"], "KEEP_OPEN")


class LifecycleCliTests(unittest.TestCase):
    def test_bind_then_exact_verify_cli(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lifecycle-cli-") as temp:
            root = Path(temp)
            decision_path = root / "decision.json"
            binding_path = root / "binding.json"
            current_path = root / "current-pr.json"
            decision_path.write_text(
                json.dumps(decision("POLICY_SKIP", "NATIVE_SOURCE_COVERED")),
                encoding="utf-8",
            )
            current_path.write_text(json.dumps(current_pr()), encoding="utf-8")

            common_env = {
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            bind_proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "publisher_lifecycle.py"),
                    "bind",
                    "--exit-code", str(publisher_gate.EXIT_POLICY_SKIP),
                    "--decision", str(decision_path),
                    "--repository", REPOSITORY,
                    "--pr-number", "48",
                    "--head-sha", HEAD_SHA,
                    "--head-ref", HEAD_REF,
                    "--base-sha", PUBLISHED_SHA,
                    "--published-sha", PUBLISHED_SHA,
                    "--control-sha", CONTROL_SHA,
                    "--workflow", lifecycle.TRUSTED_WORKFLOW,
                    "--workflow-ref", lifecycle.TRUSTED_WORKFLOW_REF,
                    "--out", str(binding_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
                env=common_env,
            )
            self.assertEqual(bind_proc.returncode, 0, bind_proc.stderr)

            verify_proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "publisher_lifecycle.py"),
                    "verify",
                    "--binding", str(binding_path),
                    "--current-pr", str(current_path),
                    "--current-published-sha", PUBLISHED_SHA,
                    "--repository", REPOSITORY,
                    "--control-sha", CONTROL_SHA,
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
                env=common_env,
            )
            self.assertEqual(verify_proc.returncode, 0, verify_proc.stderr)
            self.assertEqual(json.loads(verify_proc.stdout)["action"], "CLOSE")


class LifecycleWorkflowGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_trigger_and_permissions_are_exact(self) -> None:
        trusted_prefix = self.workflow.split("concurrency:", 1)[0]
        self.assertIn('cron: "*/15 * * * *"', trusted_prefix)
        self.assertIn("workflow_dispatch:", trusted_prefix)
        self.assertIn("default: true", trusted_prefix)
        self.assertNotIn("pull_request_target", trusted_prefix)
        self.assertIn("permissions:\n  contents: read\n  pull-requests: write\n", trusted_prefix)
        self.assertEqual(trusted_prefix.count(": write"), 1)
        for forbidden in (
            "contents: write",
            "issues: write",
            "checks: write",
            "actions: write",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_trusted_main_only_and_no_pr_head_checkout(self) -> None:
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertEqual(self.workflow.count("uses: actions/checkout@"), 1)
        self.assertNotIn("git checkout", self.workflow)
        self.assertNotIn("github.event.pull_request.head", self.workflow)

    def test_fresh_gate_validator_and_exact_binding_are_mandatory(self) -> None:
        self.assertIn("publisher_policy_gate.py", self.workflow)
        self.assertIn("publisher_lifecycle.py bind", self.workflow)
        self.assertIn("publisher_lifecycle.py verify", self.workflow)
        self.assertIn('cp ./validate_content.py "$validator_root/validate_content.py"',
                      self.workflow)
        self.assertIn('python3 "$validator_root/validate_content.py"', self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("env -u GH_TOKEN -u GITHUB_TOKEN"),
            4,
        )
        self.assertIn("--control-sha \"$CONTROL_SHA\"", self.workflow)
        self.assertIn("--base-sha \"$base_sha\"", self.workflow)
        self.assertIn("--workflow \"$WORKFLOW_NAME\"", self.workflow)
        self.assertIn("--workflow-ref \"$WORKFLOW_REF\"", self.workflow)
        self.assertIn('WORKFLOW_SHA: ${{ github.workflow_sha }}', self.workflow)
        self.assertIn('WORKFLOW_REF: ${{ github.workflow_ref }}', self.workflow)
        self.assertLess(
            self.workflow.index("publisher_lifecycle.py verify"),
            self.workflow.index("--method PATCH"),
        )

    def test_queue_is_bounded_and_fail_closed(self) -> None:
        self.assertIn("readonly LIST_LIMIT=100", self.workflow)
        self.assertIn("readonly MAX_CANDIDATES=25", self.workflow)
        self.assertIn("total >= LIST_LIMIT", self.workflow)
        self.assertIn("candidate_count > MAX_CANDIDATES", self.workflow)
        self.assertIn("Never mutate a partial queue", self.workflow)

    def test_only_github_mutation_is_close_exact_pr(self) -> None:
        self.assertEqual(self.workflow.count("--method PATCH"), 1)
        self.assertEqual(self.workflow.count("-f state=closed"), 1)
        self.assertIn('"repos/$REPO/pulls/$pr"', self.workflow)

        forbidden = (
            "gh pr merge",
            "/merges",
            "git push",
            "git rebase",
            "git update-ref",
            "git push --delete",
            "/git/refs",
            "/issues/",
            "/comments",
            "/labels",
            "/reviews",
            "--delete-branch",
            "gh pr comment",
            "gh pr edit",
            "gh pr review",
        )
        for value in forbidden:
            self.assertNotIn(value, self.workflow)

    def test_no_secrets_app_token_or_untrusted_decision_fields(self) -> None:
        lowered = self.workflow.lower()
        self.assertNotIn("secrets.", lowered)
        self.assertNotIn("create-github-app-token", lowered)
        self.assertNotIn("publisher_app", lowered)
        self.assertNotIn("headrefoid", lowered)
        self.assertIn("--json number,headRefName,createdAt", self.workflow)
        self.assertEqual(self.workflow.count('--jq "$PR_METADATA_JQ"'), 2)
        metadata_filter = self.workflow.split(
            "readonly PR_METADATA_JQ=", 1
        )[1].split("readonly FILES_JQ=", 1)[0]
        for untrusted_field in ("title", "body", "labels"):
            self.assertNotIn(untrusted_field, metadata_filter)


class ExistingTrustBoundaryTests(unittest.TestCase):
    def test_publisher_policy_remains_read_only(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher-policy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read\n  pull-requests: read\n", workflow)
        self.assertNotIn("pull-requests: write", workflow)

    def test_autonomous_publisher_permission_and_app_flow_remain_bounded(self) -> None:
        workflow = (ROOT / ".github/workflows/publisher.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "permissions:\n  contents: read\n  pull-requests: read\n  checks: read\n",
            workflow,
        )
        self.assertIn("actions/create-github-app-token@", workflow)
        self.assertIn("--match-head-commit", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
