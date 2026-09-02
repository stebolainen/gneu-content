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

    def test_malformed_pr_number_and_shas_fail_closed(self) -> None:
        valid = {
            "exit_code": publisher_gate.EXIT_POLICY_SKIP,
            "decision": decision("POLICY_SKIP", "NATIVE_SOURCE_COVERED"),
            "repository": REPOSITORY,
            "pr_number": 48,
            "head_sha": HEAD_SHA,
            "head_ref": HEAD_REF,
            "base_sha": PUBLISHED_SHA,
            "published_sha": PUBLISHED_SHA,
            "control_sha": CONTROL_SHA,
            "workflow": lifecycle.TRUSTED_WORKFLOW,
            "workflow_ref": lifecycle.TRUSTED_WORKFLOW_REF,
        }
        cases = (
            ("pr_number", 0),
            ("pr_number", True),
            ("head_sha", "not-a-sha"),
            ("base_sha", "d" * 39),
            ("published_sha", "D" * 40),
            ("control_sha", ""),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                malformed = {**valid, field: value}
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.create_binding(**malformed)

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

    def test_different_pr_number_cannot_redirect_close(self) -> None:
        with self.assertRaises(lifecycle.LifecycleError):
            verify(self.bound, current_pr(pr=49))

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

            stdout_proc = subprocess.run(
                bind_proc.args[:-2],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
                env=common_env,
            )
            self.assertEqual(stdout_proc.returncode, 0, stdout_proc.stderr)
            self.assertEqual(json.loads(stdout_proc.stdout)["action"], "CLOSE")

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


class TokenlessTrustedStagingTests(unittest.TestCase):
    def test_private_checkout_stages_nonwritable_trusted_runtime(self) -> None:
        trusted_sources = (
            "publisher_policy_gate.py",
            "publisher_gate.py",
            "publisher_lifecycle.py",
            "publisher_outcome.py",
            "validate_content.py",
            ".github/workflows/publisher-policy.yml",
        )
        tokenless_prefix = [
            "/usr/bin/env", "-u", "GH_TOKEN", "-u", "GITHUB_TOKEN",
            "/usr/bin/sudo", "--non-interactive", "--user=nobody", "--",
            "/usr/bin/env", "-i", "HOME=/tmp", "LANG=C.UTF-8",
            "PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1",
        ]

        with tempfile.TemporaryDirectory(
            prefix="gneu-tokenless-staging-", dir="/tmp"
        ) as temp:
            root = Path(temp)
            root.chmod(0o755)
            private_checkout = root / "private-checkout"
            private_checkout.mkdir(mode=0o700)
            trusted_root = root / "trusted"
            trusted_root.mkdir(mode=0o755)
            self.assertEqual(trusted_root.stat().st_mode & 0o777, 0o755)
            self.assertNotEqual(trusted_root.stat().st_uid, 65534)
            data_root = root / "data"
            data_root.mkdir(mode=0o755)
            pr_head = root / "pr-head"
            pr_head.mkdir(mode=0o777)
            marker = pr_head / "executed"
            (pr_head / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            (pr_head / "sitecustomize.py").chmod(0o644)

            for source_name in trusted_sources:
                source = ROOT / source_name
                private_destination = private_checkout / Path(source_name).name
                private_destination.write_bytes(source.read_bytes())
                private_destination.chmod(0o644)
                trusted_destination = trusted_root / Path(source_name).name
                subprocess.run(
                    [
                        "/usr/bin/install", "-m", "0644",
                        str(source), str(trusted_destination),
                    ],
                    check=True,
                )
                self.assertFalse(trusted_destination.is_symlink())
                self.assertEqual(
                    trusted_destination.stat().st_mode & 0o777,
                    0o644,
                )
                self.assertNotEqual(trusted_destination.stat().st_uid, 65534)
                self.assertEqual(
                    trusted_destination.read_bytes(),
                    source.read_bytes(),
                )

            def run_tokenless(command):
                return subprocess.run(
                    tokenless_prefix + command,
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "GH_TOKEN": "TEST_GH_TOKEN_MUST_NOT_LEAK",
                        "GITHUB_TOKEN": "TEST_GITHUB_TOKEN_MUST_NOT_LEAK",
                        "PYTHONPATH": str(pr_head),
                    },
                )

            for source_name in (
                "publisher_policy_gate.py",
                "publisher_lifecycle.py",
            ):
                direct = run_tokenless([
                    "/usr/bin/python3",
                    str(private_checkout / source_name),
                    "--help",
                ])
                self.assertNotEqual(direct.returncode, 0)

            for staged_path in (trusted_root, *trusted_root.iterdir()):
                access = run_tokenless(
                    ["/usr/bin/test", "!", "-w", str(staged_path)]
                )
                self.assertEqual(access.returncode, 0, access.stderr)

            environment_probe = run_tokenless([
                "/usr/bin/python3",
                "-c",
                (
                    "import os,sys; "
                    "sys.exit(0 if 'GH_TOKEN' not in os.environ "
                    "and 'GITHUB_TOKEN' not in os.environ "
                    "and 'PYTHONPATH' not in os.environ else 1)"
                ),
            ])
            self.assertEqual(
                environment_probe.returncode, 0, environment_probe.stderr
            )

            policy_help = run_tokenless([
                "/usr/bin/python3",
                str(trusted_root / "publisher_policy_gate.py"),
                "--help",
            ])
            self.assertEqual(policy_help.returncode, 0, policy_help.stderr)
            self.assertFalse(marker.exists(), "PR-head sitecustomize was executed")

            decision_path = data_root / "decision.json"
            decision_path.write_text(
                json.dumps(decision("POLICY_SKIP", "NATIVE_SOURCE_COVERED")),
                encoding="utf-8",
            )
            decision_path.chmod(0o644)
            bound = run_tokenless([
                "/usr/bin/python3",
                str(trusted_root / "publisher_lifecycle.py"),
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
            ])
            self.assertEqual(bound.returncode, 0, bound.stderr)
            binding_path = data_root / "binding.json"
            binding_path.write_text(bound.stdout, encoding="utf-8")
            binding_path.chmod(0o644)
            current_path = data_root / "current.json"
            current_path.write_text(json.dumps(current_pr()), encoding="utf-8")
            current_path.chmod(0o644)

            verified = run_tokenless([
                "/usr/bin/python3",
                str(trusted_root / "publisher_lifecycle.py"),
                "verify",
                "--binding", str(binding_path),
                "--current-pr", str(current_path),
                "--current-published-sha", PUBLISHED_SHA,
                "--repository", REPOSITORY,
                "--control-sha", CONTROL_SHA,
            ])
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["action"], "CLOSE")
            self.assertFalse(marker.exists(), "PR-head code was executed")


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

    def test_trigger_modes_and_live_mutation_guard(self) -> None:
        start = self.workflow.index("          dry_run=false")
        end = self.workflow.index(
            '          if ! "${TOKENLESS_EXEC[@]}"',
            start,
        )
        rollout_block = "\n".join(
            line[10:] for line in self.workflow[start:end].splitlines()
        )

        def evaluate(event_name: str, dispatch_dry_run: str) -> subprocess.CompletedProcess:
            script = rollout_block + '\nprintf "%s" "$dry_run"\n'
            return subprocess.run(
                ["/usr/bin/bash"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin",
                    "EVENT_NAME": event_name,
                    "DISPATCH_DRY_RUN": dispatch_dry_run,
                },
            )

        scheduled = evaluate("schedule", "")
        self.assertEqual(scheduled.returncode, 0, scheduled.stderr)
        self.assertEqual(scheduled.stdout, "false")

        safe_dispatch = evaluate("workflow_dispatch", "true")
        self.assertEqual(safe_dispatch.returncode, 0, safe_dispatch.stderr)
        self.assertEqual(safe_dispatch.stdout, "true")

        live_dispatch = evaluate("workflow_dispatch", "false")
        self.assertEqual(live_dispatch.returncode, 0, live_dispatch.stderr)
        self.assertEqual(live_dispatch.stdout, "false")

        unsupported = evaluate("pull_request", "")
        self.assertNotEqual(unsupported.returncode, 0)

        close_case = self.workflow.rsplit('            case "$action" in', 1)[1]
        dry_run_guard = close_case.index('if [[ "$dry_run" == "true" ]]')
        live_else = close_case.index("                else", dry_run_guard)
        patch = close_case.index("--method PATCH")
        close_fi = close_case.index("                fi", patch)
        self.assertLess(dry_run_guard, live_else)
        self.assertLess(live_else, patch)
        self.assertLess(patch, close_fi)
        self.assertNotIn("--method PATCH", close_case[dry_run_guard:live_else])

    def test_trusted_main_only_and_no_pr_head_checkout(self) -> None:
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertEqual(self.workflow.count("uses: actions/checkout@"), 1)
        self.assertNotIn("git checkout", self.workflow)
        self.assertNotIn("github.event.pull_request.head", self.workflow)

    def test_fresh_gate_validator_and_exact_binding_are_mandatory(self) -> None:
        self.assertIn("publisher_policy_gate.py", self.workflow)
        self.assertIn('publisher_lifecycle.py" bind', self.workflow)
        self.assertIn('publisher_lifecycle.py" verify', self.workflow)
        self.assertIn(
            'install -m 0644 "$TRUSTED_ROOT/validate_content.py"',
            self.workflow,
        )
        self.assertIn('readonly TRUSTED_ROOT="$ROOT/trusted"', self.workflow)
        for staged_source in (
            "publisher_policy_gate.py:publisher_policy_gate.py",
            "publisher_gate.py:publisher_gate.py",
            "publisher_lifecycle.py:publisher_lifecycle.py",
            "publisher_outcome.py:publisher_outcome.py",
            "validate_content.py:validate_content.py",
            ".github/workflows/publisher-policy.yml:publisher-policy.yml",
        ):
            self.assertIn(f'"{staged_source}"', self.workflow)
        self.assertIn(
            'git ls-files --error-unmatch -- "$source_path"',
            self.workflow,
        )
        self.assertIn(
            'git rev-parse "$CONTROL_SHA:$source_path"',
            self.workflow,
        )
        self.assertIn('git hash-object -- "$source_path"', self.workflow)
        self.assertIn('git hash-object -- "$destination_path"', self.workflow)
        self.assertIn('install -m 0644 -- "$source_path"', self.workflow)
        self.assertIn(
            '! -f "$destination_path" || -L "$destination_path"',
            self.workflow,
        )
        self.assertIn("stat -c '%a' \"$destination_path\"", self.workflow)
        self.assertIn("stat -c '%u' \"$destination_path\"", self.workflow)
        self.assertIn("readonly -a TOKENLESS_EXEC=(", self.workflow)
        self.assertIn("/usr/bin/env -u GH_TOKEN -u GITHUB_TOKEN", self.workflow)
        self.assertIn(
            "/usr/bin/sudo --non-interactive --user=nobody --",
            self.workflow,
        )
        self.assertIn("/usr/bin/env -i HOME=/tmp", self.workflow)
        sensitive_invocations = (
            '/usr/bin/python3 "$validator_root/validate_content.py"',
            '/usr/bin/python3 "$TRUSTED_ROOT/publisher_policy_gate.py"',
            '/usr/bin/python3 "$TRUSTED_ROOT/publisher_lifecycle.py" bind',
            '/usr/bin/python3 "$TRUSTED_ROOT/publisher_lifecycle.py" verify',
        )
        for invocation in sensitive_invocations:
            self.assertEqual(self.workflow.count(invocation), 1)
        self.assertIn('install -d -m 0755 "$ROOT/bindings"', self.workflow)
        self.assertNotIn('install -d -m 1777', self.workflow)
        self.assertEqual(self.workflow.count('${TOKENLESS_EXEC[@]}'), 5)
        self.assertIn("--control-sha \"$CONTROL_SHA\"", self.workflow)
        self.assertIn("--base-sha \"$base_sha\"", self.workflow)
        self.assertIn("--workflow \"$WORKFLOW_NAME\"", self.workflow)
        self.assertIn("--workflow-ref \"$WORKFLOW_REF\"", self.workflow)
        self.assertIn('WORKFLOW_SHA: ${{ github.workflow_sha }}', self.workflow)
        self.assertIn('WORKFLOW_REF: ${{ github.workflow_ref }}', self.workflow)
        self.assertLess(
            self.workflow.index(
                '/usr/bin/python3 "$TRUSTED_ROOT/publisher_lifecycle.py" verify'
            ),
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
