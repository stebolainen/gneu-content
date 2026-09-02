#!/usr/bin/env python3
"""Trusted, mutation-free policy for closing terminal publisher PRs.

The GitHub workflow owns the one permitted mutation.  This module only binds a
fresh trusted Publisher Gate decision to exact repository state and verifies
that binding immediately before a caller may close the PR.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import publisher_gate
import publisher_outcome

EXPECTED_REPOSITORY = "stebolainen/gneu-content"
TRUSTED_WORKFLOW = "publisher-lifecycle"
TRUSTED_WORKFLOW_REF = (
    "stebolainen/gneu-content/"
    ".github/workflows/publisher-lifecycle.yml@refs/heads/main"
)
BINDING_SCHEMA = "gneu-publisher-lifecycle-binding-v1"
MAX_JSON_BYTES = 64 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}")

CLOSE_ALLOWLIST = frozenset({
    (publisher_gate.OUTCOME_POLICY_SKIP, "NATIVE_SOURCE_COVERED"),
    (publisher_gate.OUTCOME_NOOP_STALE, "NO_NET_DIFF"),
})

BINDING_FIELDS = frozenset({
    "schema",
    "repository",
    "workflow",
    "workflow_ref",
    "control_sha",
    "pr_number",
    "head_sha",
    "head_ref",
    "base_sha",
    "published_sha",
    "outcome",
    "reason_code",
    "action",
})


class LifecycleError(RuntimeError):
    """The lifecycle component cannot safely interpret its trusted inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LifecycleError(message)


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def load_json_bounded(path: Path, label: str) -> dict:
    try:
        require(path.is_file(), f"{label} missing")
        require(path.stat().st_size <= MAX_JSON_BYTES, f"{label} too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LifecycleError(f"{label} unavailable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"{label} is not valid JSON: {exc}") from exc
    require(isinstance(data, dict), f"{label} root must be object")
    return data


def lifecycle_action(outcome: object, reason_code: object) -> str:
    """Map only registered gate outcomes to a bounded lifecycle action."""
    require(isinstance(outcome, str), "outcome must be string")
    require(isinstance(reason_code, str), "reason_code must be string")
    require(
        publisher_gate.valid_reason_code(outcome, reason_code),
        "outcome/reason is outside the trusted Publisher Gate registry",
    )
    if (outcome, reason_code) in CLOSE_ALLOWLIST:
        return "CLOSE"
    if outcome == publisher_gate.OUTCOME_BLOCKED:
        return "BLOCKED"
    return "KEEP_OPEN"


def create_binding(
    *,
    exit_code: int,
    decision: dict,
    repository: str,
    pr_number: int,
    head_sha: str,
    head_ref: str,
    base_sha: str,
    published_sha: str,
    control_sha: str,
    workflow: str = TRUSTED_WORKFLOW,
    workflow_ref: str = TRUSTED_WORKFLOW_REF,
) -> dict:
    """Validate a fresh gate result and bind it to exact trusted run state."""
    require(repository == EXPECTED_REPOSITORY, "unexpected repository")
    require(workflow == TRUSTED_WORKFLOW, "unexpected trusted workflow")
    require(workflow_ref == TRUSTED_WORKFLOW_REF, "unexpected trusted workflow ref")
    require(isinstance(pr_number, int) and not isinstance(pr_number, bool) and pr_number > 0,
            "invalid PR number")
    require(valid_sha(head_sha), "invalid classified head SHA")
    require(valid_sha(base_sha), "invalid classified base SHA")
    require(valid_sha(published_sha), "invalid classified published SHA")
    require(valid_sha(control_sha), "invalid trusted control SHA")
    require(
        publisher_gate.HEAD_RE.fullmatch(head_ref) is not None,
        "classified head branch is outside adam namespace",
    )

    try:
        outcome, reason_code = publisher_outcome.classify(exit_code, decision)
    except publisher_outcome.ClassifierError as exc:
        raise LifecycleError(f"fresh gate classification invalid: {exc}") from exc

    require(decision.get("pr_number") == pr_number, "gate PR number binding mismatch")
    require(decision.get("head_sha") == head_sha, "gate head SHA binding mismatch")
    decision_ref = decision.get("head_ref")
    if decision_ref is not None:
        require(decision_ref == head_ref, "gate head ref binding mismatch")

    action = lifecycle_action(outcome, reason_code)
    return {
        "schema": BINDING_SCHEMA,
        "repository": repository,
        "workflow": workflow,
        "workflow_ref": workflow_ref,
        "control_sha": control_sha,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "head_ref": head_ref,
        "base_sha": base_sha,
        "published_sha": published_sha,
        "outcome": outcome,
        "reason_code": reason_code,
        "action": action,
    }


def validate_binding(binding: dict, *, repository: str, control_sha: str) -> None:
    require(set(binding) == BINDING_FIELDS, "binding fields do not match schema")
    require(binding.get("schema") == BINDING_SCHEMA, "binding schema mismatch")
    require(repository == EXPECTED_REPOSITORY, "unexpected runtime repository")
    require(binding.get("repository") == repository, "binding repository mismatch")
    require(binding.get("workflow") == TRUSTED_WORKFLOW, "binding workflow mismatch")
    require(
        binding.get("workflow_ref") == TRUSTED_WORKFLOW_REF,
        "binding workflow ref mismatch",
    )
    require(valid_sha(control_sha), "invalid runtime control SHA")
    require(binding.get("control_sha") == control_sha, "binding control SHA mismatch")
    require(
        isinstance(binding.get("pr_number"), int)
        and not isinstance(binding.get("pr_number"), bool)
        and binding["pr_number"] > 0,
        "binding PR number invalid",
    )
    require(valid_sha(binding.get("head_sha")), "binding head SHA invalid")
    require(valid_sha(binding.get("base_sha")), "binding base SHA invalid")
    require(valid_sha(binding.get("published_sha")), "binding published SHA invalid")
    require(
        isinstance(binding.get("head_ref"), str)
        and publisher_gate.HEAD_RE.fullmatch(binding["head_ref"]) is not None,
        "binding head ref invalid",
    )
    expected_action = lifecycle_action(binding.get("outcome"), binding.get("reason_code"))
    require(binding.get("action") == expected_action, "binding action mismatch")


def result(binding: dict, action: str, reason: str) -> dict:
    return {
        "pr_number": binding["pr_number"],
        "head_sha": binding["head_sha"],
        "outcome": binding["outcome"],
        "reason_code": binding["reason_code"],
        "action": action,
        "action_reason": reason,
    }


def verify_preclose(
    binding: dict,
    current_pr: dict,
    *,
    current_published_sha: str,
    repository: str,
    control_sha: str,
) -> dict:
    """Recheck every mutable binding immediately before the close request."""
    validate_binding(binding, repository=repository, control_sha=control_sha)
    require(valid_sha(current_published_sha), "current published SHA invalid")

    number = current_pr.get("number")
    state = current_pr.get("state")
    draft = current_pr.get("draft")
    require(isinstance(number, int) and not isinstance(number, bool), "current PR number invalid")
    require(isinstance(state, str), "current PR state invalid")
    require(isinstance(draft, bool), "current PR draft flag invalid")
    require(number == binding["pr_number"], "current PR number binding mismatch")

    if state == "closed":
        return result(binding, "BENIGN_SKIP", "ALREADY_CLOSED")
    require(state == "open", "current PR state is unknown")

    head = current_pr.get("head")
    base = current_pr.get("base")
    require(isinstance(head, dict) and isinstance(base, dict), "current PR refs malformed")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    require(isinstance(head_repo, dict) and isinstance(base_repo, dict),
            "current PR repository metadata malformed")
    require(isinstance(head_repo.get("full_name"), str),
            "current head repository name malformed")
    require(isinstance(base_repo.get("full_name"), str),
            "current base repository name malformed")
    require(isinstance(base.get("ref"), str), "current base ref malformed")
    require(valid_sha(base.get("sha")), "current base SHA malformed")
    require(valid_sha(head.get("sha")), "current head SHA malformed")

    if head_repo.get("full_name") != repository:
        return result(binding, "BLOCKED", "HEAD_REPOSITORY_MISMATCH")
    if base_repo.get("full_name") != repository:
        return result(binding, "BLOCKED", "BASE_REPOSITORY_MISMATCH")

    if draft:
        return result(binding, "KEEP_OPEN", "DRAFT_NOW")
    if base.get("ref") != "published":
        return result(binding, "DEFER", "BASE_CHANGED")

    head_ref = head.get("ref")
    require(isinstance(head_ref, str), "current head ref malformed")
    if publisher_gate.HEAD_RE.fullmatch(head_ref) is None:
        return result(binding, "BLOCKED", "HEAD_NAMESPACE_MISMATCH")
    if head_ref != binding["head_ref"]:
        return result(binding, "DEFER", "HEAD_REF_CHANGED")
    if head.get("sha") != binding["head_sha"]:
        return result(binding, "DEFER", "HEAD_CHANGED")
    if current_published_sha != binding["published_sha"]:
        return result(binding, "DEFER", "PUBLISHED_CHANGED")
    if base.get("sha") != binding["base_sha"]:
        return result(binding, "DEFER", "BASE_SHA_CHANGED")
    if binding["base_sha"] != binding["published_sha"]:
        return result(binding, "DEFER", "CLASSIFIED_BASE_NOT_CURRENT")

    if binding["action"] != "CLOSE":
        return result(binding, "KEEP_OPEN", "NOT_IN_CLOSE_ALLOWLIST")
    require(
        (binding["outcome"], binding["reason_code"]) in CLOSE_ALLOWLIST,
        "close action escaped explicit allowlist",
    )
    return result(binding, "CLOSE", "EXACT_BINDING_VERIFIED")


def write_json(path: Path, data: dict) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_outputs(path: Path | None, data: dict) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        for key in ("pr_number", "head_sha", "outcome", "reason_code", "action", "action_reason"):
            if key in data:
                handle.write(f"{key}={data[key]}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    bind = sub.add_parser("bind")
    bind.add_argument("--exit-code", type=int, required=True)
    bind.add_argument("--decision", type=Path, required=True)
    bind.add_argument("--repository", required=True)
    bind.add_argument("--pr-number", type=int, required=True)
    bind.add_argument("--head-sha", required=True)
    bind.add_argument("--head-ref", required=True)
    bind.add_argument("--base-sha", required=True)
    bind.add_argument("--published-sha", required=True)
    bind.add_argument("--control-sha", required=True)
    bind.add_argument("--workflow", required=True)
    bind.add_argument("--workflow-ref", required=True)
    bind.add_argument("--out", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--binding", type=Path, required=True)
    verify.add_argument("--current-pr", type=Path, required=True)
    verify.add_argument("--current-published-sha", required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--control-sha", required=True)
    verify.add_argument("--github-output", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "bind":
            decision = load_json_bounded(args.decision, "gate decision")
            data = create_binding(
                exit_code=args.exit_code,
                decision=decision,
                repository=args.repository,
                pr_number=args.pr_number,
                head_sha=args.head_sha,
                head_ref=args.head_ref,
                base_sha=args.base_sha,
                published_sha=args.published_sha,
                control_sha=args.control_sha,
                workflow=args.workflow,
                workflow_ref=args.workflow_ref,
            )
            write_json(args.out, data)
        else:
            binding = load_json_bounded(args.binding, "lifecycle binding")
            current_pr = load_json_bounded(args.current_pr, "current PR metadata")
            data = verify_preclose(
                binding,
                current_pr,
                current_published_sha=args.current_published_sha,
                repository=args.repository,
                control_sha=args.control_sha,
            )
            write_outputs(args.github_output, data)
        print(json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    except (LifecycleError, OSError) as exc:
        print(f"LIFECYCLE_BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
