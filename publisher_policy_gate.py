#!/usr/bin/env python3
"""Required PR-head publication policy for changes targeting ``published``.

The caller supplies PR metadata and exact-SHA repository content as untrusted
data. Adam branches reuse the autonomous Publisher Gate policy, while the
strictly named Förvaltare path permits human content maintenance only. This
script never imports or executes anything from the PR head.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import publisher_gate

FORVALTARE_RE = re.compile(
    r"^forvaltare/[a-z0-9][a-z0-9._-]{0,79}$"
)
INSTALL_WORKFLOW_REF = "forvaltare/install-publisher-policy-check"
POLICY_WORKFLOW = ".github/workflows/publisher-policy.yml"
MAX_POLICY_WORKFLOW_BYTES = 128 * 1024


def validate_pr_envelope(
    args: argparse.Namespace,
    pr: dict,
) -> tuple[str, str, list]:
    files = publisher_gate.load_json(args.files)
    compare = publisher_gate.load_json(args.compare)

    publisher_gate.require(pr.get("state") == "open", "PR is not open")
    publisher_gate.require(pr.get("draft") is False, "PR is draft")
    publisher_gate.require(
        pr.get("base", {}).get("ref") == "published",
        "base must be published",
    )

    head = pr.get("head", {})
    base = pr.get("base", {})
    publisher_gate.require(
        head.get("repo", {}).get("full_name") == args.repository,
        "fork PRs are not eligible",
    )
    publisher_gate.require(
        base.get("repo", {}).get("full_name") == args.repository,
        "unexpected base repository",
    )

    head_ref = str(head.get("ref") or "")
    head_sha = str(head.get("sha") or "")
    current_base_sha = str(args.current_base_sha or "")
    publisher_gate.require(
        re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None,
        "invalid head SHA",
    )
    publisher_gate.require(
        re.fullmatch(r"[0-9a-f]{40}", current_base_sha) is not None,
        "invalid current base SHA",
    )
    publisher_gate.require(
        str(base.get("sha") or "") == current_base_sha,
        "PR base SHA is not current published",
    )

    publisher_gate.require(isinstance(files, list), "files payload must be list")
    publisher_gate.detect_noop_stale(args, files, compare)

    publisher_gate.require(
        compare.get("status") == "ahead",
        "head must be strictly ahead of current published",
    )
    publisher_gate.require(
        int(compare.get("behind_by", -1)) == 0,
        "head is behind/diverged from current published",
    )
    publisher_gate.require(
        int(compare.get("ahead_by", 0)) >= 1,
        "head contains no new commit",
    )

    return head_ref, head_sha, files


def validate_trusted_workflow_install(
    args: argparse.Namespace,
    pr: dict,
) -> dict:
    head_ref, head_sha, files = validate_pr_envelope(args, pr)
    publisher_gate.require(
        head_ref == INSTALL_WORKFLOW_REF,
        "unexpected trusted workflow install branch",
    )

    publisher_gate.require(
        len(files) == 1
        and isinstance(files[0], dict)
        and files[0].get("filename") == POLICY_WORKFLOW
        and files[0].get("status") in {"added", "modified"},
        "workflow install must change only the trusted policy workflow",
    )

    head_workflow = args.head_policy_workflow
    trusted_workflow = args.trusted_policy_workflow
    publisher_gate.require(
        head_workflow.is_file(),
        "head policy workflow missing",
    )
    publisher_gate.require(
        trusted_workflow.is_file(),
        "trusted main policy workflow missing",
    )
    publisher_gate.require(
        head_workflow.stat().st_size <= MAX_POLICY_WORKFLOW_BYTES,
        "head policy workflow too large",
    )
    publisher_gate.require(
        trusted_workflow.stat().st_size <= MAX_POLICY_WORKFLOW_BYTES,
        "trusted main policy workflow too large",
    )
    publisher_gate.require(
        head_workflow.read_bytes() == trusted_workflow.read_bytes(),
        "head policy workflow does not match trusted main",
    )

    return {
        "decision": "PASS_TRUSTED_WORKFLOW_INSTALL",
        "outcome": publisher_gate.OUTCOME_ACTIONABLE,
        "reason_code": "TRUSTED_WORKFLOW_INSTALL",
        "notify_human": False,
        "technical_error": False,
        "pr_number": int(pr["number"]),
        "head_sha": head_sha,
        "head_ref": head_ref,
        "workflow": POLICY_WORKFLOW,
    }


def validate_editorial_maintenance(
    args: argparse.Namespace,
    pr: dict,
) -> dict:
    head_ref, head_sha, files = validate_pr_envelope(args, pr)
    publisher_gate.require(
        FORVALTARE_RE.fullmatch(head_ref) is not None,
        "head branch must match forvaltare/description",
    )
    names = {
        str(row.get("filename"))
        for row in files
        if isinstance(row, dict)
    }
    publisher_gate.require(
        names == publisher_gate.ALLOWED_FILES,
        "changed files must be exactly events.json and manifest.json",
    )
    publisher_gate.require(len(files) == 2, "PR must change exactly two files")
    for row in files:
        publisher_gate.require(
            row.get("status") == "modified",
            f"{row.get('filename')}: must be modified, not added/deleted",
        )

    base_events, _ = publisher_gate.verify_manifest(
        args.base_events,
        args.base_manifest,
        "base",
    )
    head_events, head_manifest = publisher_gate.verify_manifest(
        args.head_events,
        args.head_manifest,
        "head",
    )

    base_generation = int(base_events["generation"])
    head_generation = int(head_events["generation"])
    publisher_gate.require(
        head_generation == base_generation + 1,
        "generation must increment by exactly one",
    )

    validator_output = publisher_gate.run_trusted_validator(
        args.trusted_validator,
        args.head_events,
        args.head_manifest,
    )

    return {
        "decision": "PASS_EDITORIAL_MAINTENANCE",
        "outcome": publisher_gate.OUTCOME_ACTIONABLE,
        "reason_code": "EDITORIAL_MAINTENANCE",
        "notify_human": False,
        "technical_error": False,
        "pr_number": int(pr["number"]),
        "head_sha": head_sha,
        "head_ref": head_ref,
        "base_generation": base_generation,
        "generation": head_generation,
        "event_count": len(head_events["events"]),
        "events_sha256": str(head_manifest["events_sha256"]),
        "validator": validator_output,
    }


def validate(args: argparse.Namespace) -> dict:
    pr = publisher_gate.load_json(args.pr)
    head_ref = str(pr.get("head", {}).get("ref") or "")

    if head_ref == INSTALL_WORKFLOW_REF:
        return validate_trusted_workflow_install(args, pr)

    if publisher_gate.HEAD_RE.fullmatch(head_ref):
        # ``validate`` is a separate required check at the ruleset boundary.
        # The final autonomous Publisher Gate still independently requires and
        # verifies that check before it can mint a Publisher token.
        return publisher_gate.validate(args, require_validate_check=False)

    if FORVALTARE_RE.fullmatch(head_ref):
        return validate_editorial_maintenance(args, pr)

    publisher_gate.fail("head branch is not an allowed publication path")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--current-base-sha", required=True)
    parser.add_argument("--pr", type=Path, required=True)
    parser.add_argument("--files", type=Path, required=True)
    parser.add_argument("--compare", type=Path, required=True)
    parser.add_argument("--base-events", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--head-events", type=Path, required=True)
    parser.add_argument("--head-manifest", type=Path, required=True)
    parser.add_argument("--aihot-coverage", type=Path, required=True)
    parser.add_argument("--trusted-validator", type=Path, required=True)
    parser.add_argument("--head-policy-workflow", type=Path, required=True)
    parser.add_argument("--trusted-policy-workflow", type=Path, required=True)
    args = parser.parse_args()

    try:
        result = validate(args)
    except publisher_gate.GateOutcome as exc:
        # This is the required merge gate, not the autonomous publisher. Only
        # an empty net diff may report a passing check here: it cannot publish
        # anything. POLICY_SKIP and NEEDS_HUMAN still have to keep the check
        # red, because GitHub counts a neutral or skipped required check as
        # satisfied and the PR would become manually mergeable.
        print(json.dumps(
            publisher_gate.outcome_payload(exc, args.pr),
            ensure_ascii=False,
            sort_keys=True,
        ))
        return publisher_gate.NON_ACTIONABLE_EXIT_CODES[exc.outcome]
    except publisher_gate.GateError as exc:
        print(json.dumps(
            publisher_gate.blocked_payload(exc, args.pr),
            ensure_ascii=False,
            sort_keys=True,
        ))
        return publisher_gate.EXIT_BLOCKED

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return publisher_gate.EXIT_ACTIONABLE


if __name__ == "__main__":
    raise SystemExit(main())
