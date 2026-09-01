#!/usr/bin/env python3
"""Trusted classifier for one publisher gate run.

Turns a gate exit code plus its decision payload into a bounded, validated
(outcome, reason_code) pair that a workflow may publish as a check-run name.

Everything here is fail-closed. The classifier refuses to emit anything it
cannot fully verify: an unknown exit code, a payload that disagrees with the
exit code, or a reason code outside the trusted registry all make this script
exit non-zero and emit nothing. A missing publisher-outcome check is therefore
itself a signal, and never a silent pass.

No value from a PR title, body, label or any other untrusted field can reach
the output: the reason code must be a member of publisher_gate.REASON_CODES.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import publisher_gate

MAX_DECISION_BYTES = 64 * 1024

EXIT_OK = 0
EXIT_CLASSIFIER_FAILURE = 1

REQUIRED_FIELDS = ("outcome", "reason_code", "notify_human", "technical_error")


class ClassifierError(RuntimeError):
    pass


def load_decision(path: Path) -> dict:
    try:
        if not path.is_file():
            raise ClassifierError("decision payload missing")
        if path.stat().st_size > MAX_DECISION_BYTES:
            raise ClassifierError("decision payload too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ClassifierError(f"decision payload unavailable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClassifierError(f"decision payload is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ClassifierError("decision payload root must be an object")
    return data


def classify(exit_code: int, decision: dict) -> tuple[str, str]:
    for field in REQUIRED_FIELDS:
        if field not in decision:
            raise ClassifierError(f"decision payload is missing {field}")

    outcome = decision["outcome"]
    reason_code = decision["reason_code"]

    if outcome not in publisher_gate.REASON_CODES:
        raise ClassifierError(f"unknown outcome: {outcome!r}")

    if not publisher_gate.valid_reason_code(outcome, reason_code):
        raise ClassifierError(
            f"reason code outside the trusted registry: {outcome}/{reason_code!r}"
        )

    expected_exit = publisher_gate.OUTCOME_EXIT_CODES[outcome]
    if exit_code != expected_exit:
        raise ClassifierError(
            f"exit code {exit_code} does not match outcome {outcome} "
            f"(expected {expected_exit})"
        )

    notify = decision["notify_human"]
    technical = decision["technical_error"]
    if not isinstance(notify, bool) or not isinstance(technical, bool):
        raise ClassifierError("notify_human and technical_error must be boolean")

    expected_notify = (
        outcome in publisher_gate.NOTIFY_OUTCOMES
        or outcome == publisher_gate.OUTCOME_BLOCKED
    )
    if notify is not expected_notify:
        raise ClassifierError(f"notify_human does not match outcome {outcome}")

    expected_technical = outcome == publisher_gate.OUTCOME_BLOCKED
    if technical is not expected_technical:
        raise ClassifierError(f"technical_error does not match outcome {outcome}")

    return outcome, reason_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    try:
        if args.exit_code not in publisher_gate.OUTCOME_EXIT_CODES.values():
            raise ClassifierError(f"unknown gate exit code: {args.exit_code}")
        outcome, reason_code = classify(args.exit_code, load_decision(args.decision))
    except ClassifierError as exc:
        print(f"CLASSIFIER_FAILURE: {exc}", file=sys.stderr)
        return EXIT_CLASSIFIER_FAILURE

    print(f"{outcome} {reason_code}")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"outcome={outcome}\n")
            handle.write(f"reason_code={reason_code}\n")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
