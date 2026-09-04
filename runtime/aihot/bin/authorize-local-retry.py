#!/usr/bin/env python3
"""Authorize and verify one append-only AI-hot local correction retry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aihot_local_retry import (
    REASON,
    RetryError,
    RetryPaths,
    authorize,
    verify_authorization,
    verify_consumed,
)


PATHS = RetryPaths(
    state=Path("/root/gneu-aihot-bridge/state"),
    outbox=Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox"),
    scheduler_config=Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json"),
    executions_db=Path("/root/.hermes/profiles/gneu/cron/executions.db"),
    cron_output=Path("/root/.hermes/profiles/gneu/cron/output"),
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Authorize one verified local AI-hot correction retry"
    )
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("authorize", "verify", "verify-consumed"):
        child = commands.add_parser(command)
        child.add_argument("--attempt", required=True)
        child.add_argument("--source-candidate-sha256", required=True)
        child.add_argument("--source-handoff-sha256", required=True)
        child.add_argument("--source-report-sha256", required=True)
        if command == "authorize":
            child.add_argument("--hermes-execution-id", required=True)
            child.add_argument("--reason", required=True, choices=(REASON,))
    return result


def expected_hashes(args: argparse.Namespace) -> dict[str, str]:
    return {
        "candidate": args.source_candidate_sha256,
        "handoff": args.source_handoff_sha256,
        "report": args.source_report_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    hashes = expected_hashes(args)
    if args.command == "authorize":
        value, receipt_sha = authorize(
            PATHS,
            args.attempt,
            hashes,
            args.hermes_execution_id,
            args.reason,
        )
        print(
            "AIHOT_LOCAL_RETRY_AUTHORIZED "
            f"package={value['target_package_id']} authorization_sha256={receipt_sha}"
        )
    elif args.command == "verify":
        value, receipt_sha = verify_authorization(PATHS, args.attempt, hashes)
        print(
            "AIHOT_LOCAL_RETRY_AUTHORIZATION_VERIFIED "
            f"package={value['target_package_id']} authorization_sha256={receipt_sha}"
        )
    else:
        value, receipt_sha = verify_consumed(PATHS, args.attempt, hashes)
        print(
            "AIHOT_LOCAL_RETRY_CONSUMED_VERIFIED "
            f"package={value['target_package_id']} consumed_sha256={receipt_sha}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RetryError as exc:
        print(f"BLOCKED_LOCAL_RETRY {exc}", file=sys.stderr)
        raise SystemExit(1)
