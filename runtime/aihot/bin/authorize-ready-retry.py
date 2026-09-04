#!/usr/bin/env python3
"""Authorize and verify one append-only trusted READY processing retry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aihot_ready_retry import (
    REASON,
    ReadyRetryError,
    ReadyRetryPaths,
    authorize,
    verify_authorization,
    verify_consumed,
)


BRIDGE = Path("/root/gneu-aihot-bridge")
PATHS = ReadyRetryPaths(
    state=BRIDGE / "state",
    outbox=Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox"),
    provenance=BRIDGE / "PROVENANCE.json",
    bin_dir=BRIDGE / "bin",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Authorize one verified trusted READY processing retry"
    )
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("authorize", "verify", "verify-consumed"):
        child = commands.add_parser(command)
        child.add_argument("--failed-receipt-sha256", required=True)
        child.add_argument("--candidate-sha256", required=True)
        child.add_argument("--handoff-sha256", required=True)
        child.add_argument("--report-sha256", required=True)
        child.add_argument("--ready-sha256", required=True)
        child.add_argument("--runtime-source-commit", required=True)
        if command == "authorize":
            child.add_argument("--reason", required=True, choices=(REASON,))
    return result


def expected_hashes(args: argparse.Namespace) -> dict[str, str]:
    return {
        "candidate": args.candidate_sha256,
        "handoff": args.handoff_sha256,
        "report": args.report_sha256,
        "ready": args.ready_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    hashes = expected_hashes(args)
    if args.command == "authorize":
        value, receipt_sha = authorize(
            PATHS,
            args.failed_receipt_sha256,
            hashes,
            args.runtime_source_commit,
            args.reason,
        )
        print(
            "AIHOT_READY_RETRY_AUTHORIZED "
            f"package={value['package_id']} authorization_sha256={receipt_sha}"
        )
    elif args.command == "verify":
        value, receipt_sha = verify_authorization(
            PATHS,
            args.failed_receipt_sha256,
            hashes,
            args.runtime_source_commit,
        )
        print(
            "AIHOT_READY_RETRY_AUTHORIZATION_VERIFIED "
            f"package={value['package_id']} authorization_sha256={receipt_sha}"
        )
    else:
        value, receipt_sha = verify_consumed(
            PATHS,
            args.failed_receipt_sha256,
            hashes,
            args.runtime_source_commit,
        )
        print(
            "AIHOT_READY_RETRY_CONSUMED_VERIFIED "
            f"package={value['package_id']} consumed_sha256={receipt_sha}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReadyRetryError as exc:
        print(f"BLOCKED_READY_RETRY {exc}", file=sys.stderr)
        raise SystemExit(1)
