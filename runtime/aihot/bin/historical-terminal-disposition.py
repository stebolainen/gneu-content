#!/usr/bin/env python3
"""Append or verify an exact historical AI-hot terminal disposition."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aihot_historical_disposition import (
    HISTORICAL_CASES,
    HistoricalDispositionError,
    append_disposition,
    verify_receipt,
)


BRIDGE = Path("/root/gneu-aihot-bridge")
STATE = BRIDGE / "state"
OUTBOX = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")


def parse_evidence(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, digest = value.partition("=")
        if not separator or not name or name in result:
            raise HistoricalDispositionError("INVALID_EVIDENCE_ARGUMENT")
        result[name] = digest
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Append or verify one exact historical terminal disposition",
        epilog=(
            "Evidence names are fixed by package: common="
            "failed_sha256,ready_sha256,handoff_sha256,candidate_sha256,"
            "report_sha256; r1 additionally requires local_retry_authorization_sha256,"
            "local_retry_consumed_sha256,ready_retry_authorization_sha256,"
            "ready_retry_consumed_sha256,ready_retry_failure_sha256; r2 additionally "
            "requires content_retry_authorization_sha256,content_retry_consumed_sha256."
        ),
    )
    commands = result.add_subparsers(dest="command", required=True)
    append = commands.add_parser("append")
    append.add_argument("--package-id", required=True, choices=tuple(HISTORICAL_CASES))
    append.add_argument("--failure-code", required=True)
    append.add_argument("--evidence-sha256", action="append", default=[], required=True)
    append.add_argument("--human-approval", required=True)
    append.add_argument("--reason", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--package-id", required=True, choices=tuple(HISTORICAL_CASES))
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "append":
        outcome = append_disposition(
            args.package_id,
            args.failure_code,
            parse_evidence(args.evidence_sha256),
            args.human_approval,
            args.reason,
            state_root=STATE,
            outbox_root=OUTBOX,
        )
        print(f"{outcome} {args.package_id}")
    else:
        verify_receipt(args.package_id, state_root=STATE, outbox_root=OUTBOX)
        print(f"VERIFIED_HISTORICAL_TERMINAL {args.package_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HistoricalDispositionError as exc:
        print(f"BLOCKED_HISTORICAL_TERMINAL_DISPOSITION {exc}", file=sys.stderr)
        raise SystemExit(1)
