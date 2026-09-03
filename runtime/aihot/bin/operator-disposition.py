#!/usr/bin/env python3
"""Explicit operator disposition for terminal AI-hot READY failures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).absolute()
if SCRIPT_PATH.is_symlink() or SCRIPT_PATH.parent.is_symlink():
    raise SystemExit("BLOCKED: operator runtime path must not be a symlink")
sys.path.insert(0, str(SCRIPT_PATH.parent))

from aihot_rejection import (
    RejectionError,
    exclusive_process_lock,
    reject,
    verify_receipt,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify or create a fail-closed AI-hot rejection receipt"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--edition", required=True)

    reject_parser = subparsers.add_parser("reject")
    reject_parser.add_argument("--edition", required=True)
    reject_parser.add_argument("--failing-article", required=True)
    reject_parser.add_argument("--run-id", required=True)
    reject_parser.add_argument("--failure-sha256", required=True)
    reject_parser.add_argument("--ready-sha256", required=True)
    reject_parser.add_argument("--handoff-sha256", required=True)
    reject_parser.add_argument("--candidate-sha256", required=True)
    reject_parser.add_argument("--report-sha256", required=True)
    reject_parser.add_argument("--transport-sha256", required=True)
    reject_parser.add_argument("--payload-sha256", required=True)
    reject_parser.add_argument("--base-main-sha", required=True)
    reject_parser.add_argument("--reason", required=True)
    reject_parser.add_argument("--remote-proof", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.operation == "verify":
        with exclusive_process_lock():
            verify_receipt(args.edition)
        print(f"VERIFIED_REJECTED {args.edition}")
        return 0

    result = reject(
        args.edition,
        failing_article=args.failing_article,
        run_id=args.run_id,
        failure_sha256=args.failure_sha256,
        ready_sha256=args.ready_sha256,
        handoff_sha256=args.handoff_sha256,
        candidate_sha256=args.candidate_sha256,
        report_sha256=args.report_sha256,
        transport_sha256=args.transport_sha256,
        payload_sha256=args.payload_sha256,
        base_main_sha=args.base_main_sha,
        reason=args.reason,
        remote_proof=args.remote_proof,
    )
    print(f"{result} {args.edition}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RejectionError as exc:
        raise SystemExit(f"BLOCKED: {exc}")
