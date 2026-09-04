#!/usr/bin/env python3
"""Authorize and verify the single bounded AI-hot r2 correction."""

from __future__ import annotations

import argparse
import sys
from aihot_content_retry import (
    INCIDENT,
    REASON,
    ContentRetryError,
    authorize,
    production_paths,
    verify_authorization,
    verify_consumed,
)


PATHS = production_paths()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Authorize one incident-bound AI-hot r2 content correction"
    )
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("authorize", "verify", "verify-consumed"):
        child = commands.add_parser(command)
        child.add_argument("--attempt", required=True, choices=(INCIDENT["attempt"],))
        child.add_argument("--runtime-source-commit", required=True)
        if command == "authorize":
            child.add_argument("--reason", required=True, choices=(REASON,))
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "authorize":
        value, receipt_sha = authorize(
            PATHS,
            args.attempt,
            args.runtime_source_commit,
            args.reason,
        )
        print(
            "AIHOT_CONTENT_RETRY_AUTHORIZED "
            f"package={value['target_package_id']} authorization_sha256={receipt_sha}"
        )
    elif args.command == "verify":
        value, receipt_sha = verify_authorization(
            PATHS, args.attempt, args.runtime_source_commit
        )
        print(
            "AIHOT_CONTENT_RETRY_AUTHORIZATION_VERIFIED "
            f"package={value['target_package_id']} authorization_sha256={receipt_sha}"
        )
    else:
        value, receipt_sha = verify_consumed(
            PATHS, args.attempt, args.runtime_source_commit
        )
        print(
            "AIHOT_CONTENT_RETRY_CONSUMED_VERIFIED "
            f"package={value['target_package_id']} consumed_sha256={receipt_sha}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContentRetryError as exc:
        print(f"BLOCKED_CONTENT_RETRY {exc}", file=sys.stderr)
        raise SystemExit(1)
