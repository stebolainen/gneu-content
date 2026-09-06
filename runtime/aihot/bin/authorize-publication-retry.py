#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt

from aihot_publication_retry import (
    REASON, PublicationRetryError, authorize, production_paths,
    verify_authorization,
)

parser = argparse.ArgumentParser(description="Authorize one verified pre-write AI-hot publication retry")
parser.add_argument("operation", choices=("authorize", "verify"))
parser.add_argument("--package-id", required=True)
parser.add_argument("--runtime-source-commit", required=True)
parser.add_argument("--conflicting-pr", type=int, required=True)
parser.add_argument("--reason", choices=(REASON,))
args = parser.parse_args()
paths = production_paths()

try:
    if args.operation == "authorize":
        if args.reason != REASON:
            raise PublicationRetryError("authorization reason required")
        value, sha = authorize(
            paths, args.package_id, args.runtime_source_commit, args.reason,
            args.conflicting_pr,
            dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        )
        print("AIHOT_PUBLICATION_RETRY_AUTHORIZED")
    else:
        value, sha = verify_authorization(paths, args.package_id, args.runtime_source_commit)
        if value.get("conflicting_pr") != args.conflicting_pr:
            raise PublicationRetryError("conflicting PR mismatch")
        print("AIHOT_PUBLICATION_RETRY_AUTHORIZATION_VERIFIED")
    print("package_id:", value["package_id"])
    print("authorization_sha256:", sha)
except PublicationRetryError as exc:
    print("BLOCKED_PUBLICATION_RETRY:", str(exc))
    raise SystemExit(1)
