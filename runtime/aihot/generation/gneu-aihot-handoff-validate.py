#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path


SOURCE_BIN = Path(__file__).resolve().parents[1] / "bin"
RUNTIME_BIN = Path("/root/gneu-aihot-bridge/bin")
sys.path.insert(0, str(SOURCE_BIN if (SOURCE_BIN / "aihot_local_retry.py").is_file() else RUNTIME_BIN))

from aihot_local_retry import RetryError, RetryPaths, verify_target_consumed
from aihot_content_retry import (
    ContentRetryError,
    production_paths as content_retry_paths,
    verify_target_consumed as verify_content_retry_consumed,
)
from aihot_package_identity import parse_package_id
from aihot_content_contract import (
    ContentContractError,
    load_contract,
    validate_article,
)


ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff")
INBOX = ROOT / "inbox"
OUTBOX = ROOT / "outbox"
RETRY_STATE = Path("/root/gneu-aihot-bridge/state")
SCHEDULER_CONFIG = Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json")
EXECUTIONS_DB = Path("/root/.hermes/profiles/gneu/cron/executions.db")
CRON_OUTPUT = Path("/root/.hermes/profiles/gneu/cron/output")
CONTENT_CONTRACT = load_contract()


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: gneu-aihot-handoff-validate.py PACKAGE_ID")
    package_id = sys.argv[1]
    try:
        edition, attempt, revision = parse_package_id(package_id)
    except ValueError as exc:
        fail(str(exc))
    if revision == 1:
        try:
            verify_target_consumed(
                RetryPaths(
                    RETRY_STATE,
                    OUTBOX,
                    SCHEDULER_CONFIG,
                    EXECUTIONS_DB,
                    CRON_OUTPUT,
                ),
                package_id,
            )
        except RetryError:
            fail("retry authorization missing or invalid")
    elif revision == 2:
        try:
            verify_content_retry_consumed(content_retry_paths(), package_id)
        except ContentRetryError:
            fail("content retry authorization missing or invalid")
    package = OUTBOX / package_id
    ready = package / "READY"
    if ready.exists():
        if ready.is_symlink() or not ready.is_file():
            fail("unsafe READY marker")
        print(f"ALREADY_READY {package_id}")
        return
    if package.is_symlink() or not package.is_dir():
        fail("package directory missing or unsafe")
    if {entry.name for entry in package.iterdir()} != {
        "handoff.json",
        "candidate.json",
        "report.md",
    }:
        fail("package file set mismatch")
    for name in ("handoff.json", "candidate.json", "report.md"):
        path = package / name
        if path.is_symlink() or not path.is_file():
            fail(f"unsafe or missing {name}")

    base_raw = (INBOX / "current.json").read_bytes()
    base_sha = hashlib.sha256(base_raw).hexdigest()
    try:
        base = json.loads(base_raw)
        candidate = json.loads((package / "candidate.json").read_text())
        handoff = json.loads((package / "handoff.json").read_text())
    except Exception:
        fail("invalid JSON")
    if not isinstance(base, dict) or not isinstance(candidate, dict) or not isinstance(handoff, dict):
        fail("base/candidate/handoff root must be object")
    expected_schema = "gneu-aihot-handoff-v2" if attempt else "gneu-aihot-handoff-v1"
    if handoff.get("schema") != expected_schema or handoff.get("producer") != "adam":
        fail("handoff identity mismatch")
    if handoff.get("edition") != edition:
        fail("handoff edition mismatch")
    if attempt is not None and handoff.get("attempt") != attempt:
        fail("handoff attempt mismatch")
    if attempt is None and "attempt" in handoff:
        fail("legacy handoff contains attempt")
    if revision in {1, 2} and handoff.get("revision") != revision:
        fail("handoff revision mismatch")
    if revision not in {1, 2} and "revision" in handoff:
        fail("unexpected handoff revision")
    mode = handoff.get("mode")
    if mode not in ("edition", "no-change"):
        fail("invalid mode")
    if handoff.get("base_sha256") != base_sha or handoff.get("base_generated") != base.get("generated"):
        fail("base binding mismatch")
    if candidate.get("generated") != base.get("generated"):
        fail("Adam must not change generated")
    be, ce = base.get("editions"), candidate.get("editions")
    ba, ca = base.get("articles"), candidate.get("articles")
    if not all(isinstance(value, list) for value in (be, ce, ba, ca)):
        fail("editions/articles must be lists")
    if ce[: len(be)] != be or ca[: len(ba)] != ba:
        fail("published material changed")
    if {k: v for k, v in base.items() if k not in ("editions", "articles")} != {
        k: v for k, v in candidate.items() if k not in ("editions", "articles")
    }:
        fail("top-level material changed")
    added_editions, added_articles = ce[len(be) :], ca[len(ba) :]
    if mode == "no-change":
        if added_editions or added_articles:
            fail("no-change contains new material")
    else:
        if (
            len(added_editions) != 1
            or not isinstance(added_editions[0], dict)
            or added_editions[0].get("id") != edition
        ):
            fail("edition delta invalid")
        if not 1 <= len(added_articles) <= 6:
            fail("article delta invalid")
        existing = {str(item.get("id")) for item in ba if isinstance(item, dict)}
        seen: set[str] = set()
        for article in added_articles:
            try:
                article_id = validate_article(
                    article,
                    edition,
                    existing,
                    seen,
                    CONTENT_CONTRACT,
                    date.fromisoformat(attempt) if revision == 2 else None,
                )
            except ContentContractError as exc:
                fail(str(exc))
            seen.add(article_id)
    if len((package / "report.md").read_text().strip()) < 200:
        fail("report.md is too short")

    temporary = ready.with_name("READY.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"PASS {package_id} mode={mode} base={base_sha}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, ready)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(
        f"PASS: {package_id} mode={mode} new_editions={len(added_editions)} "
        f"new_articles={len(added_articles)} base={base_sha[:12]}"
    )


if __name__ == "__main__":
    main()
