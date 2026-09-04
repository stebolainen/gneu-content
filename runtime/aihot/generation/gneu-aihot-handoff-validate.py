#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import date
from pathlib import Path


ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff")
INBOX = ROOT / "inbox"
OUTBOX = ROOT / "outbox"
PACKAGE_RE = re.compile(
    r"^(?P<edition>20\d{2}-W(?:0[1-9]|[1-4]\d|5[0-3]))"
    r"(?:--(?P<attempt>20\d{2}-\d{2}-\d{2}))?$"
)


def fail(message: str) -> None:
    raise SystemExit("FAIL: " + message)


def parse_package_id(value: str) -> tuple[str, str | None]:
    match = PACKAGE_RE.fullmatch(value)
    if not match:
        fail("invalid package id")
    edition, attempt = match.group("edition"), match.group("attempt")
    if attempt is not None:
        parsed = date.fromisoformat(attempt).isocalendar()
        if (parsed.year, parsed.week) != (int(edition[:4]), int(edition[-2:])):
            fail("attempt date is outside edition")
    return edition, attempt


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: gneu-aihot-handoff-validate.py PACKAGE_ID")
    package_id = sys.argv[1]
    edition, attempt = parse_package_id(package_id)
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
            if not isinstance(article, dict):
                fail("new article must be object")
            article_id = str(article.get("id") or "")
            if not article_id or article_id in existing or article_id in seen:
                fail("duplicate or missing article id")
            seen.add(article_id)
            if article.get("edition") != edition:
                fail("article edition mismatch")
            try:
                article_date = date.fromisoformat(str(article.get("date") or ""))
            except ValueError:
                fail("article date invalid")
            article_iso = article_date.isocalendar()
            if (article_iso.year, article_iso.week) != (
                int(edition[:4]),
                int(edition[-2:]),
            ):
                fail("article date outside edition")
            sources = article.get("sources")
            if not isinstance(sources, list) or len(sources) < 2:
                fail("article source count invalid")
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
