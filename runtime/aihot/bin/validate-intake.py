#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

HANDOFF_ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff")
OUTBOX = HANDOFF_ROOT / "outbox"
LIVE_URL = "https://gneu.se/data/aihot.json"

WEEK_RE = re.compile(r"^20\d{2}-W(?:0[1-9]|[1-4]\d|5[0-3])$")


def fail(msg: str) -> None:
    raise SystemExit("BLOCKED: " + msg)


if len(sys.argv) != 2:
    fail("usage: validate-intake.py YYYY-Www")

edition = sys.argv[1]
if not WEEK_RE.fullmatch(edition):
    fail("invalid edition")

pkg = OUTBOX / edition

for name in ("handoff.json", "candidate.json", "report.md", "READY"):
    if not (pkg / name).is_file():
        fail(f"missing {name}")

try:
    handoff = json.loads((pkg / "handoff.json").read_text())
    candidate = json.loads((pkg / "candidate.json").read_text())
except Exception as exc:
    fail(f"invalid package JSON: {exc}")

# Independently fetch a fresh public baseline.
req = urllib.request.Request(
    LIVE_URL,
    headers={
        "User-Agent": "gneu-aihot-trusted-bridge/1.0 (+https://gneu.se)",
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    },
)

with urllib.request.urlopen(req, timeout=20) as r:
    raw = r.read(5 * 1024 * 1024 + 1)

if not raw or len(raw) > 5 * 1024 * 1024:
    fail("invalid live baseline")

try:
    base = json.loads(raw)
except Exception as exc:
    fail(f"live baseline invalid JSON: {exc}")

base_sha = hashlib.sha256(raw).hexdigest()

if handoff.get("schema") != "gneu-aihot-handoff-v1":
    fail("handoff schema")

if handoff.get("producer") != "adam":
    fail("producer")

if handoff.get("edition") != edition:
    fail("edition mismatch")

if handoff.get("base_sha256") != base_sha:
    fail("stale or unexpected base")

if handoff.get("base_generated") != base.get("generated"):
    fail("base generated mismatch")

if candidate.get("generated") != base.get("generated"):
    fail("candidate changed generated")

be = base.get("editions")
ce = candidate.get("editions")
ba = base.get("articles")
ca = candidate.get("articles")

if not all(isinstance(x, list) for x in (be, ce, ba, ca)):
    fail("editions/articles must be lists")

if ce[:len(be)] != be:
    fail("published editions mutated")

if ca[:len(ba)] != ba:
    fail("published articles mutated")

# Nothing else at top-level may change.
bo = {k: v for k, v in base.items() if k not in ("editions", "articles")}
co = {k: v for k, v in candidate.items() if k not in ("editions", "articles")}

if bo != co:
    fail("unexpected top-level mutation")

added_e = ce[len(be):]
added_a = ca[len(ba):]

mode = handoff.get("mode")

if mode == "no-change":
    if added_e or added_a:
        fail("no-change contains material")

elif mode == "edition":
    if len(added_e) != 1:
        fail("requires exactly one new edition")

    if not isinstance(added_e[0], dict) or added_e[0].get("id") != edition:
        fail("new edition mismatch")

    if not 1 <= len(added_a) <= 6:
        fail("requires 1-6 new articles")

    old_ids = {
        str(x.get("id"))
        for x in ba
        if isinstance(x, dict) and x.get("id") is not None
    }

    seen = set()

    for a in added_a:
        if not isinstance(a, dict):
            fail("article is not object")

        aid = str(a.get("id") or "")
        if not aid or aid in old_ids or aid in seen:
            fail(f"invalid/duplicate article id: {aid}")

        seen.add(aid)

        if a.get("edition") != edition:
            fail(f"{aid}: wrong edition")

        sources = a.get("sources")
        if not isinstance(sources, list) or len(sources) < 2:
            fail(f"{aid}: insufficient sources")

else:
    fail("invalid mode")

report = (pkg / "report.md").read_text().strip()
if len(report) < 200:
    fail("report too short")

print(
    f"PASS_INTAKE {edition} "
    f"mode={mode} articles={len(added_a)} base={base_sha[:12]}"
)
