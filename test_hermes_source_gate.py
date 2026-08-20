#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("gate", ROOT / "hermes_source_gate.py")
gate = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(gate)

N = 0
def ok(v, label):
    global N
    N += 1
    if not v:
        raise SystemExit("FAIL: " + label)

def snap(seed, status=200):
    return {
        "status": status,
        "sha256": (seed * 64)[:64],
        "etag": '"' + seed + '"',
        "last_modified": "Wed, 20 Aug 2026 10:00:00 GMT",
        "content_length": 123,
    }

state = gate._empty_state()

def first(source_id, url, baseline):
    return snap(source_id[0])

r = gate.run_check(state, fetcher=first, now=1000)
ok(r["wakeAgent"] is False, "bootstrap quiet")
ok(r["context"]["gate_version"] == "9.9.2", "version")

state["last_agent_success_at"] = 1000
def unchanged(source_id, url, baseline):
    return {"status": 304}

r = gate.run_check(state, fetcher=unchanged, now=1200)
ok(r["wakeAgent"] is False, "unchanged quiet")

def changed(source_id, url, baseline):
    if source_id == "cert-se":
        return snap("z")
    return {"status": 304}

r = gate.run_check(state, fetcher=changed, now=1400)
ok(r["wakeAgent"] is True, "change wakes")
ok("cert-se" in r["context"]["changed_sources"], "changed source context")
ok("--ack" in r["context"]["instruction"], "ack instruction")
ok(str(Path(gate.__file__).resolve()) in r["context"]["instruction"], "ack uses actual script path")

old = state["sources"]["cert-se"]["baseline"]["sha256"]
r = gate.run_check(state, fetcher=unchanged, now=1600)
ok(r["wakeAgent"] is True, "pending survives")
ok(state["sources"]["cert-se"]["baseline"]["sha256"] == old, "baseline waits for ack")

n = gate.promote_pending(state, 1700)
ok(n == 1, "ack promotes pending")
ok(state["last_agent_success_at"] == 1700, "success timestamp")
ok(state["sources"]["cert-se"]["pending"] is None, "pending cleared")

r = gate.run_check(state, fetcher=unchanged, now=1800)
ok(r["wakeAgent"] is False, "quiet after ack")

r = gate.run_check(state, fetcher=unchanged, now=1700 + gate.FORCE_SWEEP_SECONDS + 1)
ok(r["wakeAgent"] is True, "6h sweep")

print(f"gneu-content 9.9.2 source gate OK · {N} kontroller")
