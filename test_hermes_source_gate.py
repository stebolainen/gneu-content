#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hermes_source_gate", ROOT / "hermes_source_gate.py")
gate = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(gate)

N = 0
def ok(cond, label):
    global N
    N += 1
    if not cond:
        raise SystemExit("FAIL: " + label)

def snap(seed, status=200):
    return {
        "status": status,
        "sha256": (seed * 64)[:64],
        "etag": '"' + seed + '"',
        "last_modified": "Wed, 19 Aug 2026 08:00:00 GMT",
        "content_length": 100,
    }

with tempfile.TemporaryDirectory(prefix="gneu-gate-") as td:
    state = gate._empty_state()

    def bootstrap(source_id, url, baseline):
        return snap(source_id[0])

    r = gate.run_check(state, fetcher=bootstrap, now=1000)
    ok(r["wakeAgent"] is False, "first run bootstraps silently")
    ok(len(state["sources"]) == 3, "three priority sources")
    ok(all(v.get("baseline") for v in state["sources"].values()), "baselines stored")

    def unchanged(source_id, url, baseline):
        return {"status": 304}

    state["last_agent_success_at"] = 1000
    r = gate.run_check(state, fetcher=unchanged, now=1200)
    ok(r["wakeAgent"] is False, "unchanged is zero-token")

    def one_changed(source_id, url, baseline):
        if source_id == "cert-se":
            return snap("z")
        return {"status": 304}

    r = gate.run_check(state, fetcher=one_changed, now=1400)
    ok(r["wakeAgent"] is True, "source change wakes agent")
    ok("cert-se" in r["context"]["changed_sources"], "changed source passed as context")
    ok(state["sources"]["cert-se"]["pending"] is not None, "change remains pending")
    old_hash = state["sources"]["cert-se"]["baseline"]["sha256"]

    r = gate.run_check(state, fetcher=unchanged, now=1600)
    ok(r["wakeAgent"] is True, "unacked pending change keeps waking")
    ok(state["sources"]["cert-se"]["baseline"]["sha256"] == old_hash, "baseline not advanced before ack")

    promoted = gate.promote_pending(state, 1700)
    ok(promoted == 1, "ack promotes one pending source")
    ok(state["sources"]["cert-se"]["pending"] is None, "pending cleared after ack")

    r = gate.run_check(state, fetcher=unchanged, now=1800)
    ok(r["wakeAgent"] is False, "ack returns gate to quiet")

    r = gate.run_check(state, fetcher=unchanged, now=1700 + gate.FORCE_SWEEP_SECONDS + 1)
    ok(r["wakeAgent"] is True, "six-hour safety sweep wakes agent")
    ok("six_hour_safety_sweep" in r["context"]["reason"], "safety reason included")

    state = gate._empty_state()
    gate.run_check(state, fetcher=bootstrap, now=1000)
    state["last_agent_success_at"] = 1000

    def failing(source_id, url, baseline):
        if source_id == "msrc":
            raise RuntimeError("HTTP 503")
        return {"status": 304}

    r = gate.run_check(state, fetcher=failing, now=1100)
    ok(r["wakeAgent"] is False, "single source error stays quiet")
    r = gate.run_check(state, fetcher=failing, now=1200)
    ok(r["wakeAgent"] is False, "second source error stays quiet")
    r = gate.run_check(state, fetcher=failing, now=1300)
    ok(r["wakeAgent"] is True, "third consecutive source error wakes")
    ok(r["context"]["error_sources"][0]["source"] == "msrc", "error source passed to agent")

print(f"gneu-content 9.9.1 Hermes source gate OK · {N} kontroller")
