#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

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
ok(r["context"]["gate_version"] == "9.9.3", "version")

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

def reverted(source_id, url, baseline):
    if source_id == "cert-se":
        return snap("c")
    return {"status": 304}

r = gate.run_check(state, fetcher=reverted, now=1650)
ok(r["wakeAgent"] is True, "pending survives source reversion before ack")
ok(state["sources"]["cert-se"]["pending"] is not None, "reversion cannot clear unacked pending")

n = gate.promote_pending(state, 1700)
ok(n == 1, "ack promotes pending")
ok(state["last_agent_success_at"] == 1700, "success timestamp")
ok(state["sources"]["cert-se"]["pending"] is None, "pending cleared")

r = gate.run_check(state, fetcher=unchanged, now=1800)
ok(r["wakeAgent"] is False, "quiet after ack")

r = gate.run_check(state, fetcher=unchanged, now=1700 + gate.FORCE_SWEEP_SECONDS + 1)
ok(r["wakeAgent"] is True, "6h sweep")


def auth_fixture(root: Path, status: str = "ready") -> tuple[Path, Path, Path]:
    helper = root / "adam-auth.py"
    adapter = root / "adam-github.py"
    token = root / "github-token"
    helper.write_text(
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        f"token = pathlib.Path({str(token)!r})\n"
        "if sys.argv[1] == 'mint':\n"
        "    token.write_text('forbidden')\n"
        "    raise SystemExit(91)\n"
        f"print(json.dumps({{'status': {status!r}, 'configured': {status == 'ready'!r}}}))\n",
        encoding="utf-8",
    )
    adapter.write_text("# installed adapter sentinel\n", encoding="utf-8")
    os.chmod(helper, 0o700)
    os.chmod(adapter, 0o700)
    return helper, adapter, token


def add_auth(result, helper: Path, adapter: Path):
    with mock.patch.object(gate, "_auth_helper", return_value=helper), \
            mock.patch.object(gate, "_adam_adapter", return_value=adapter):
        return gate.attach_auth_status(result)


with tempfile.TemporaryDirectory(prefix="gneu-source-gate-") as td:
    root = Path(td)
    helper, adapter, token = auth_fixture(root)

    changed_state = gate._empty_state()
    gate.run_check(changed_state, fetcher=first, now=1000)
    changed_state["last_agent_success_at"] = 1000
    changed_result = gate.run_check(changed_state, fetcher=changed, now=1400)
    add_auth(changed_result, helper, adapter)
    ok(changed_result["context"]["auth"]["status"] == "ready", "change wake auth ready")
    ok(not token.exists(), "change wake creates no token file")

    sweep_state = changed_state
    gate.promote_pending(sweep_state, 1500)
    sweep_result = gate.run_check(
        sweep_state,
        fetcher=unchanged,
        now=1500 + gate.FORCE_SWEEP_SECONDS + 1,
    )
    add_auth(sweep_result, helper, adapter)
    ok(sweep_result["context"]["auth"]["status"] == "ready", "safety sweep auth ready")
    ok(not token.exists(), "safety sweep creates no token file")

    error_state = gate._empty_state()
    gate.run_check(error_state, fetcher=first, now=1000)
    error_state["last_agent_success_at"] = 1000
    def broken(source_id, url, baseline):
        raise RuntimeError("source unavailable")
    for when in (1100, 1200, 1300):
        error_result = gate.run_check(error_state, fetcher=broken, now=when)
    add_auth(error_result, helper, adapter)
    ok(error_result["wakeAgent"] is True, "source error wakes")
    ok(not token.exists(), "source error wake creates no token file")

    quiet_result = gate.run_check(sweep_state, fetcher=unchanged, now=1600)
    add_auth(quiet_result, helper, adapter)
    ok(quiet_result["wakeAgent"] is False, "normal no-wake remains quiet")
    ok("auth" not in quiet_result["context"], "no-wake does not check auth")
    ok(not token.exists(), "normal no-wake creates no token file")

with tempfile.TemporaryDirectory(prefix="gneu-source-gate-state-") as td:
    state_path = Path(td) / "state.json"
    persisted = gate._empty_state()
    gate.save_state(state_path, persisted)
    ok(gate.load_state(state_path)["schema"] == persisted["schema"], "secure state roundtrip")
    ok((state_path.stat().st_mode & 0o777) == 0o600, "state is owner-only")
    state_path.write_text("{malformed", encoding="utf-8")
    os.chmod(state_path, 0o600)
    try:
        gate.load_state(state_path)
    except gate.StateError:
        ok(True, "malformed state fails closed")
    else:
        ok(False, "malformed state must not silently bootstrap")
    state_path.unlink()
    victim = Path(td) / "victim.json"
    victim.write_text(json.dumps(persisted), encoding="utf-8")
    state_path.symlink_to(victim)
    try:
        gate.load_state(state_path)
    except gate.StateError:
        ok(True, "state symlink fails closed")
    else:
        ok(False, "state symlink must not be followed")

with tempfile.TemporaryDirectory(prefix="gneu-source-gate-auth-required-") as td:
    helper, adapter, token = auth_fixture(Path(td), "auth_required")
    result = {"wakeAgent": True, "context": {}}
    add_auth(result, helper, adapter)
    ok(result["context"]["auth"]["status"] == "auth_required", "missing credentials fail closed")
    ok(not token.exists(), "auth-required status creates no token")

source_tree = ast.parse((ROOT / "hermes_source_gate.py").read_text(encoding="utf-8"))
for node in ast.walk(source_tree):
    if not isinstance(node, ast.Call):
        continue
    called = node.func.attr if isinstance(node.func, ast.Attribute) else (
        node.func.id if isinstance(node.func, ast.Name) else ""
    )
    ok(called not in {"mint", "_mint", "_mint_token", "_store_token"}, "source gate has no token-mint call")
    for arg in node.args:
        if isinstance(arg, (ast.List, ast.Tuple)):
            values = [item.value for item in arg.elts if isinstance(item, ast.Constant)]
            ok("mint" not in values, "source gate subprocess never invokes mint")

print(f"gneu-content 9.9.3 source gate OK · {N} kontroller")
