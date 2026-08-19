#!/usr/bin/env python3
"""gneu-content 9.9.1 — deterministic Hermes source gate.

Designed to run as a Hermes cron pre-run script. It emits exactly one JSON line:
  {"wakeAgent": false}
or
  {"wakeAgent": true, "context": {...}}

No model/provider credentials are required. State is private to HERMES_HOME/scripts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

VERSION = "9.9.1"
FORCE_SWEEP_SECONDS = 6 * 60 * 60
ERROR_WAKE_THRESHOLD = 3
MAX_BODY_BYTES = 8 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 20

SOURCES = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cert-se": "https://www.cert.se/feed/atom.xml",
    "msrc": "https://api.msrc.microsoft.com/update-guide/rss",
}


def _now() -> int:
    return int(time.time())


def _state_path() -> Path:
    override = os.getenv("GNEU_WATCH_GATE_STATE", "").strip()
    if override:
        return Path(override).expanduser()
    home = Path(os.getenv("HERMES_HOME", "~/.hermes")).expanduser()
    return home / "scripts" / ".gneu-content-source-gate-state.json"


def _empty_state() -> dict[str, Any]:
    return {
        "schema": "gneu-content-hermes-gate-v1",
        "version": VERSION,
        "sources": {},
        "last_agent_success_at": None,
        "last_check_at": None,
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty_state()
    if not isinstance(obj, dict) or obj.get("schema") != "gneu-content-hermes-gate-v1":
        return _empty_state()
    obj.setdefault("sources", {})
    obj.setdefault("last_agent_success_at", None)
    obj.setdefault("last_check_at", None)
    obj["version"] = VERSION
    return obj


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    raw = json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    tmp.write_text(raw, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_source(source_id: str, url: str, baseline: dict[str, Any] | None) -> dict[str, Any]:
    headers = {
        "User-Agent": "gneu-content-watch/9.9.1 (+https://gneu.se)",
        "Accept": "application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.1",
        "Cache-Control": "no-cache",
    }
    if baseline:
        etag = str(baseline.get("etag") or "").strip()
        modified = str(baseline.get("last_modified") or "").strip()
        if etag:
            headers["If-None-Match"] = etag
        if modified:
            headers["If-Modified-Since"] = modified

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", 200))
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise RuntimeError(f"{source_id}: body exceeds {MAX_BODY_BYTES} bytes")
            return {
                "status": status,
                "sha256": _sha256(body),
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "content_length": len(body),
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return {"status": 304}
        raise RuntimeError(f"{source_id}: HTTP {exc.code}") from exc
    except Exception as exc:
        raise RuntimeError(f"{source_id}: {type(exc).__name__}: {exc}") from exc


def promote_pending(state: dict[str, Any], now: int) -> int:
    promoted = 0
    for source in state.get("sources", {}).values():
        if not isinstance(source, dict):
            continue
        pending = source.get("pending")
        if isinstance(pending, dict):
            source["baseline"] = pending
            source["pending"] = None
            promoted += 1
        source["consecutive_errors"] = 0
    state["last_agent_success_at"] = now
    return promoted


def run_check(state: dict[str, Any], fetcher=fetch_source, now: int | None = None) -> dict[str, Any]:
    now = _now() if now is None else int(now)
    changed: list[str] = []
    errors: list[dict[str, str]] = []
    bootstrapped: list[str] = []

    sources_state = state.setdefault("sources", {})

    for source_id, url in SOURCES.items():
        src = sources_state.setdefault(source_id, {
            "url": url,
            "baseline": None,
            "pending": None,
            "consecutive_errors": 0,
            "last_checked_at": None,
            "last_error": None,
        })
        src["url"] = url
        src["last_checked_at"] = now

        baseline = src.get("baseline")
        try:
            result = fetcher(source_id, url, baseline if isinstance(baseline, dict) else None)
            src["consecutive_errors"] = 0
            src["last_error"] = None

            if result.get("status") == 304:
                continue

            snapshot = {
                "sha256": result["sha256"],
                "etag": result.get("etag"),
                "last_modified": result.get("last_modified"),
                "content_length": int(result.get("content_length", 0)),
                "observed_at": now,
            }

            if not isinstance(baseline, dict):
                src["baseline"] = snapshot
                src["pending"] = None
                bootstrapped.append(source_id)
                continue

            if snapshot["sha256"] == baseline.get("sha256"):
                # Header churn alone must never wake the LLM.
                src["pending"] = None
                continue

            src["pending"] = snapshot
            changed.append(source_id)

        except Exception as exc:
            n = int(src.get("consecutive_errors") or 0) + 1
            src["consecutive_errors"] = n
            src["last_error"] = str(exc)[:300]
            if n >= ERROR_WAKE_THRESHOLD:
                errors.append({
                    "source": source_id,
                    "error": src["last_error"],
                    "consecutive": str(n),
                })

    state["last_check_at"] = now

    # Pending changes remain wake-worthy until Adam acknowledges a successful cycle.
    for source_id, src in sources_state.items():
        if isinstance(src, dict) and isinstance(src.get("pending"), dict) and source_id not in changed:
            changed.append(source_id)

    last_success = state.get("last_agent_success_at")
    safety_sweep = (
        last_success is None
        or now - int(last_success) >= FORCE_SWEEP_SECONDS
    )

    # First ever run is a baseline bootstrap, not an expensive agent wake.
    first_bootstrap = bool(bootstrapped) and last_success is None and not changed and not errors

    wake = bool(changed or errors or (safety_sweep and not first_bootstrap))

    if not wake:
        return {
            "wakeAgent": False,
            "context": {
                "gate_version": VERSION,
                "reason": "baseline_bootstrap" if first_bootstrap else "no_source_change",
                "checked_sources": list(SOURCES.keys()),
            },
        }

    reasons: list[str] = []
    if changed:
        reasons.append("source_change")
    if errors:
        reasons.append("source_error_threshold")
    if safety_sweep and not changed and not errors:
        reasons.append("six_hour_safety_sweep")

    return {
        "wakeAgent": True,
        "context": {
            "gate_version": VERSION,
            "reason": ",".join(reasons),
            "changed_sources": sorted(changed),
            "error_sources": errors,
            "instruction": (
                "Run the normal remote-first gneu-content-watch cycle. "
                "If the cycle finishes successfully, acknowledge the gate with "
                "python3 ~/.hermes/scripts/gneu-content-source-gate.py --ack"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ack", action="store_true", help="promote pending fingerprints after successful agent cycle")
    parser.add_argument("--state", type=Path, help="override state path (tests/diagnostics)")
    args = parser.parse_args()

    path = args.state.expanduser() if args.state else _state_path()
    state = load_state(path)
    now = _now()

    if args.ack:
        promoted = promote_pending(state, now)
        state["last_check_at"] = state.get("last_check_at") or now
        save_state(path, state)
        print(json.dumps({
            "ack": True,
            "promoted": promoted,
            "version": VERSION,
        }, separators=(",", ":")))
        return 0

    try:
        result = run_check(state, now=now)
        save_state(path, state)
        # Hermes inspects the final stdout line for wakeAgent.
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception as exc:
        # Fail open to the agent for an unexpected gate-internal error.
        print(json.dumps({
            "wakeAgent": True,
            "context": {
                "gate_version": VERSION,
                "reason": "gate_internal_error",
                "error": f"{type(exc).__name__}: {exc}"[:300],
            },
        }, ensure_ascii=False, separators=(",", ":")))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
