#!/usr/bin/env python3
"""Read-only public AI-hot freshness probe with a 26-hour SLO."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import urllib.request


LIVE_URL = "https://gneu.se/data/aihot.json"
MAX_BYTES = 5 * 1024 * 1024
MAX_AGE = dt.timedelta(hours=26)


def probe(now: dt.datetime | None = None, opener=urllib.request.urlopen) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    request = urllib.request.Request(
        LIVE_URL,
        headers={
            "User-Agent": "gneu-aihot-freshness/1.0 (+https://gneu.se)",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )
    with opener(request, timeout=20) as response:
        if int(getattr(response, "status", 200)) != 200:
            raise ValueError("unexpected public HTTP status")
        raw = response.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("public AI-hot payload size invalid")
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise ValueError("public AI-hot JSON invalid") from exc
    if not isinstance(data, dict) or set(data) != {"generated", "editions", "articles"}:
        raise ValueError("public AI-hot schema invalid")
    generated = data.get("generated")
    if not isinstance(generated, str):
        raise ValueError("public generated timestamp missing")
    try:
        generated_at = dt.datetime.fromisoformat(generated.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("public generated timestamp invalid") from exc
    if generated_at.tzinfo is None or generated_at > now:
        raise ValueError("public generated timestamp is unsafe")
    age = now - generated_at
    latest = data["editions"][-1] if data["editions"] else None
    latest_id = latest.get("id") if isinstance(latest, dict) else None
    return {
        "schema": "gneu-aihot-freshness-v1",
        "state": "FRESH" if age < MAX_AGE else "STALE",
        "generated": generated_at.astimezone(dt.timezone.utc).isoformat(),
        "age_seconds": int(age.total_seconds()),
        "threshold_seconds": int(MAX_AGE.total_seconds()),
        "latest_edition": latest_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check public AI-hot freshness")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = probe()
    except Exception as exc:
        print(f"AIHOT_FRESHNESS UNKNOWN reason={type(exc).__name__}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"AIHOT_FRESHNESS {result['state']} age_seconds={result['age_seconds']} "
            f"threshold_seconds={result['threshold_seconds']} "
            f"latest_edition={result['latest_edition']}"
        )
    return 0 if result["state"] == "FRESH" else 2


if __name__ == "__main__":
    raise SystemExit(main())
