#!/usr/bin/env python3
"""Hermes pre-agent gate for one AI-hot generation attempt per Stockholm day."""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
from pathlib import Path
from zoneinfo import ZoneInfo


ZONE = ZoneInfo("Europe/Stockholm")
STATE = Path("/root/gneu-aihot-bridge/state")
OUTBOX = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")
CLAIMS = STATE / "generation"
BASE_META = Path("/root/.hermes/profiles/gneu/aihot-handoff/inbox/current.meta.json")
FRESHNESS_SECONDS = 26 * 60 * 60
DAILY_PACKAGE_RE = re.compile(r"^\d{4}-W\d{2}--\d{4}-\d{2}-\d{2}$")


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def evaluate(now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    local = now.astimezone(ZONE)
    iso = local.date().isocalendar()
    edition = f"{iso.year}-W{iso.week:02d}"
    attempt = local.date().isoformat()
    package_id = f"{edition}--{attempt}"
    context = {
        "timezone": "Europe/Stockholm",
        "scheduled_local_time": "07:00",
        "edition": edition,
        "attempt": attempt,
        "package_id": package_id,
    }
    try:
        meta = json.loads(BASE_META.read_text(encoding="utf-8"))
        generated = dt.datetime.fromisoformat(str(meta["generated"]).replace("Z", "+00:00"))
        if generated.tzinfo is None or generated > now:
            raise ValueError
        age_seconds = int((now - generated).total_seconds())
        context.update(
            {
                "freshness": "FRESH" if age_seconds < FRESHNESS_SECONDS else "STALE",
                "public_age_seconds": age_seconds,
                "freshness_threshold_seconds": FRESHNESS_SECONDS,
            }
        )
    except Exception:
        context["freshness"] = "UNKNOWN"

    if local.time() < dt.time(7, 0):
        return {
            "wakeAgent": False,
            "context": {**context, "reason": "before_daily_aihot_window"},
        }

    if OUTBOX.is_symlink():
        return {
            "wakeAgent": False,
            "context": {**context, "reason": "unsafe_outbox"},
        }
    if OUTBOX.is_dir():
        for entry in OUTBOX.iterdir():
            if not DAILY_PACKAGE_RE.fullmatch(entry.name) or entry.name == package_id:
                continue
            terminal = (
                (STATE / "processed" / f"{entry.name}.json").is_file()
                or (STATE / "failed" / f"{entry.name}.json").is_file()
            )
            if not terminal:
                return {
                    "wakeAgent": False,
                    "context": {
                        **context,
                        "reason": "earlier_daily_attempt_pending",
                        "pending_package_id": entry.name,
                    },
                }

    package = OUTBOX / package_id
    processed = STATE / "processed" / f"{package_id}.json"
    failed = STATE / "failed" / f"{package_id}.json"
    if processed.is_file() or (package / "READY").is_file():
        return {
            "wakeAgent": False,
            "context": {**context, "reason": "daily_attempt_complete"},
        }
    if os.path.lexists(processed) or os.path.lexists(failed) or os.path.lexists(package):
        return {
            "wakeAgent": False,
            "context": {**context, "reason": "daily_attempt_requires_operator"},
        }

    CLAIMS.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CLAIMS.is_symlink() or not CLAIMS.is_dir():
        raise RuntimeError("unsafe generation state directory")
    os.chmod(CLAIMS, 0o700)
    lock_path = CLAIMS / "daily-gate.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        claim = CLAIMS / f"{attempt}.json"
        if os.path.lexists(claim):
            return {
                "wakeAgent": False,
                "context": {**context, "reason": "daily_attempt_already_claimed"},
            }
        atomic_json(
            claim,
            {
                "schema": "gneu-aihot-generation-claim-v1",
                "edition": edition,
                "attempt": attempt,
                "package_id": package_id,
                "claimed_at": now.astimezone(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
            },
        )

    return {
        "wakeAgent": True,
        "context": {**context, "reason": "daily_aihot_window"},
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), separators=(",", ":")))
