#!/usr/bin/env python3
"""Hermes pre-agent gate for one AI-hot generation attempt per Stockholm day."""

from __future__ import annotations

import datetime as dt
import argparse
import fcntl
import json
import os
import re
import sys
from pathlib import Path
from zoneinfo import ZoneInfo


SOURCE_BIN = Path(__file__).resolve().parents[1] / "bin"
RUNTIME_BIN = Path("/root/gneu-aihot-bridge/bin")
sys.path.insert(0, str(SOURCE_BIN if (SOURCE_BIN / "aihot_claim_resume.py").is_file() else RUNTIME_BIN))

from aihot_claim_resume import ResumeError, ResumePaths, consume_authorization
from aihot_local_retry import (
    RetryError,
    RetryPaths,
    consume_authorization as consume_retry_authorization,
    source_resolved_by_retry,
)


ZONE = ZoneInfo("Europe/Stockholm")
STATE = Path("/root/gneu-aihot-bridge/state")
OUTBOX = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")
CLAIMS = STATE / "generation"
BASE_META = Path("/root/.hermes/profiles/gneu/aihot-handoff/inbox/current.meta.json")
SCHEDULER_CONFIG = Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json")
EXECUTIONS_DB = Path("/root/.hermes/profiles/gneu/cron/executions.db")
CRON_OUTPUT = Path("/root/.hermes/profiles/gneu/cron/output")
FRESHNESS_SECONDS = 26 * 60 * 60
DAILY_PACKAGE_RE = re.compile(
    r"^\d{4}-W\d{2}--\d{4}-\d{2}-\d{2}(?:--r1)?$"
)


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


def resume_paths() -> ResumePaths:
    return ResumePaths(STATE, OUTBOX, SCHEDULER_CONFIG, EXECUTIONS_DB, CRON_OUTPUT)


def retry_paths() -> RetryPaths:
    return RetryPaths(STATE, OUTBOX, SCHEDULER_CONFIG, EXECUTIONS_DB, CRON_OUTPUT)


def context_for(now: dt.datetime) -> tuple[dt.datetime, str, str, str, dict]:
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
    return local, edition, attempt, package_id, context


def inspect(now: dt.datetime | None = None) -> dict:
    """Describe today's gate inputs without locks, chmod, claims, or receipts."""
    now = now or dt.datetime.now(dt.timezone.utc)
    local, _, attempt, package_id, context = context_for(now)
    if local.time() < dt.time(7, 0):
        reason = "before_daily_aihot_window"
    elif os.path.lexists(STATE / "processed" / f"{package_id}.json"):
        reason = "daily_attempt_complete"
    elif os.path.lexists(STATE / "failed" / f"{package_id}.json"):
        reason = "daily_attempt_requires_operator"
    elif os.path.lexists(CLAIMS / "retry-consumed" / f"{attempt}-r1.json"):
        reason = "retry_already_consumed"
    elif os.path.lexists(CLAIMS / "retry-authorized" / f"{attempt}-r1.json"):
        reason = "operator_local_retry_authorized"
    elif os.path.lexists(OUTBOX / package_id):
        reason = "daily_attempt_requires_operator"
    elif os.path.lexists(CLAIMS / "resume-consumed" / f"{attempt}.json"):
        reason = "resume_already_consumed"
    elif os.path.lexists(CLAIMS / "resume-authorized" / f"{attempt}.json"):
        reason = "operator_resume_authorized"
    elif os.path.lexists(CLAIMS / f"{attempt}.json"):
        reason = "daily_attempt_already_claimed"
    else:
        reason = "daily_attempt_unclaimed"
    return {
        "status": "AIHOT_DAILY_GATE_INSPECT",
        "context": {**context, "reason": reason},
    }


def evaluate(now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    local, edition, attempt, package_id, context = context_for(now)

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
            if not DAILY_PACKAGE_RE.fullmatch(entry.name) or entry.name in {
                package_id,
                f"{package_id}--r1",
            }:
                continue
            terminal = (
                (STATE / "processed" / f"{entry.name}.json").is_file()
                or (STATE / "failed" / f"{entry.name}.json").is_file()
                or (entry / "READY").is_file()
            )
            entry_attempt = entry.name.split("--")[1]
            retry_consumed = CLAIMS / "retry-consumed" / f"{entry_attempt}-r1.json"
            if (
                not terminal
                and not entry.name.endswith("--r1")
                and os.path.lexists(retry_consumed)
            ):
                try:
                    terminal = source_resolved_by_retry(retry_paths(), entry.name)
                except RetryError:
                    return {
                        "wakeAgent": False,
                        "context": {**context, "reason": "unsafe_retry_state"},
                    }
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
    if os.path.lexists(processed) or os.path.lexists(failed):
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
        if os.path.lexists(package):
            try:
                retry_state, authorization = consume_retry_authorization(
                    retry_paths(), attempt, now
                )
            except RetryError:
                return {
                    "wakeAgent": False,
                    "context": {**context, "reason": "unsafe_retry_state"},
                }
            if retry_state == "consumed" and authorization is not None:
                return {
                    "wakeAgent": True,
                    "context": {
                        **context,
                        "edition": authorization["edition"],
                        "attempt": authorization["attempt"],
                        "package_id": authorization["target_package_id"],
                        "revision": authorization["revision"],
                        "reason": "operator_local_retry",
                    },
                }
            reason = (
                "retry_already_consumed"
                if retry_state == "already-consumed"
                else "daily_attempt_requires_operator"
            )
            return {"wakeAgent": False, "context": {**context, "reason": reason}}
        if os.path.lexists(claim):
            try:
                resume_state, original_claim = consume_authorization(
                    resume_paths(), attempt, now
                )
            except ResumeError:
                return {
                    "wakeAgent": False,
                    "context": {**context, "reason": "unsafe_resume_state"},
                }
            if resume_state == "consumed" and original_claim is not None:
                return {
                    "wakeAgent": True,
                    "context": {
                        **context,
                        "edition": original_claim["edition"],
                        "attempt": original_claim["attempt"],
                        "package_id": original_claim["package_id"],
                        "reason": "operator_resume_claim",
                    },
                }
            reason = (
                "resume_already_consumed"
                if resume_state == "already-consumed"
                else "daily_attempt_already_claimed"
            )
            return {"wakeAgent": False, "context": {**context, "reason": reason}}
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GNEU AI-hot daily scheduler gate")
    parser.add_argument("command", nargs="?", choices=("help", "inspect", "check"))
    args = parser.parse_args(argv)
    if args.command == "help":
        parser.print_help()
        return 0
    value = inspect() if args.command in {"inspect", "check"} else evaluate()
    print(json.dumps(value, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
