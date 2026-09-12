#!/usr/bin/env python3
"""Hermes pre-agent gate for one AI-hot generation attempt per Stockholm day."""

from __future__ import annotations

import datetime as dt
import argparse
import fcntl
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from zoneinfo import ZoneInfo


SOURCE_BIN = Path(__file__).resolve().parents[1] / "bin"
RUNTIME_BIN = Path("/root/gneu-aihot-bridge/bin")
sys.path.insert(0, str(SOURCE_BIN if (SOURCE_BIN / "aihot_claim_resume.py").is_file() else RUNTIME_BIN))

from aihot_claim_resume import (
    ResumeError,
    ResumePaths,
    atomic_create as create_immutable,
    consume_authorization,
    load_canonical,
    load_claim,
    load_job_id,
    parse_timestamp,
    sha256_bytes,
)
from aihot_local_retry import (
    RetryError,
    RetryPaths,
    consume_authorization as consume_retry_authorization,
    source_resolved_by_retry,
)
from aihot_content_retry import (
    ContentRetryError,
    ContentRetryPaths,
    consume_authorization as consume_content_retry_authorization,
    production_paths as production_content_retry_paths,
)


ZONE = ZoneInfo("Europe/Stockholm")
STATE = Path("/root/gneu-aihot-bridge/state")
OUTBOX = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")
CLAIMS = STATE / "generation"
BASE_META = Path("/root/.hermes/profiles/gneu/aihot-handoff/inbox/current.meta.json")
SCHEDULER_CONFIG = Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json")
EXECUTIONS_DB = Path("/root/.hermes/profiles/gneu/cron/executions.db")
CRON_OUTPUT = Path("/root/.hermes/profiles/gneu/cron/output")
REQUEST_DUMPS = Path("/root/.hermes/profiles/gneu/sessions")
TRUSTED_UID = 0
FRESHNESS_SECONDS = 26 * 60 * 60
DAILY_PACKAGE_RE = re.compile(
    r"^\d{4}-W\d{2}--\d{4}-\d{2}-\d{2}(?:--r[12])?$"
)
ACTIVE_EXECUTION_STATUSES = {"claimed", "running"}
TERMINAL_EXECUTION_STATUSES = {"completed", "failed", "unknown"}
TRANSIENT_PROVIDER_ERRORS = {
    "usage_limit_reached",
    "HTTP 429: The usage limit has been reached",
    "HTTP 429: usage_limit_reached",
    "RuntimeError: HTTP 429: The usage limit has been reached",
    "RuntimeError: HTTP 429: usage_limit_reached",
}


class FallbackStateError(RuntimeError):
    """A non-secret, fail-closed pre-research fallback state error."""


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


def fallback_path(attempt: str) -> Path:
    return CLAIMS / "pre-research-fallback" / f"{attempt}.json"


def package_state_exists(package_id: str) -> bool:
    paths = (
        OUTBOX / package_id,
        OUTBOX.parent / f"citations-{package_id}.json",
        STATE / "processed" / f"{package_id}.json",
        STATE / "failed" / f"{package_id}.json",
        STATE / "rejected" / f"{package_id}.json",
        STATE / "intake" / f"{package_id}.transport.json",
    )
    return any(os.path.lexists(path) for path in paths)


def load_executions(claim: dict) -> list[dict]:
    if EXECUTIONS_DB.is_symlink() or not EXECUTIONS_DB.is_file():
        raise FallbackStateError("invalid execution ledger")
    paths = resume_paths()
    try:
        job_id = load_job_id(paths)
    except ResumeError as exc:
        raise FallbackStateError("invalid scheduler config") from exc
    try:
        connection = sqlite3.connect(f"file:{EXECUTIONS_DB}?mode=ro", uri=True)
        try:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(executions)")}
            required = {
                "id", "job_id", "source", "status", "claimed_at",
                "started_at", "finished_at", "error",
            }
            if not required.issubset(columns):
                raise FallbackStateError("invalid execution ledger")
            rows = connection.execute(
                """SELECT id, source, status, claimed_at, started_at, finished_at, error
                   FROM executions WHERE job_id = ? ORDER BY claimed_at, id""",
                (job_id,),
            ).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        raise FallbackStateError("invalid execution ledger") from exc

    result = []
    for row in rows:
        execution_id, source, status, claimed_at, started_at, finished_at, error = row
        try:
            execution_time = parse_timestamp(claimed_at, "INVALID_EXECUTION_LEDGER")
        except ResumeError as exc:
            raise FallbackStateError("invalid execution timestamp") from exc
        if execution_time.astimezone(ZONE).date().isoformat() != claim["attempt"]:
            continue
        if (
            not isinstance(execution_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", execution_id)
            or source != "builtin"
            or status not in ACTIVE_EXECUTION_STATUSES | TERMINAL_EXECUTION_STATUSES
        ):
            raise FallbackStateError("invalid execution row")
        if started_at is not None:
            try:
                start_time = parse_timestamp(started_at, "INVALID_EXECUTION_LEDGER")
            except ResumeError as exc:
                raise FallbackStateError("invalid execution timestamp") from exc
        else:
            start_time = None
        if status in TERMINAL_EXECUTION_STATUSES:
            if start_time is None or finished_at is None:
                raise FallbackStateError("terminal execution lacks finish time")
            try:
                finish_time = parse_timestamp(finished_at, "INVALID_EXECUTION_LEDGER")
            except ResumeError as exc:
                raise FallbackStateError("invalid execution timestamp") from exc
            if not execution_time <= start_time <= finish_time:
                raise FallbackStateError("invalid execution timestamp order")
        else:
            if finished_at is not None:
                raise FallbackStateError("active execution has finish time")
            finish_time = None
        if error is not None and (not isinstance(error, str) or len(error) > 512):
            raise FallbackStateError("invalid execution error")
        result.append(
            {
                "id": execution_id,
                "status": status,
                "claimed_at": execution_time,
                "started_at": start_time,
                "finished_at": finish_time,
                "error": error,
            }
        )
    return result


def load_generation_claim(
    attempt: str, edition: str, package_id: str
) -> tuple[dict, bytes]:
    try:
        claim, data = load_claim(resume_paths(), attempt)
    except ResumeError as exc:
        raise FallbackStateError("invalid claim") from exc
    if claim["edition"] != edition or claim["attempt"] != attempt or claim["package_id"] != package_id:
        raise FallbackStateError("claim identity mismatch")
    try:
        claimed_at = parse_timestamp(claim["claimed_at"], "INVALID_CLAIM")
    except ResumeError as exc:
        raise FallbackStateError("invalid claim timestamp") from exc
    if claimed_at.astimezone(ZONE).date().isoformat() != attempt:
        raise FallbackStateError("claim day mismatch")
    return claim, data


def pre_research_provider_failure(primary: dict) -> str:
    if REQUEST_DUMPS.is_symlink() or not REQUEST_DUMPS.is_dir():
        raise FallbackStateError("invalid provider evidence directory")
    directory_stat = REQUEST_DUMPS.stat()
    if directory_stat.st_uid != TRUSTED_UID or (directory_stat.st_mode & 0o077):
        raise FallbackStateError("invalid provider evidence directory")
    try:
        job_id = load_job_id(resume_paths())
    except ResumeError as exc:
        raise FallbackStateError("invalid scheduler config") from exc
    prefix = f"request_dump_cron_{job_id}_"
    candidates = []
    for path in REQUEST_DUMPS.glob(f"{prefix}*.json"):
        if path.is_symlink() or not path.is_file():
            continue
        stat_result = path.stat()
        modified = dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc)
        if not (
            primary["started_at"] - dt.timedelta(seconds=2)
            <= modified
            <= primary["finished_at"] + dt.timedelta(seconds=2)
        ):
            continue
        if (
            stat_result.st_uid != TRUSTED_UID
            or (stat_result.st_mode & 0o777) != 0o600
            or not 0 < stat_result.st_size <= 2 * 1024 * 1024
        ):
            raise FallbackStateError("invalid provider evidence file")
        raw = path.read_bytes()
        try:
            value = json.loads(raw)
            request = value["request"]
            error = value["error"]
            body = request["body"]
            inputs = body["input"]
            timestamp = dt.datetime.fromisoformat(value["timestamp"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise FallbackStateError("invalid provider evidence") from exc
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
        else:
            timestamp = timestamp.astimezone(dt.timezone.utc)
        initial_input = (
            isinstance(inputs, list)
            and len(inputs) == 1
            and isinstance(inputs[0], dict)
            and inputs[0].get("role") == "user"
            and isinstance(inputs[0].get("content"), str)
        )
        session_id = value.get("session_id") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or not isinstance(session_id, str)
            or not re.fullmatch(rf"cron_{job_id}_\d{{8}}_\d{{6}}", session_id)
            or value.get("reason") != "max_retries_exhausted"
            or not isinstance(request, dict)
            or not isinstance(body, dict)
            or not isinstance(error, dict)
            or error.get("type") != "usage_limit_reached"
            or error.get("status_code") != 429
            or not initial_input
            or not primary["started_at"] <= timestamp <= primary["finished_at"]
        ):
            continue
        candidates.append(sha256_bytes(raw))
    if len(candidates) != 1:
        raise FallbackStateError("pre-research provider failure not proven")
    return candidates[0]


def load_fallback(attempt: str, claim: dict, claim_data: bytes) -> dict | None:
    path = fallback_path(attempt)
    if not os.path.lexists(path):
        return None
    try:
        value, _ = load_canonical(
            path,
            {
                "schema", "status", "edition", "attempt", "package_id",
                "claim_sha256", "primary_execution_id", "fallback_execution_id",
                "provider_error", "provider_failure_sha256", "consumed_at",
            },
            "gneu-aihot-pre-research-fallback-v1",
            "INVALID_FALLBACK_RECEIPT",
        )
    except ResumeError as exc:
        raise FallbackStateError("invalid fallback receipt") from exc
    if (
        value["status"] != "FALLBACK_RETRY"
        or value["edition"] != claim["edition"]
        or value["attempt"] != attempt
        or value["package_id"] != claim["package_id"]
        or value["claim_sha256"] != sha256_bytes(claim_data)
        or value["provider_error"] != "usage_limit_reached"
        or not re.fullmatch(r"[0-9a-f]{64}", value["provider_failure_sha256"])
        or not re.fullmatch(r"[0-9a-f]{32}", value["primary_execution_id"])
        or not re.fullmatch(r"[0-9a-f]{32}", value["fallback_execution_id"])
    ):
        raise FallbackStateError("invalid fallback receipt")
    try:
        parse_timestamp(value["consumed_at"], "INVALID_FALLBACK_RECEIPT")
    except ResumeError as exc:
        raise FallbackStateError("invalid fallback receipt timestamp") from exc
    return value


def classify_claimed_attempt(
    attempt: str,
    edition: str,
    package_id: str,
    now: dt.datetime,
) -> tuple[str, dict | None, dict | None]:
    if now.astimezone(ZONE).date().isoformat() != attempt:
        return "daily_attempt_already_claimed", None, None
    if package_state_exists(package_id):
        return "daily_attempt_requires_operator", None, None
    claim, claim_data = load_generation_claim(attempt, edition, package_id)
    executions = load_executions(claim)
    receipt = load_fallback(attempt, claim, claim_data)
    if receipt is not None:
        primary_matches = [
            row for row in executions if row["id"] == receipt["primary_execution_id"]
        ]
        matches = [row for row in executions if row["id"] == receipt["fallback_execution_id"]]
        if (
            len(primary_matches) != 1
            or primary_matches[0]["status"] != "failed"
            or primary_matches[0]["error"] not in TRANSIENT_PROVIDER_ERRORS
            or len(matches) != 1
            or matches[0]["claimed_at"] < primary_matches[0]["finished_at"]
            or pre_research_provider_failure(primary_matches[0])
            != receipt["provider_failure_sha256"]
        ):
            raise FallbackStateError("fallback execution missing")
        fallback = matches[0]
        if fallback["status"] in ACTIVE_EXECUTION_STATUSES:
            return "FALLBACK_RETRY", None, fallback
        if fallback["status"] == "failed":
            reason = (
                "FALLBACK_TRANSIENT_FAILURE_TERMINAL"
                if fallback["error"] in TRANSIENT_PROVIDER_ERRORS
                else "FALLBACK_FAILURE_TERMINAL"
            )
            return reason, None, fallback
        if fallback["status"] == "unknown":
            return "FALLBACK_FAILURE_TERMINAL", None, fallback
        return "FALLBACK_NO_PACKAGE_TERMINAL", None, fallback

    claim_time = parse_timestamp(claim["claimed_at"], "INVALID_CLAIM")
    claim_ceiling = claim_time + dt.timedelta(seconds=1)
    terminal = [
        row for row in executions
        if row["status"] in TERMINAL_EXECUTION_STATUSES
        and row["claimed_at"] <= claim_ceiling
        and row["started_at"] <= claim_ceiling
        and row["finished_at"] >= claim_time
    ]
    if not terminal:
        return "daily_attempt_already_claimed", None, None
    if len(terminal) != 1:
        raise FallbackStateError("ambiguous primary execution")
    primary = terminal[0]
    if primary["status"] == "completed":
        return "PRIMARY_NO_PACKAGE_TERMINAL", primary, None
    if primary["error"] not in TRANSIENT_PROVIDER_ERRORS:
        return "PRIMARY_FAILURE_TERMINAL", primary, None
    try:
        pre_research_provider_failure(primary)
    except (FallbackStateError, ResumeError):
        return "PRIMARY_FAILURE_TERMINAL", primary, None
    return "PRIMARY_TRANSIENT_FAILURE", primary, None


def consume_pre_research_fallback(
    attempt: str,
    edition: str,
    package_id: str,
    now: dt.datetime,
) -> dict:
    reason, primary, _ = classify_claimed_attempt(attempt, edition, package_id, now)
    if reason != "PRIMARY_TRANSIENT_FAILURE" or primary is None:
        return {"wakeAgent": False, "reason": reason}
    claim, claim_data = load_generation_claim(attempt, edition, package_id)
    executions = load_executions(claim)
    active = [
        row for row in executions
        if row["status"] == "running"
        and row["claimed_at"] >= primary["finished_at"]
        and row["claimed_at"] <= now
    ]
    if len(active) != 1:
        return {"wakeAgent": False, "reason": "PRIMARY_TRANSIENT_FAILURE"}
    provider_failure_sha256 = pre_research_provider_failure(primary)
    try:
        create_immutable(
            fallback_path(attempt),
            {
                "schema": "gneu-aihot-pre-research-fallback-v1",
                "status": "FALLBACK_RETRY",
                "edition": edition,
                "attempt": attempt,
                "package_id": package_id,
                "claim_sha256": sha256_bytes(claim_data),
                "primary_execution_id": primary["id"],
                "fallback_execution_id": active[0]["id"],
                "provider_error": "usage_limit_reached",
                "provider_failure_sha256": provider_failure_sha256,
                "consumed_at": now.astimezone(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
            },
        )
    except (OSError, ResumeError) as exc:
        raise FallbackStateError("could not create fallback receipt") from exc
    return {"wakeAgent": True, "reason": "FALLBACK_RETRY"}


def resume_paths() -> ResumePaths:
    return ResumePaths(STATE, OUTBOX, SCHEDULER_CONFIG, EXECUTIONS_DB, CRON_OUTPUT)


def retry_paths() -> RetryPaths:
    return RetryPaths(STATE, OUTBOX, SCHEDULER_CONFIG, EXECUTIONS_DB, CRON_OUTPUT)


def content_retry_paths() -> ContentRetryPaths:
    production = production_content_retry_paths()
    return ContentRetryPaths(
        STATE,
        OUTBOX,
        SCHEDULER_CONFIG,
        EXECUTIONS_DB,
        CRON_OUTPUT,
        production.provenance,
        production.runtime_paths,
        production.proc_root,
    )


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
    elif os.path.lexists(CLAIMS / "retry-consumed" / f"{attempt}-r2.json"):
        reason = "content_retry_already_consumed"
    elif os.path.lexists(CLAIMS / "retry-authorized" / f"{attempt}-r2.json"):
        reason = "operator_content_contract_retry_authorized"
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
        try:
            reason, _, _ = classify_claimed_attempt(
                attempt, context["edition"], package_id, now
            )
        except FallbackStateError:
            reason = "unsafe_pre_research_fallback_state"
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
                f"{package_id}--r2",
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
                content_retry_state, content_authorization = (
                    consume_content_retry_authorization(
                        content_retry_paths(), attempt, now
                    )
                )
            except ContentRetryError:
                return {
                    "wakeAgent": False,
                    "context": {**context, "reason": "unsafe_content_retry_state"},
                }
            if content_retry_state == "consumed" and content_authorization is not None:
                return {
                    "wakeAgent": True,
                    "context": {
                        **context,
                        "edition": content_authorization["edition"],
                        "attempt": content_authorization["attempt"],
                        "package_id": content_authorization["target_package_id"],
                        "revision": content_authorization["revision"],
                        "reason": "operator_content_contract_retry",
                    },
                }
            if content_retry_state == "already-consumed":
                return {
                    "wakeAgent": False,
                    "context": {**context, "reason": "content_retry_already_consumed"},
                }
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
            resume_state, original_claim = "not-authorized", None
            if (
                os.path.lexists(CLAIMS / "resume-authorized" / f"{attempt}.json")
                or os.path.lexists(CLAIMS / "resume-consumed" / f"{attempt}.json")
            ):
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
            if resume_state == "not-authorized":
                try:
                    fallback = consume_pre_research_fallback(
                        attempt, edition, package_id, now
                    )
                except FallbackStateError:
                    return {
                        "wakeAgent": False,
                        "context": {
                            **context,
                            "reason": "unsafe_pre_research_fallback_state",
                        },
                    }
                if fallback["wakeAgent"]:
                    return {
                        "wakeAgent": True,
                        "context": {**context, "reason": "FALLBACK_RETRY"},
                    }
                if fallback["reason"] != "daily_attempt_already_claimed":
                    return {
                        "wakeAgent": False,
                        "context": {**context, "reason": fallback["reason"]},
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
    inspection = args.command in {"inspect", "check"}
    value = inspect() if inspection else evaluate()
    print(json.dumps(value, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
