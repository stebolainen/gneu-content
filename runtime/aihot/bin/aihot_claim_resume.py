#!/usr/bin/env python3
"""Shared fail-closed state contract for AI-hot generation claim resume."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo


ZONE = ZoneInfo("Europe/Stockholm")
ATTEMPT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACKAGE_RE = re.compile(r"^(\d{4})-W(\d{2})--(\d{4}-\d{2}-\d{2})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REASON = "CLAIM_CREATED_WITHOUT_AGENT"
EXPECTED_JOB_ID = "fbd796dbb875"
ACTIVE_STATUSES = {"claimed", "running"}
CLAIM_KEYS = {"schema", "edition", "attempt", "package_id", "claimed_at"}
AUTHORIZATION_KEYS = {
    "schema",
    "edition",
    "attempt",
    "package_id",
    "claim_sha256",
    "claimed_at",
    "reason",
    "authorized_at",
}
CONSUMED_KEYS = AUTHORIZATION_KEYS | {
    "authorization_sha256",
    "consumed_at",
}


class ResumeError(RuntimeError):
    """A bounded, non-secret recovery-policy failure."""


class ResumePaths:
    def __init__(
        self,
        state: Path,
        outbox: Path,
        scheduler_config: Path,
        executions_db: Path,
        cron_output: Path,
    ) -> None:
        self.state = state
        self.outbox = outbox
        self.scheduler_config = scheduler_config
        self.executions_db = executions_db
        self.cron_output = cron_output

    @property
    def claims(self) -> Path:
        return self.state / "generation"

    @property
    def authorizations(self) -> Path:
        return self.claims / "resume-authorized"

    @property
    def consumed(self) -> Path:
        return self.claims / "resume-consumed"


def canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_timestamp(value: object, code: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ResumeError(code)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResumeError(code) from exc
    if parsed.tzinfo is None:
        raise ResumeError(code)
    return parsed.astimezone(dt.timezone.utc)


def validate_identity(edition: object, attempt: object, package_id: object) -> None:
    if not all(isinstance(value, str) for value in (edition, attempt, package_id)):
        raise ResumeError("INVALID_IDENTITY")
    if not ATTEMPT_RE.fullmatch(attempt):
        raise ResumeError("INVALID_IDENTITY")
    match = PACKAGE_RE.fullmatch(package_id)
    if match is None or match.group(3) != attempt:
        raise ResumeError("INVALID_IDENTITY")
    try:
        day = dt.date.fromisoformat(attempt)
    except ValueError as exc:
        raise ResumeError("INVALID_IDENTITY") from exc
    iso = day.isocalendar()
    expected = f"{iso.year}-W{iso.week:02d}"
    if edition != expected or package_id != f"{expected}--{attempt}":
        raise ResumeError("INVALID_IDENTITY")


def require_regular_root_file(path: Path, code: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ResumeError(code)
    stat_result = path.stat()
    if stat_result.st_uid != 0 or stat_result.st_gid != 0:
        raise ResumeError(code)
    if (stat_result.st_mode & 0o777) != 0o600:
        raise ResumeError(code)
    data = path.read_bytes()
    if len(data) > 8192:
        raise ResumeError(code)
    return data


def load_canonical(path: Path, keys: set[str], schema: str, code: str) -> tuple[dict, bytes]:
    data = require_regular_root_file(path, code)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResumeError(code) from exc
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise ResumeError(code)
    if canonical_bytes(value) != data:
        raise ResumeError(code)
    return value, data


def claim_path(paths: ResumePaths, attempt: str) -> Path:
    if not ATTEMPT_RE.fullmatch(attempt):
        raise ResumeError("INVALID_ATTEMPT")
    try:
        dt.date.fromisoformat(attempt)
    except ValueError as exc:
        raise ResumeError("INVALID_ATTEMPT") from exc
    return paths.claims / f"{attempt}.json"


def load_claim(paths: ResumePaths, attempt: str) -> tuple[dict, bytes]:
    claim, data = load_canonical(
        claim_path(paths, attempt),
        CLAIM_KEYS,
        "gneu-aihot-generation-claim-v1",
        "INVALID_CLAIM",
    )
    validate_identity(claim["edition"], claim["attempt"], claim["package_id"])
    if claim["attempt"] != attempt:
        raise ResumeError("INVALID_CLAIM")
    claimed_at = parse_timestamp(claim["claimed_at"], "INVALID_CLAIM")
    if claimed_at.astimezone(ZONE).date().isoformat() != attempt:
        raise ResumeError("INVALID_CLAIM")
    return claim, data


def authorization_path(paths: ResumePaths, attempt: str) -> Path:
    claim_path(paths, attempt)
    return paths.authorizations / f"{attempt}.json"


def consumed_path(paths: ResumePaths, attempt: str) -> Path:
    claim_path(paths, attempt)
    return paths.consumed / f"{attempt}.json"


def require_same_local_day(attempt: str, now: dt.datetime) -> None:
    if now.tzinfo is None:
        raise ResumeError("INVALID_TIME")
    if now.astimezone(ZONE).date().isoformat() != attempt:
        raise ResumeError("ATTEMPT_NOT_TODAY")


def require_absent(path: Path, code: str) -> None:
    if os.path.lexists(path):
        raise ResumeError(code)


def verify_package_absent(paths: ResumePaths, package_id: str) -> None:
    require_absent(paths.outbox / package_id, "PACKAGE_STATE_EXISTS")
    require_absent(paths.state / "processed" / f"{package_id}.json", "PROCESSED_STATE_EXISTS")
    require_absent(paths.state / "failed" / f"{package_id}.json", "FAILED_STATE_EXISTS")
    require_absent(paths.state / "intake" / f"{package_id}.transport.json", "TRANSPORT_STATE_EXISTS")


def load_job_id(paths: ResumePaths) -> str:
    if paths.scheduler_config.is_symlink() or not paths.scheduler_config.is_file():
        raise ResumeError("INVALID_SCHEDULER_CONFIG")
    config_stat = paths.scheduler_config.stat()
    if config_stat.st_uid != 0 or config_stat.st_gid != 0:
        raise ResumeError("INVALID_SCHEDULER_CONFIG")
    if (config_stat.st_mode & 0o777) != 0o600:
        raise ResumeError("INVALID_SCHEDULER_CONFIG")
    try:
        value = json.loads(paths.scheduler_config.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ResumeError("INVALID_SCHEDULER_CONFIG") from exc
    job_id = value.get("job_id") if isinstance(value, dict) else None
    if (
        job_id != EXPECTED_JOB_ID
        or value.get("schema") != "gneu-aihot-hermes-scheduler-v1"
        or value.get("name") != "gneu-aihot-daily"
        or value.get("script") != "gneu-aihot-daily-gate.py"
    ):
        raise ResumeError("INVALID_SCHEDULER_CONFIG")
    return job_id


def verify_no_execution_owner(paths: ResumePaths, claim: dict) -> None:
    job_id = load_job_id(paths)
    if paths.executions_db.is_symlink() or not paths.executions_db.is_file():
        raise ResumeError("INVALID_EXECUTION_LEDGER")
    claimed_at = parse_timestamp(claim["claimed_at"], "INVALID_CLAIM")
    try:
        connection = sqlite3.connect(f"file:{paths.executions_db}?mode=ro", uri=True)
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(executions)")
            }
            required = {"job_id", "status", "claimed_at"}
            if not required.issubset(columns):
                raise ResumeError("INVALID_EXECUTION_LEDGER")
            rows = connection.execute(
                "SELECT status, claimed_at FROM executions WHERE job_id = ?",
                (job_id,),
            ).fetchall()
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as exc:
        raise ResumeError("INVALID_EXECUTION_LEDGER") from exc
    for status, execution_claimed_at in rows:
        if status in ACTIVE_STATUSES:
            raise ResumeError("ACTIVE_EXECUTION")
        execution_time = parse_timestamp(execution_claimed_at, "INVALID_EXECUTION_LEDGER")
        if execution_time >= claimed_at:
            raise ResumeError("EXECUTION_AFTER_CLAIM")

    output_dir = paths.cron_output / job_id
    if os.path.lexists(output_dir):
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise ResumeError("INVALID_EXECUTION_OUTPUT")
        marker = claim["package_id"].encode()
        for entry in output_dir.iterdir():
            if entry.is_symlink() or not entry.is_file():
                raise ResumeError("INVALID_EXECUTION_OUTPUT")
            stat_result = entry.stat()
            if stat_result.st_size > 1024 * 1024:
                raise ResumeError("INVALID_EXECUTION_OUTPUT")
            data = entry.read_bytes()
            if marker in data or dt.datetime.fromtimestamp(
                stat_result.st_mtime, dt.timezone.utc
            ) >= claimed_at:
                raise ResumeError("EXECUTION_OUTPUT_AFTER_CLAIM")
    process_markers = (
        b"gneu-aihot-daily-gate.py",
        b"gneu-aihot-base-refresh.py",
        b"gneu-aihot-handoff-validate.py",
    )
    for process in Path("/proc").glob("[0-9]*"):
        if process.name == str(os.getpid()):
            continue
        try:
            command = (process / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(marker in command for marker in process_markers):
            raise ResumeError("ACTIVE_GENERATION_PROCESS")


def atomic_create(path: Path, value: dict) -> str:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink() or not parent.is_dir():
        raise ResumeError("UNSAFE_STATE_DIRECTORY")
    os.chmod(parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    data = canonical_bytes(value)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.chown(temporary, 0, 0)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ResumeError("STATE_ALREADY_EXISTS") from exc
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return sha256_bytes(data)


def load_authorization(paths: ResumePaths, attempt: str, claim: dict, claim_sha: str) -> tuple[dict, bytes]:
    authorization, data = load_canonical(
        authorization_path(paths, attempt),
        AUTHORIZATION_KEYS,
        "gneu-aihot-generation-resume-authorization-v1",
        "INVALID_AUTHORIZATION",
    )
    validate_identity(
        authorization["edition"], authorization["attempt"], authorization["package_id"]
    )
    for key in ("edition", "attempt", "package_id", "claimed_at"):
        if authorization[key] != claim[key]:
            raise ResumeError("AUTHORIZATION_BINDING_MISMATCH")
    if authorization["claim_sha256"] != claim_sha or authorization["reason"] != REASON:
        raise ResumeError("AUTHORIZATION_BINDING_MISMATCH")
    authorized_at = parse_timestamp(
        authorization["authorized_at"], "INVALID_AUTHORIZATION"
    )
    if authorized_at.astimezone(ZONE).date().isoformat() != attempt:
        raise ResumeError("INVALID_AUTHORIZATION")
    return authorization, data


def load_consumed(
    paths: ResumePaths,
    attempt: str,
    claim: dict,
    claim_sha: str,
    authorization: dict,
    authorization_sha: str,
) -> tuple[dict, bytes]:
    consumed, data = load_canonical(
        consumed_path(paths, attempt),
        CONSUMED_KEYS,
        "gneu-aihot-generation-resume-consumed-v1",
        "INVALID_CONSUMED_RECEIPT",
    )
    for key in AUTHORIZATION_KEYS - {"schema"}:
        if consumed[key] != authorization[key]:
            raise ResumeError("CONSUMED_BINDING_MISMATCH")
    if consumed["claim_sha256"] != claim_sha:
        raise ResumeError("CONSUMED_BINDING_MISMATCH")
    if consumed["authorization_sha256"] != authorization_sha:
        raise ResumeError("CONSUMED_BINDING_MISMATCH")
    consumed_at = parse_timestamp(consumed["consumed_at"], "INVALID_CONSUMED_RECEIPT")
    if consumed_at.astimezone(ZONE).date().isoformat() != attempt:
        raise ResumeError("INVALID_CONSUMED_RECEIPT")
    return consumed, data


def generation_lock(paths: ResumePaths):
    paths.claims.mkdir(parents=True, exist_ok=True, mode=0o700)
    if paths.claims.is_symlink() or not paths.claims.is_dir():
        raise ResumeError("UNSAFE_GENERATION_STATE")
    lock_path = paths.claims / "daily-gate.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    handle = os.fdopen(descriptor, "a+")
    os.chmod(lock_path, 0o600)
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def authorize(
    paths: ResumePaths,
    attempt: str,
    expected_claim_sha: str,
    reason: str,
    now: dt.datetime | None = None,
) -> tuple[dict, str]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if reason != REASON or not SHA256_RE.fullmatch(expected_claim_sha):
        raise ResumeError("INVALID_AUTHORIZATION_REQUEST")
    require_same_local_day(attempt, now)
    initial_claim, initial_claim_data = load_claim(paths, attempt)
    if sha256_bytes(initial_claim_data) != expected_claim_sha:
        raise ResumeError("CLAIM_HASH_MISMATCH")
    with generation_lock(paths):
        claim, claim_data = load_claim(paths, attempt)
        claim_sha = sha256_bytes(claim_data)
        if claim_sha != expected_claim_sha:
            raise ResumeError("CLAIM_HASH_MISMATCH")
        if parse_timestamp(claim["claimed_at"], "INVALID_CLAIM") > now.astimezone(
            dt.timezone.utc
        ):
            raise ResumeError("CLAIM_FROM_FUTURE")
        verify_package_absent(paths, claim["package_id"])
        require_absent(authorization_path(paths, attempt), "AUTHORIZATION_ALREADY_EXISTS")
        require_absent(consumed_path(paths, attempt), "CONSUMED_RECEIPT_EXISTS")
        verify_no_execution_owner(paths, claim)
        value = {
            "schema": "gneu-aihot-generation-resume-authorization-v1",
            "edition": claim["edition"],
            "attempt": claim["attempt"],
            "package_id": claim["package_id"],
            "claim_sha256": claim_sha,
            "claimed_at": claim["claimed_at"],
            "reason": REASON,
            "authorized_at": now.astimezone(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }
        authorization_sha = atomic_create(authorization_path(paths, attempt), value)
    return value, authorization_sha


def verify_authorization(
    paths: ResumePaths, attempt: str, expected_claim_sha: str
) -> tuple[dict, str]:
    claim, claim_data = load_claim(paths, attempt)
    claim_sha = sha256_bytes(claim_data)
    if claim_sha != expected_claim_sha:
        raise ResumeError("CLAIM_HASH_MISMATCH")
    authorization, data = load_authorization(paths, attempt, claim, claim_sha)
    return authorization, sha256_bytes(data)


def consume_authorization(
    paths: ResumePaths, attempt: str, now: dt.datetime
) -> tuple[str, dict | None]:
    claim, claim_data = load_claim(paths, attempt)
    require_same_local_day(attempt, now)
    claim_sha = sha256_bytes(claim_data)
    authorization_file = authorization_path(paths, attempt)
    consumed_file = consumed_path(paths, attempt)
    if not os.path.lexists(authorization_file):
        if os.path.lexists(consumed_file):
            raise ResumeError("CONSUMED_WITHOUT_AUTHORIZATION")
        return "not-authorized", claim
    authorization, authorization_data = load_authorization(
        paths, attempt, claim, claim_sha
    )
    if parse_timestamp(
        authorization["authorized_at"], "INVALID_AUTHORIZATION"
    ) > now.astimezone(dt.timezone.utc):
        raise ResumeError("AUTHORIZATION_FROM_FUTURE")
    authorization_sha = sha256_bytes(authorization_data)
    if os.path.lexists(consumed_file):
        load_consumed(
            paths, attempt, claim, claim_sha, authorization, authorization_sha
        )
        return "already-consumed", claim
    verify_package_absent(paths, claim["package_id"])
    value = {
        **authorization,
        "schema": "gneu-aihot-generation-resume-consumed-v1",
        "authorization_sha256": authorization_sha,
        "consumed_at": now.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }
    atomic_create(consumed_file, value)
    return "consumed", claim


def verify_consumed(
    paths: ResumePaths, attempt: str, expected_claim_sha: str
) -> tuple[dict, str]:
    claim, claim_data = load_claim(paths, attempt)
    claim_sha = sha256_bytes(claim_data)
    if claim_sha != expected_claim_sha:
        raise ResumeError("CLAIM_HASH_MISMATCH")
    authorization, authorization_data = load_authorization(
        paths, attempt, claim, claim_sha
    )
    consumed, consumed_data = load_consumed(
        paths,
        attempt,
        claim,
        claim_sha,
        authorization,
        sha256_bytes(authorization_data),
    )
    return consumed, sha256_bytes(consumed_data)
