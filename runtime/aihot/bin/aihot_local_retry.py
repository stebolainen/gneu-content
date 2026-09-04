#!/usr/bin/env python3
"""Fail-closed authorization for one local AI-hot correction revision."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from zoneinfo import ZoneInfo

from aihot_claim_resume import (
    ACTIVE_STATUSES,
    ResumeError,
    ResumePaths,
    atomic_create,
    canonical_bytes,
    generation_lock,
    load_job_id,
    parse_timestamp,
    sha256_bytes,
)


ZONE = ZoneInfo("Europe/Stockholm")
ATTEMPT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SOURCE_PACKAGE_RE = re.compile(r"^(\d{4}-W\d{2})--(\d{4}-\d{2}-\d{2})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXECUTION_RE = re.compile(r"^[0-9a-f]{32}$")
REVISION = 1
REASON = "ARTICLE_DATE_OUTSIDE_EDITION"
AUTHORIZATION_KEYS = {
    "schema",
    "edition",
    "attempt",
    "source_package_id",
    "source_candidate_sha256",
    "source_handoff_sha256",
    "source_report_sha256",
    "hermes_execution_id",
    "validation_failure",
    "target_package_id",
    "revision",
    "authorized_at",
}
CONSUMED_KEYS = AUTHORIZATION_KEYS | {"authorization_sha256", "consumed_at"}


class RetryError(RuntimeError):
    """A bounded, non-secret local-retry policy failure."""


class RetryPaths(ResumePaths):
    @property
    def authorizations(self) -> Path:
        return self.claims / "retry-authorized"

    @property
    def consumed(self) -> Path:
        return self.claims / "retry-consumed"


def identity_for_attempt(attempt: str) -> tuple[str, str, str]:
    if not isinstance(attempt, str) or not ATTEMPT_RE.fullmatch(attempt):
        raise RetryError("INVALID_ATTEMPT")
    try:
        day = dt.date.fromisoformat(attempt)
    except ValueError as exc:
        raise RetryError("INVALID_ATTEMPT") from exc
    iso = day.isocalendar()
    edition = f"{iso.year}-W{iso.week:02d}"
    source = f"{edition}--{attempt}"
    return edition, source, f"{source}--r1"


def authorization_path(paths: RetryPaths, attempt: str) -> Path:
    identity_for_attempt(attempt)
    return paths.authorizations / f"{attempt}-r1.json"


def consumed_path(paths: RetryPaths, attempt: str) -> Path:
    identity_for_attempt(attempt)
    return paths.consumed / f"{attempt}-r1.json"


def require_same_local_day(attempt: str, now: dt.datetime) -> None:
    if now.tzinfo is None or now.astimezone(ZONE).date().isoformat() != attempt:
        raise RetryError("ATTEMPT_NOT_TODAY")


def require_absent(path: Path, code: str) -> None:
    if os.path.lexists(path):
        raise RetryError(code)


def require_regular(path: Path, code: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RetryError(code)
    data = path.read_bytes()
    if not data or len(data) > maximum:
        raise RetryError(code)
    return data


def create_receipt(path: Path, value: dict) -> str:
    try:
        return atomic_create(path, value)
    except ResumeError as exc:
        raise RetryError("RETRY_STATE_CREATE_FAILED") from exc


def load_canonical(path: Path, keys: set[str], schema: str, code: str) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise RetryError(code)
    stat_result = path.stat()
    if stat_result.st_uid != 0 or stat_result.st_gid != 0:
        raise RetryError(code)
    if (stat_result.st_mode & 0o777) != 0o600:
        raise RetryError(code)
    data = path.read_bytes()
    if not data or len(data) > 8192:
        raise RetryError(code)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetryError(code) from exc
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise RetryError(code)
    if canonical_bytes(value) != data:
        raise RetryError(code)
    return value, data


def source_hashes(paths: RetryPaths, source_package_id: str) -> dict[str, str]:
    if paths.outbox.is_symlink() or not paths.outbox.is_dir():
        raise RetryError("UNSAFE_OUTBOX")
    package = paths.outbox / source_package_id
    if package.is_symlink() or not package.is_dir():
        raise RetryError("SOURCE_PACKAGE_MISSING")
    if {entry.name for entry in package.iterdir()} != {
        "candidate.json",
        "handoff.json",
        "report.md",
    }:
        raise RetryError("SOURCE_PACKAGE_FILE_SET_INVALID")
    limits = {"candidate.json": 5 * 1024 * 1024, "handoff.json": 8192, "report.md": 50000}
    return {
        name.removesuffix(".json").removesuffix(".md"): hashlib.sha256(
            require_regular(package / name, "SOURCE_PACKAGE_FILE_INVALID", limits[name])
        ).hexdigest()
        for name in ("candidate.json", "handoff.json", "report.md")
    }


def verify_source_immutable(paths: RetryPaths, source_package_id: str) -> dict[str, str]:
    match = SOURCE_PACKAGE_RE.fullmatch(source_package_id)
    if match is None:
        raise RetryError("INVALID_SOURCE_IDENTITY")
    edition, attempt = match.groups()
    expected_edition, expected_source, _ = identity_for_attempt(attempt)
    if edition != expected_edition or source_package_id != expected_source:
        raise RetryError("INVALID_SOURCE_IDENTITY")
    require_absent(paths.outbox / source_package_id / "READY", "SOURCE_READY_EXISTS")
    require_absent(paths.state / "processed" / f"{source_package_id}.json", "SOURCE_PROCESSED_EXISTS")
    require_absent(paths.state / "failed" / f"{source_package_id}.json", "SOURCE_FAILED_EXISTS")
    require_absent(paths.state / "intake" / f"{source_package_id}.transport.json", "SOURCE_TRANSPORT_EXISTS")
    return source_hashes(paths, source_package_id)


def verify_source_terminal(paths: RetryPaths, source_package_id: str) -> dict[str, str]:
    hashes = verify_source_immutable(paths, source_package_id)
    match = SOURCE_PACKAGE_RE.fullmatch(source_package_id)
    assert match is not None
    edition, attempt = match.groups()
    package = paths.outbox / source_package_id
    try:
        base = json.loads((paths.outbox.parent / "inbox" / "current.json").read_text())
        handoff = json.loads((package / "handoff.json").read_text())
        candidate = json.loads((package / "candidate.json").read_text())
    except Exception as exc:
        raise RetryError("SOURCE_JSON_INVALID") from exc
    if not all(isinstance(value, dict) for value in (base, handoff, candidate)):
        raise RetryError("SOURCE_JSON_INVALID")
    if handoff.get("schema") != "gneu-aihot-handoff-v2" or handoff.get("producer") != "adam":
        raise RetryError("SOURCE_HANDOFF_INVALID")
    if handoff.get("edition") != edition or handoff.get("attempt") != attempt:
        raise RetryError("SOURCE_HANDOFF_INVALID")
    if "revision" in handoff:
        raise RetryError("SOURCE_HANDOFF_INVALID")
    if handoff.get("mode") != "edition":
        raise RetryError("SOURCE_FAILURE_NOT_REPRODUCED")
    base_raw = (paths.outbox.parent / "inbox" / "current.json").read_bytes()
    if handoff.get("base_sha256") != hashlib.sha256(base_raw).hexdigest():
        raise RetryError("SOURCE_BASE_BINDING_INVALID")
    if handoff.get("base_generated") != base.get("generated") or candidate.get("generated") != base.get("generated"):
        raise RetryError("SOURCE_BASE_BINDING_INVALID")
    be, ce = base.get("editions"), candidate.get("editions")
    ba, ca = base.get("articles"), candidate.get("articles")
    if not all(isinstance(value, list) for value in (be, ce, ba, ca)):
        raise RetryError("SOURCE_DELTA_INVALID")
    if ce[: len(be)] != be or ca[: len(ba)] != ba:
        raise RetryError("SOURCE_DELTA_INVALID")
    if set(candidate) != {"generated", "editions", "articles"}:
        raise RetryError("SOURCE_DELTA_INVALID")
    if {key: value for key, value in base.items() if key not in {"editions", "articles"}} != {
        key: value
        for key, value in candidate.items()
        if key not in {"editions", "articles"}
    }:
        raise RetryError("SOURCE_DELTA_INVALID")
    added_editions, added_articles = ce[len(be) :], ca[len(ba) :]
    if len(added_editions) != 1 or not isinstance(added_editions[0], dict) or added_editions[0].get("id") != edition:
        raise RetryError("SOURCE_DELTA_INVALID")
    if not 1 <= len(added_articles) <= 6:
        raise RetryError("SOURCE_DELTA_INVALID")
    outside = False
    existing = {str(item.get("id")) for item in ba if isinstance(item, dict)}
    seen: set[str] = set()
    for article in added_articles:
        if not isinstance(article, dict):
            raise RetryError("SOURCE_DELTA_INVALID")
        article_id = str(article.get("id") or "")
        if not article_id or article_id in existing or article_id in seen or article.get("edition") != edition:
            raise RetryError("SOURCE_DELTA_INVALID")
        seen.add(article_id)
        try:
            article_date = dt.date.fromisoformat(str(article.get("date") or ""))
        except ValueError as exc:
            raise RetryError("SOURCE_DELTA_INVALID") from exc
        article_iso = article_date.isocalendar()
        if (article_iso.year, article_iso.week) != (int(edition[:4]), int(edition[-2:])):
            outside = True
        sources = article.get("sources")
        if not isinstance(sources, list) or len(sources) < 2:
            raise RetryError("SOURCE_DELTA_INVALID")
    if not outside:
        raise RetryError("SOURCE_FAILURE_NOT_REPRODUCED")
    if len((package / "report.md").read_text().strip()) < 200:
        raise RetryError("SOURCE_DELTA_INVALID")
    return hashes


def verify_execution(paths: RetryPaths, execution_id: str, source_package_id: str) -> None:
    if not EXECUTION_RE.fullmatch(execution_id):
        raise RetryError("INVALID_EXECUTION_ID")
    try:
        job_id = load_job_id(paths)
    except ResumeError as exc:
        raise RetryError("INVALID_SCHEDULER_CONFIG") from exc
    try:
        if paths.executions_db.is_symlink() or not paths.executions_db.is_file():
            raise RetryError("INVALID_EXECUTION_LEDGER")
        connection = sqlite3.connect(f"file:{paths.executions_db}?mode=ro", uri=True)
        try:
            rows = connection.execute(
                "SELECT id, status FROM executions WHERE job_id = ?", (job_id,)
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RetryError("INVALID_EXECUTION_LEDGER") from exc
    if any(status in ACTIVE_STATUSES for _, status in rows):
        raise RetryError("ACTIVE_EXECUTION")
    match = [status for row_id, status in rows if row_id == execution_id]
    if match != ["completed"]:
        raise RetryError("SOURCE_EXECUTION_NOT_TERMINAL")
    output_dir = paths.cron_output / job_id
    marker = f"AIHOT_HANDOFF_FAILED {source_package_id} article date outside edition".encode()
    found = False
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise RetryError("INVALID_EXECUTION_OUTPUT")
    for entry in output_dir.iterdir():
        data = require_regular(entry, "INVALID_EXECUTION_OUTPUT", 1024 * 1024)
        if source_package_id.encode() in data and marker in data:
            found = True
    if not found:
        raise RetryError("SOURCE_FAILURE_OUTPUT_MISSING")
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
            raise RetryError("ACTIVE_GENERATION_PROCESS")


def verify_target_absent(paths: RetryPaths, target: str) -> None:
    require_absent(paths.outbox / target, "TARGET_PACKAGE_EXISTS")
    require_absent(paths.state / "processed" / f"{target}.json", "TARGET_PROCESSED_EXISTS")
    require_absent(paths.state / "failed" / f"{target}.json", "TARGET_FAILED_EXISTS")
    require_absent(paths.state / "intake" / f"{target}.transport.json", "TARGET_TRANSPORT_EXISTS")


def authorization_values_match(value: dict, attempt: str, hashes: dict[str, str]) -> None:
    edition, source, target = identity_for_attempt(attempt)
    expected = {
        "edition": edition,
        "attempt": attempt,
        "source_package_id": source,
        "source_candidate_sha256": hashes["candidate"],
        "source_handoff_sha256": hashes["handoff"],
        "source_report_sha256": hashes["report"],
        "target_package_id": target,
        "revision": REVISION,
        "validation_failure": REASON,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise RetryError("AUTHORIZATION_BINDING_MISMATCH")


def load_authorization(paths: RetryPaths, attempt: str, hashes: dict[str, str]) -> tuple[dict, bytes]:
    value, data = load_canonical(
        authorization_path(paths, attempt),
        AUTHORIZATION_KEYS,
        "gneu-aihot-generation-retry-authorization-v1",
        "INVALID_RETRY_AUTHORIZATION",
    )
    authorization_values_match(value, attempt, hashes)
    authorized_at = parse_timestamp(
        value["authorized_at"], "INVALID_RETRY_AUTHORIZATION"
    )
    if authorized_at.astimezone(ZONE).date().isoformat() != attempt:
        raise RetryError("INVALID_RETRY_AUTHORIZATION")
    if not EXECUTION_RE.fullmatch(str(value.get("hermes_execution_id") or "")):
        raise RetryError("INVALID_RETRY_AUTHORIZATION")
    return value, data


def load_consumed(paths: RetryPaths, attempt: str, authorization: dict, authorization_sha: str) -> tuple[dict, bytes]:
    value, data = load_canonical(
        consumed_path(paths, attempt),
        CONSUMED_KEYS,
        "gneu-aihot-generation-retry-consumed-v1",
        "INVALID_RETRY_CONSUMED",
    )
    for key in AUTHORIZATION_KEYS - {"schema"}:
        if value.get(key) != authorization.get(key):
            raise RetryError("RETRY_CONSUMED_BINDING_MISMATCH")
    if value.get("authorization_sha256") != authorization_sha:
        raise RetryError("RETRY_CONSUMED_BINDING_MISMATCH")
    consumed_at = parse_timestamp(value["consumed_at"], "INVALID_RETRY_CONSUMED")
    if consumed_at.astimezone(ZONE).date().isoformat() != authorization["attempt"]:
        raise RetryError("INVALID_RETRY_CONSUMED")
    return value, data


def authorize(
    paths: RetryPaths,
    attempt: str,
    expected_hashes: dict[str, str],
    execution_id: str,
    reason: str,
    now: dt.datetime | None = None,
) -> tuple[dict, str]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if reason != REASON or set(expected_hashes) != {"candidate", "handoff", "report"}:
        raise RetryError("INVALID_RETRY_REQUEST")
    if not all(SHA256_RE.fullmatch(value) for value in expected_hashes.values()):
        raise RetryError("INVALID_RETRY_REQUEST")
    require_same_local_day(attempt, now)
    edition, source, target = identity_for_attempt(attempt)
    try:
        lock = generation_lock(paths)
    except ResumeError as exc:
        raise RetryError("UNSAFE_GENERATION_STATE") from exc
    with lock:
        hashes = verify_source_terminal(paths, source)
        if hashes != expected_hashes:
            raise RetryError("SOURCE_HASH_MISMATCH")
        verify_execution(paths, execution_id, source)
        verify_target_absent(paths, target)
        require_absent(authorization_path(paths, attempt), "RETRY_AUTHORIZATION_EXISTS")
        require_absent(consumed_path(paths, attempt), "RETRY_CONSUMED_EXISTS")
        value = {
            "schema": "gneu-aihot-generation-retry-authorization-v1",
            "edition": edition,
            "attempt": attempt,
            "source_package_id": source,
            "source_candidate_sha256": hashes["candidate"],
            "source_handoff_sha256": hashes["handoff"],
            "source_report_sha256": hashes["report"],
            "hermes_execution_id": execution_id,
            "validation_failure": REASON,
            "target_package_id": target,
            "revision": REVISION,
            "authorized_at": now.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
        receipt_sha = create_receipt(authorization_path(paths, attempt), value)
    return value, receipt_sha


def verify_authorization(paths: RetryPaths, attempt: str, expected_hashes: dict[str, str]) -> tuple[dict, str]:
    _, source, _ = identity_for_attempt(attempt)
    hashes = verify_source_immutable(paths, source)
    if hashes != expected_hashes:
        raise RetryError("SOURCE_HASH_MISMATCH")
    value, data = load_authorization(paths, attempt, hashes)
    return value, sha256_bytes(data)


def consume_authorization(paths: RetryPaths, attempt: str, now: dt.datetime) -> tuple[str, dict | None]:
    require_same_local_day(attempt, now)
    _, source, target = identity_for_attempt(attempt)
    hashes = verify_source_immutable(paths, source)
    auth_path = authorization_path(paths, attempt)
    receipt_path = consumed_path(paths, attempt)
    if not os.path.lexists(auth_path):
        if os.path.lexists(receipt_path):
            raise RetryError("RETRY_CONSUMED_WITHOUT_AUTHORIZATION")
        return "not-authorized", None
    authorization, data = load_authorization(paths, attempt, hashes)
    if parse_timestamp(
        authorization["authorized_at"], "INVALID_RETRY_AUTHORIZATION"
    ) > now.astimezone(dt.timezone.utc):
        raise RetryError("RETRY_AUTHORIZATION_FROM_FUTURE")
    authorization_sha = sha256_bytes(data)
    if os.path.lexists(receipt_path):
        load_consumed(paths, attempt, authorization, authorization_sha)
        return "already-consumed", authorization
    verify_target_absent(paths, target)
    value = {
        **authorization,
        "schema": "gneu-aihot-generation-retry-consumed-v1",
        "authorization_sha256": authorization_sha,
        "consumed_at": now.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    create_receipt(receipt_path, value)
    return "consumed", authorization


def verify_consumed(paths: RetryPaths, attempt: str, expected_hashes: dict[str, str]) -> tuple[dict, str]:
    authorization, authorization_data = verify_authorization(paths, attempt, expected_hashes)
    consumed, data = load_consumed(
        paths, attempt, authorization, sha256_bytes(authorization_data)
    )
    return consumed, sha256_bytes(data)


def verify_target_consumed(paths: RetryPaths, target_package_id: str) -> tuple[dict, str]:
    match = re.fullmatch(
        r"(?P<source>\d{4}-W\d{2}--(?P<attempt>\d{4}-\d{2}-\d{2}))--r1",
        target_package_id,
    )
    if match is None:
        raise RetryError("INVALID_TARGET_IDENTITY")
    attempt = match.group("attempt")
    _, expected_source, expected_target = identity_for_attempt(attempt)
    if match.group("source") != expected_source or target_package_id != expected_target:
        raise RetryError("INVALID_TARGET_IDENTITY")
    hashes = verify_source_immutable(paths, expected_source)
    authorization, authorization_data = load_authorization(paths, attempt, hashes)
    consumed, data = load_consumed(
        paths, attempt, authorization, sha256_bytes(authorization_data)
    )
    return consumed, sha256_bytes(data)


def source_resolved_by_retry(paths: RetryPaths, source_package_id: str) -> bool:
    match = SOURCE_PACKAGE_RE.fullmatch(source_package_id)
    if match is None:
        return False
    attempt = match.group(2)
    hashes = verify_source_immutable(paths, source_package_id)
    authorization, authorization_data = load_authorization(paths, attempt, hashes)
    load_consumed(paths, attempt, authorization, sha256_bytes(authorization_data))
    target = authorization["target_package_id"]
    return any(
        os.path.lexists(path)
        for path in (
            paths.outbox / target / "READY",
            paths.state / "processed" / f"{target}.json",
            paths.state / "failed" / f"{target}.json",
        )
    )
