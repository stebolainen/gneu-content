#!/usr/bin/env python3
"""Append-only authorization for one trusted READY processing retry."""

from __future__ import annotations

import ast
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from contextlib import contextmanager

from aihot_claim_resume import (
    ResumeError,
    atomic_create,
    canonical_bytes,
    parse_timestamp,
    sha256_bytes,
)
from aihot_package_identity import parse_package_id


REASON = "VALIDATE_RUNTIME_DATE_IMPORT_ERROR"
FAILURE_CLASS = REASON
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_LIMITS = {
    "candidate.json": 5 * 1024 * 1024,
    "handoff.json": 8192,
    "report.md": 50000,
    "READY": 8192,
}
AUTHORIZATION_KEYS = {
    "schema",
    "package_id",
    "edition",
    "attempt",
    "revision",
    "candidate_sha256",
    "handoff_sha256",
    "report_sha256",
    "ready_sha256",
    "failed_receipt_sha256",
    "failed_stage",
    "failure_class",
    "runtime_source_commit",
    "reason",
    "authorized_at",
}
CONSUMED_KEYS = AUTHORIZATION_KEYS | {
    "authorization_sha256",
    "consumed_at",
}
RETRY_FAILURE_KEYS = {
    "schema",
    "package_id",
    "edition",
    "attempt",
    "revision",
    "original_failed_receipt_sha256",
    "authorization_sha256",
    "consumed_sha256",
    "failed_at",
    "failed_stage",
    "failure_code",
    "stages",
}
RECOVERY_PROCESSED_KEYS = {
    "ready_retry_failed_sha256",
    "ready_retry_authorization_sha256",
    "ready_retry_consumed_sha256",
    "ready_retry_failure_class",
}
REQUIRED_RUNTIME = {
    "runtime/aihot/bin/validate-intake.py": ("validate-intake.py", "0700"),
    "runtime/aihot/bin/process-ready.py": ("process-ready.py", "0700"),
    "runtime/aihot/bin/aihot_local_retry.py": ("aihot_local_retry.py", "0600"),
    "runtime/aihot/bin/authorize-local-retry.py": ("authorize-local-retry.py", "0700"),
    "runtime/aihot/bin/aihot_ready_retry.py": ("aihot_ready_retry.py", "0600"),
    "runtime/aihot/bin/authorize-ready-retry.py": ("authorize-ready-retry.py", "0700"),
}


class ReadyRetryError(RuntimeError):
    """A bounded, non-secret READY-retry policy failure."""


class ReadyRetryPaths:
    def __init__(
        self,
        state: Path,
        outbox: Path,
        provenance: Path,
        bin_dir: Path,
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.state = state
        self.outbox = outbox
        self.provenance = provenance
        self.bin_dir = bin_dir
        self.proc_root = proc_root

    @property
    def root(self) -> Path:
        return self.state / "ready-retry"

    @property
    def authorized(self) -> Path:
        return self.root / "authorized"

    @property
    def consumed(self) -> Path:
        return self.root / "consumed"

    @property
    def retry_failed(self) -> Path:
        return self.root / "failed"


def require_sha(value: str, code: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReadyRetryError(code)


def require_regular(path: Path, code: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReadyRetryError(code)
    data = path.read_bytes()
    if not data or len(data) > maximum:
        raise ReadyRetryError(code)
    return data


def require_root_state(path: Path, code: str, maximum: int = 65536) -> bytes:
    data = require_regular(path, code, maximum)
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise ReadyRetryError(code)
    if (metadata.st_mode & 0o777) != 0o600:
        raise ReadyRetryError(code)
    return data


def load_canonical(
    path: Path, keys: set[str], schema: str, code: str
) -> tuple[dict, bytes]:
    data = require_root_state(path, code, 65536)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadyRetryError(code) from exc
    if not isinstance(value, dict) or set(value) != keys:
        raise ReadyRetryError(code)
    if value.get("schema") != schema or canonical_bytes(value) != data:
        raise ReadyRetryError(code)
    return value, data


def create_receipt(path: Path, value: dict) -> str:
    try:
        return atomic_create(path, value)
    except ResumeError as exc:
        raise ReadyRetryError("READY_RETRY_STATE_CREATE_FAILED") from exc


def identity(package_id: str) -> tuple[str, str, int]:
    try:
        edition, attempt, revision = parse_package_id(package_id)
    except (TypeError, ValueError) as exc:
        raise ReadyRetryError("INVALID_READY_RETRY_PACKAGE") from exc
    if attempt is None or revision != 1:
        raise ReadyRetryError("INVALID_READY_RETRY_PACKAGE")
    return edition, attempt, revision


def authorization_path(paths: ReadyRetryPaths, package_id: str) -> Path:
    identity(package_id)
    return paths.authorized / f"{package_id}.json"


def consumed_path(paths: ReadyRetryPaths, package_id: str) -> Path:
    identity(package_id)
    return paths.consumed / f"{package_id}.json"


def retry_failure_path(paths: ReadyRetryPaths, package_id: str) -> Path:
    identity(package_id)
    return paths.retry_failed / f"{package_id}.json"


def package_hashes(paths: ReadyRetryPaths, package_id: str) -> dict[str, str]:
    edition, attempt, revision = identity(package_id)
    if paths.outbox.is_symlink() or not paths.outbox.is_dir():
        raise ReadyRetryError("UNSAFE_OUTBOX")
    package = paths.outbox / package_id
    if package.is_symlink() or not package.is_dir():
        raise ReadyRetryError("READY_RETRY_PACKAGE_MISSING")
    if {entry.name for entry in package.iterdir()} != set(PACKAGE_LIMITS):
        raise ReadyRetryError("READY_RETRY_PACKAGE_FILE_SET_INVALID")
    result = {}
    for filename, maximum in PACKAGE_LIMITS.items():
        key = filename.removesuffix(".json").removesuffix(".md").lower()
        result[key] = hashlib.sha256(
            require_regular(
                package / filename,
                "READY_RETRY_PACKAGE_FILE_INVALID",
                maximum,
            )
        ).hexdigest()
    try:
        handoff = json.loads((package / "handoff.json").read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReadyRetryError("READY_RETRY_HANDOFF_INVALID") from exc
    if not isinstance(handoff, dict):
        raise ReadyRetryError("READY_RETRY_HANDOFF_INVALID")
    if (
        handoff.get("schema") != "gneu-aihot-handoff-v2"
        or handoff.get("edition") != edition
        or handoff.get("attempt") != attempt
        or handoff.get("revision") != revision
    ):
        raise ReadyRetryError("READY_RETRY_HANDOFF_INVALID")
    return result


def expected_hashes_match(actual: dict[str, str], expected: dict[str, str]) -> None:
    if set(expected) != {"candidate", "handoff", "report", "ready"}:
        raise ReadyRetryError("INVALID_READY_RETRY_REQUEST")
    if not all(SHA256_RE.fullmatch(value) for value in expected.values()):
        raise ReadyRetryError("INVALID_READY_RETRY_REQUEST")
    if actual != expected:
        raise ReadyRetryError("READY_RETRY_PACKAGE_HASH_MISMATCH")


def failed_path(paths: ReadyRetryPaths, package_id: str) -> Path:
    identity(package_id)
    return paths.state / "failed" / f"{package_id}.json"


def find_failed_by_sha(paths: ReadyRetryPaths, expected_sha: str) -> tuple[str, Path]:
    require_sha(expected_sha, "INVALID_FAILED_RECEIPT_SHA")
    root = paths.state / "failed"
    if root.is_symlink() or not root.is_dir():
        raise ReadyRetryError("UNSAFE_FAILED_STATE")
    matches: list[tuple[str, Path]] = []
    for entry in root.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ReadyRetryError("UNSAFE_FAILED_STATE")
        if entry.suffix != ".json":
            raise ReadyRetryError("UNSAFE_FAILED_STATE")
        try:
            identity(entry.stem)
        except ReadyRetryError:
            continue
        data = require_root_state(entry, "INVALID_FAILED_RECEIPT", 65536)
        if hashlib.sha256(data).hexdigest() == expected_sha:
            matches.append((entry.stem, entry))
    if len(matches) != 1:
        raise ReadyRetryError("FAILED_RECEIPT_NOT_UNIQUE")
    return matches[0]


def verify_failure_receipt(
    paths: ReadyRetryPaths, package_id: str, expected_sha: str
) -> tuple[dict, bytes]:
    path = failed_path(paths, package_id)
    data = require_root_state(path, "INVALID_FAILED_RECEIPT", 65536)
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ReadyRetryError("FAILED_RECEIPT_HASH_MISMATCH")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadyRetryError("INVALID_FAILED_RECEIPT") from exc
    expected_keys = {
        "schema",
        "edition",
        "package_id",
        "attempt",
        "revision",
        "failed_at",
        "failed_stage",
        "stages",
    }
    edition, attempt, revision = identity(package_id)
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ReadyRetryError("INVALID_FAILED_RECEIPT")
    if (
        value.get("schema") != "gneu-aihot-ready-failure-v1"
        or value.get("edition") != edition
        or value.get("package_id") != package_id
        or value.get("attempt") != attempt
        or value.get("revision") != revision
        or value.get("failed_stage") != "validate"
    ):
        raise ReadyRetryError("FAILED_RECEIPT_NOT_ELIGIBLE")
    try:
        parse_timestamp(value.get("failed_at"), "INVALID_FAILED_RECEIPT")
    except ResumeError as exc:
        raise ReadyRetryError("INVALID_FAILED_RECEIPT") from exc
    stages = value.get("stages")
    if not isinstance(stages, list) or len(stages) != 1:
        raise ReadyRetryError("FAILED_RECEIPT_NOT_ELIGIBLE")
    stage = stages[0]
    if not isinstance(stage, dict) or set(stage) != {"stage", "returncode", "output"}:
        raise ReadyRetryError("FAILED_RECEIPT_NOT_ELIGIBLE")
    output = stage.get("output")
    if (
        stage.get("stage") != "validate"
        or stage.get("returncode") != 1
        or not isinstance(output, str)
        or not 1 <= len(output.encode("utf-8")) <= 20000
    ):
        raise ReadyRetryError("FAILED_RECEIPT_NOT_ELIGIBLE")
    lines = output.splitlines()
    required_source = (
        "article_date = date.fromisoformat(value) "
        "if isinstance(value, str) else None"
    )
    if (
        not lines
        or lines[-1] != "NameError: name 'date' is not defined"
        or "validate-intake.py" not in output
        or required_source not in output
    ):
        raise ReadyRetryError("FAILED_RUNTIME_FINGERPRINT_MISMATCH")
    return value, data


def no_active_processor(paths: ReadyRetryPaths) -> None:
    markers = (
        b"process-ready.py",
        b"validate-intake.py",
        b"build-intake-payload.py",
        b"dispatch-trusted-intake.py",
    )
    if paths.proc_root.is_symlink() or not paths.proc_root.is_dir():
        raise ReadyRetryError("INVALID_PROCESS_STATE")
    for process in paths.proc_root.glob("[0-9]*"):
        if process.name == str(os.getpid()):
            continue
        try:
            command = (process / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(marker in command for marker in markers):
            raise ReadyRetryError("ACTIVE_READY_PROCESSOR")


@contextmanager
def process_ready_lock(paths: ReadyRetryPaths):
    path = paths.state / "process-ready.lock"
    if path.is_symlink() or not path.is_file():
        raise ReadyRetryError("INVALID_PROCESS_READY_LOCK")
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise ReadyRetryError("INVALID_PROCESS_READY_LOCK")
    if (metadata.st_mode & 0o777) != 0o600:
        raise ReadyRetryError("INVALID_PROCESS_READY_LOCK")
    with path.open("r+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReadyRetryError("ACTIVE_READY_PROCESSOR") from exc
        yield


def validator_fix_present(path: Path) -> bool:
    try:
        tree = ast.parse(require_regular(path, "INVALID_RUNTIME_PROVENANCE", 65536))
    except (SyntaxError, UnicodeDecodeError):
        return False
    imported = any(
        isinstance(node, ast.Import)
        and any(alias.name == "datetime" and alias.asname == "dt" for alias in node.names)
        for node in tree.body
    )
    fixed_call = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fromisoformat"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "date"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "dt"
        for node in ast.walk(tree)
    )
    return imported and fixed_call


def verify_runtime_provenance(
    paths: ReadyRetryPaths, expected_source_commit: str
) -> dict:
    if not COMMIT_RE.fullmatch(expected_source_commit):
        raise ReadyRetryError("INVALID_RUNTIME_SOURCE_COMMIT")
    data = require_root_state(paths.provenance, "INVALID_RUNTIME_PROVENANCE", 2 * 1024 * 1024)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadyRetryError("INVALID_RUNTIME_PROVENANCE") from exc
    if not isinstance(value, dict) or value.get("schema") != "gneu-aihot-runtime-provenance-v1":
        raise ReadyRetryError("INVALID_RUNTIME_PROVENANCE")
    if value.get("source_commit") != expected_source_commit:
        raise ReadyRetryError("RUNTIME_SOURCE_COMMIT_MISMATCH")
    if not SHA256_RE.fullmatch(str(value.get("manifest_sha256") or "")):
        raise ReadyRetryError("INVALID_RUNTIME_PROVENANCE")
    files = value.get("files")
    if not isinstance(files, dict):
        raise ReadyRetryError("INVALID_RUNTIME_PROVENANCE")
    for relative, (filename, mode) in REQUIRED_RUNTIME.items():
        entry = files.get(relative)
        runtime_path = paths.bin_dir / filename
        raw = require_regular(runtime_path, "INVALID_RUNTIME_PROVENANCE", 2 * 1024 * 1024)
        if (
            not isinstance(entry, dict)
            or entry.get("destination") != str(runtime_path)
            or entry.get("mode") != mode
            or entry.get("sha256") != hashlib.sha256(raw).hexdigest()
        ):
            raise ReadyRetryError("INVALID_RUNTIME_PROVENANCE")
    if not validator_fix_present(paths.bin_dir / "validate-intake.py"):
        raise ReadyRetryError("VALIDATOR_FIX_NOT_PRESENT")
    return value


def require_no_downstream(paths: ReadyRetryPaths, package_id: str) -> None:
    if os.path.lexists(paths.state / "processed" / f"{package_id}.json"):
        raise ReadyRetryError("READY_RETRY_PROCESSED_EXISTS")
    if os.path.lexists(paths.state / "intake" / f"{package_id}.transport.json"):
        raise ReadyRetryError("READY_RETRY_TRANSPORT_EXISTS")


def authorization_values(
    package_id: str,
    hashes: dict[str, str],
    failed_sha: str,
    runtime_source_commit: str,
) -> dict:
    edition, attempt, revision = identity(package_id)
    return {
        "package_id": package_id,
        "edition": edition,
        "attempt": attempt,
        "revision": revision,
        "candidate_sha256": hashes["candidate"],
        "handoff_sha256": hashes["handoff"],
        "report_sha256": hashes["report"],
        "ready_sha256": hashes["ready"],
        "failed_receipt_sha256": failed_sha,
        "failed_stage": "validate",
        "failure_class": FAILURE_CLASS,
        "runtime_source_commit": runtime_source_commit,
        "reason": REASON,
    }


def load_authorization(
    paths: ReadyRetryPaths,
    package_id: str,
    hashes: dict[str, str],
    failed_sha: str,
) -> tuple[dict, bytes]:
    value, data = load_canonical(
        authorization_path(paths, package_id),
        AUTHORIZATION_KEYS,
        "gneu-aihot-ready-retry-authorization-v1",
        "INVALID_READY_RETRY_AUTHORIZATION",
    )
    expected = authorization_values(
        package_id, hashes, failed_sha, value.get("runtime_source_commit")
    )
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ReadyRetryError("READY_RETRY_AUTHORIZATION_BINDING_MISMATCH")
    try:
        parse_timestamp(value.get("authorized_at"), "INVALID_READY_RETRY_AUTHORIZATION")
    except ResumeError as exc:
        raise ReadyRetryError("INVALID_READY_RETRY_AUTHORIZATION") from exc
    return value, data


def load_consumed(
    paths: ReadyRetryPaths,
    package_id: str,
    authorization: dict,
    authorization_sha: str,
) -> tuple[dict, bytes]:
    value, data = load_canonical(
        consumed_path(paths, package_id),
        CONSUMED_KEYS,
        "gneu-aihot-ready-retry-consumed-v1",
        "INVALID_READY_RETRY_CONSUMED",
    )
    for key in AUTHORIZATION_KEYS - {"schema"}:
        if value.get(key) != authorization.get(key):
            raise ReadyRetryError("READY_RETRY_CONSUMED_BINDING_MISMATCH")
    if value.get("authorization_sha256") != authorization_sha:
        raise ReadyRetryError("READY_RETRY_CONSUMED_BINDING_MISMATCH")
    try:
        authorized_at = parse_timestamp(
            authorization.get("authorized_at"), "INVALID_READY_RETRY_CONSUMED"
        )
        consumed_at = parse_timestamp(
            value.get("consumed_at"), "INVALID_READY_RETRY_CONSUMED"
        )
    except ResumeError as exc:
        raise ReadyRetryError("INVALID_READY_RETRY_CONSUMED") from exc
    if consumed_at < authorized_at:
        raise ReadyRetryError("INVALID_READY_RETRY_CONSUMED")
    return value, data


def authorize(
    paths: ReadyRetryPaths,
    failed_sha: str,
    expected_hashes: dict[str, str],
    expected_source_commit: str,
    reason: str,
    now: dt.datetime | None = None,
) -> tuple[dict, str]:
    if os.geteuid() != 0 or reason != REASON:
        raise ReadyRetryError("INVALID_READY_RETRY_REQUEST")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ReadyRetryError("INVALID_TIME")
    with process_ready_lock(paths):
        package_id, _ = find_failed_by_sha(paths, failed_sha)
        verify_failure_receipt(paths, package_id, failed_sha)
        hashes = package_hashes(paths, package_id)
        expected_hashes_match(hashes, expected_hashes)
        require_no_downstream(paths, package_id)
        no_active_processor(paths)
        verify_runtime_provenance(paths, expected_source_commit)
        for path, code in (
            (authorization_path(paths, package_id), "READY_RETRY_AUTHORIZATION_EXISTS"),
            (consumed_path(paths, package_id), "READY_RETRY_CONSUMED_EXISTS"),
            (retry_failure_path(paths, package_id), "READY_RETRY_FAILURE_EXISTS"),
        ):
            if os.path.lexists(path):
                raise ReadyRetryError(code)
        value = {
            "schema": "gneu-aihot-ready-retry-authorization-v1",
            **authorization_values(
                package_id, hashes, failed_sha, expected_source_commit
            ),
            "authorized_at": now.astimezone(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }
        receipt_sha = create_receipt(
            authorization_path(paths, package_id), value
        )
    return value, receipt_sha


def verify_authorization(
    paths: ReadyRetryPaths,
    failed_sha: str,
    expected_hashes: dict[str, str],
    expected_source_commit: str,
) -> tuple[dict, str]:
    package_id, _ = find_failed_by_sha(paths, failed_sha)
    verify_failure_receipt(paths, package_id, failed_sha)
    hashes = package_hashes(paths, package_id)
    expected_hashes_match(hashes, expected_hashes)
    verify_runtime_provenance(paths, expected_source_commit)
    value, data = load_authorization(paths, package_id, hashes, failed_sha)
    if value.get("runtime_source_commit") != expected_source_commit:
        raise ReadyRetryError("RUNTIME_SOURCE_COMMIT_MISMATCH")
    return value, sha256_bytes(data)


def consume_for_processing(
    paths: ReadyRetryPaths,
    package_id: str,
    now: dt.datetime | None = None,
) -> dict | None:
    now = now or dt.datetime.now(dt.timezone.utc)
    auth_path = authorization_path(paths, package_id)
    receipt_path = consumed_path(paths, package_id)
    retry_failed_path = retry_failure_path(paths, package_id)
    if not os.path.lexists(auth_path):
        if os.path.lexists(receipt_path) or os.path.lexists(retry_failed_path):
            raise ReadyRetryError("READY_RETRY_STATE_WITHOUT_AUTHORIZATION")
        return None
    failed_data = require_root_state(
        failed_path(paths, package_id), "INVALID_FAILED_RECEIPT", 65536
    )
    failed_sha = hashlib.sha256(failed_data).hexdigest()
    verify_failure_receipt(paths, package_id, failed_sha)
    hashes = package_hashes(paths, package_id)
    authorization, authorization_data = load_authorization(
        paths, package_id, hashes, failed_sha
    )
    verify_runtime_provenance(paths, authorization["runtime_source_commit"])
    require_no_downstream(paths, package_id)
    authorization_sha = sha256_bytes(authorization_data)
    if os.path.lexists(retry_failed_path):
        raise ReadyRetryError("READY_RETRY_ALREADY_FAILED")
    if os.path.lexists(receipt_path):
        load_consumed(paths, package_id, authorization, authorization_sha)
        raise ReadyRetryError("READY_RETRY_ALREADY_CONSUMED")
    value = {
        **authorization,
        "schema": "gneu-aihot-ready-retry-consumed-v1",
        "authorization_sha256": authorization_sha,
        "consumed_at": now.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }
    consumed_sha = create_receipt(receipt_path, value)
    return {
        "package_id": package_id,
        "edition": authorization["edition"],
        "attempt": authorization["attempt"],
        "revision": authorization["revision"],
        "failed_receipt_sha256": failed_sha,
        "authorization_sha256": authorization_sha,
        "consumed_sha256": consumed_sha,
        "failure_class": authorization["failure_class"],
    }


def verify_consumed(
    paths: ReadyRetryPaths,
    failed_sha: str,
    expected_hashes: dict[str, str],
    expected_source_commit: str,
) -> tuple[dict, str]:
    authorization, authorization_sha = verify_authorization(
        paths, failed_sha, expected_hashes, expected_source_commit
    )
    package_id = authorization["package_id"]
    consumed, data = load_consumed(
        paths, package_id, authorization, authorization_sha
    )
    return consumed, sha256_bytes(data)


def record_retry_failure(
    paths: ReadyRetryPaths,
    recovery: dict,
    failed_stage: str,
    failure_code: str,
    stages: list[dict],
    now: dt.datetime | None = None,
) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    package_id = recovery["package_id"]
    edition, attempt, revision = identity(package_id)
    if not isinstance(failed_stage, str) or not failed_stage:
        raise ReadyRetryError("INVALID_READY_RETRY_FAILURE")
    if not isinstance(failure_code, str) or not re.fullmatch(r"[A-Z0-9_]{1,80}", failure_code):
        raise ReadyRetryError("INVALID_READY_RETRY_FAILURE")
    if not isinstance(stages, list) or len(stages) > 3:
        raise ReadyRetryError("INVALID_READY_RETRY_FAILURE")
    for stage in stages:
        if (
            not isinstance(stage, dict)
            or set(stage) != {"stage", "returncode", "output"}
            or stage.get("stage") not in {"validate", "build", "dispatch"}
            or not isinstance(stage.get("returncode"), int)
            or not isinstance(stage.get("output"), str)
            or len(stage["output"].encode("utf-8")) > 20000
        ):
            raise ReadyRetryError("INVALID_READY_RETRY_FAILURE")
    value = {
        "schema": "gneu-aihot-ready-retry-failure-v1",
        "package_id": package_id,
        "edition": edition,
        "attempt": attempt,
        "revision": revision,
        "original_failed_receipt_sha256": recovery["failed_receipt_sha256"],
        "authorization_sha256": recovery["authorization_sha256"],
        "consumed_sha256": recovery["consumed_sha256"],
        "failed_at": now.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "failed_stage": failed_stage,
        "failure_code": failure_code,
        "stages": stages,
    }
    return create_receipt(retry_failure_path(paths, package_id), value)


def processed_lineage_fields(recovery: dict) -> dict[str, str]:
    return {
        "ready_retry_failed_sha256": recovery["failed_receipt_sha256"],
        "ready_retry_authorization_sha256": recovery["authorization_sha256"],
        "ready_retry_consumed_sha256": recovery["consumed_sha256"],
        "ready_retry_failure_class": recovery["failure_class"],
    }


def verify_processed_lineage(
    paths: ReadyRetryPaths, package_id: str, processed: dict
) -> None:
    edition, attempt, revision = identity(package_id)
    expected_keys = {
        "schema",
        "edition",
        "package_id",
        "attempt",
        "revision",
        "processed_at",
        "base_main_sha",
        "payload_sha256",
        "mode",
        "result",
        *RECOVERY_PROCESSED_KEYS,
    }
    if not isinstance(processed, dict) or set(processed) != expected_keys:
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
    if (
        processed.get("schema") != "gneu-aihot-ready-processed-v1"
        or processed.get("edition") != edition
        or processed.get("package_id") != package_id
        or processed.get("attempt") != attempt
        or processed.get("revision") != revision
        or processed.get("result") != "success"
        or processed.get("mode") not in {"edition", "no-change"}
        or not re.fullmatch(r"[0-9a-f]{40}", str(processed.get("base_main_sha") or ""))
        or not SHA256_RE.fullmatch(str(processed.get("payload_sha256") or ""))
    ):
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
    try:
        parse_timestamp(processed.get("processed_at"), "INVALID_PROCESSED_LINEAGE")
    except ResumeError as exc:
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE") from exc
    if os.path.lexists(retry_failure_path(paths, package_id)):
        raise ReadyRetryError("PROCESSED_WITH_RETRY_FAILURE")
    failed_data = require_root_state(
        failed_path(paths, package_id), "INVALID_FAILED_RECEIPT", 65536
    )
    failed_sha = hashlib.sha256(failed_data).hexdigest()
    verify_failure_receipt(paths, package_id, failed_sha)
    hashes = package_hashes(paths, package_id)
    authorization, authorization_data = load_authorization(
        paths, package_id, hashes, failed_sha
    )
    authorization_sha = sha256_bytes(authorization_data)
    consumed, consumed_data = load_consumed(
        paths, package_id, authorization, authorization_sha
    )
    expected = {
        "ready_retry_failed_sha256": failed_sha,
        "ready_retry_authorization_sha256": authorization_sha,
        "ready_retry_consumed_sha256": sha256_bytes(consumed_data),
        "ready_retry_failure_class": FAILURE_CLASS,
    }
    if any(processed.get(key) != value for key, value in expected.items()):
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
    try:
        processed_at = parse_timestamp(
            processed.get("processed_at"), "INVALID_PROCESSED_LINEAGE"
        )
        consumed_at = parse_timestamp(
            consumed.get("consumed_at"), "INVALID_PROCESSED_LINEAGE"
        )
    except ResumeError as exc:
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE") from exc
    if processed_at < consumed_at:
        raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
