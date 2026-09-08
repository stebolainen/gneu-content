"""Append-only terminal dispositions for three verified historical READY blockers."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from aihot_package_identity import parse_package_id


SCHEMA = "gneu-aihot-historical-terminal-disposition-v1"
DISPOSITION = "historical_terminal"
STATUS = "closed_non_actionable"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{8,500}$")
MAX_RECEIPT_SIZE = 32768


class HistoricalDispositionError(RuntimeError):
    """A bounded, non-secret historical-disposition policy failure."""


@dataclass(frozen=True)
class HistoricalCase:
    package_id: str
    failure_code: str
    failure_stage: str
    failure_detail: str
    evidence_names: tuple[str, ...]


COMMON_EVIDENCE = (
    "failed_sha256",
    "ready_sha256",
    "handoff_sha256",
    "candidate_sha256",
    "report_sha256",
)

HISTORICAL_CASES = {
    "2026-W36--2026-09-04--r1": HistoricalCase(
        package_id="2026-W36--2026-09-04--r1",
        failure_code="RUNTIME_SOURCE_COMMIT_MISMATCH",
        failure_stage="ready-retry-lineage",
        failure_detail="RUNTIME_SOURCE_COMMIT_MISMATCH",
        evidence_names=COMMON_EVIDENCE
        + (
            "local_retry_authorization_sha256",
            "local_retry_consumed_sha256",
            "ready_retry_authorization_sha256",
            "ready_retry_consumed_sha256",
            "ready_retry_failure_sha256",
        ),
    ),
    "2026-W36--2026-09-04--r2": HistoricalCase(
        package_id="2026-W36--2026-09-04--r2",
        failure_code="INVALID_RUNTIME_PROVENANCE",
        failure_stage="content-retry-lineage",
        failure_detail="INVALID_RUNTIME_PROVENANCE",
        evidence_names=COMMON_EVIDENCE
        + (
            "content_retry_authorization_sha256",
            "content_retry_consumed_sha256",
        ),
    ),
    "2026-W37--2026-09-07": HistoricalCase(
        package_id="2026-W37--2026-09-07",
        failure_code="CANDIDATE_EDITION_PREFIX_DIFFERS_FROM_ORIGIN_MAIN",
        failure_stage="build",
        failure_detail="candidate edition prefix differs from origin/main",
        evidence_names=COMMON_EVIDENCE,
    ),
}


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def require_safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_TEXT_RE.fullmatch(value):
        raise HistoricalDispositionError(f"INVALID_{label.upper()}")
    lowered = value.lower()
    secret_markers = (
        "bearer ",
        "private key",
        "github" + "_pat_",
        "gh" + "p_",
    )
    if any(token in lowered for token in secret_markers):
        raise HistoricalDispositionError(f"SECRET_LIKE_{label.upper()}_FORBIDDEN")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise HistoricalDispositionError(f"INVALID_{label.upper()}")
    return value


def read_regular(path: Path, label: str, maximum: int = MAX_RECEIPT_SIZE) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise HistoricalDispositionError(f"MISSING_{label.upper()}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HistoricalDispositionError(f"INVALID_{label.upper()}")
    if before.st_uid != os.geteuid() or before.st_mode & 0o022:
        raise HistoricalDispositionError(f"UNSAFE_{label.upper()}_MODE")
    if before.st_size < 1 or before.st_size > maximum:
        raise HistoricalDispositionError(f"INVALID_{label.upper()}_SIZE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HistoricalDispositionError(f"UNSAFE_{label.upper()}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise HistoricalDispositionError(f"CHANGED_{label.upper()}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise HistoricalDispositionError(f"INVALID_{label.upper()}_SIZE")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise HistoricalDispositionError(f"CHANGED_{label.upper()}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_json(path: Path, label: str) -> tuple[dict, bytes]:
    raw = read_regular(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HistoricalDispositionError(f"INVALID_{label.upper()}_JSON") from exc
    if not isinstance(value, dict):
        raise HistoricalDispositionError(f"INVALID_{label.upper()}_JSON")
    return value, raw


def hash_file(path: Path, label: str) -> str:
    return hashlib.sha256(read_regular(path, label, 5 * 1024 * 1024)).hexdigest()


def disposition_path(state_root: Path, package_id: str) -> Path:
    return state_root / "historical-terminal-dispositions" / f"{package_id}.json"


@contextmanager
def exclusive_process_lock(state_root: Path) -> Iterator[None]:
    lock_path = state_root / "process-ready.lock"
    try:
        metadata = lock_path.lstat()
    except FileNotFoundError as exc:
        raise HistoricalDispositionError("MISSING_PROCESS_LOCK") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise HistoricalDispositionError("INVALID_PROCESS_LOCK")
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HistoricalDispositionError("READY_PROCESSOR_ACTIVE") from exc
        yield
    finally:
        os.close(descriptor)


def evidence_paths(state_root: Path, outbox_root: Path, case: HistoricalCase) -> dict[str, Path]:
    edition, attempt, revision = parse_package_id(case.package_id)
    package = outbox_root / case.package_id
    paths = {
        "failed_sha256": state_root / "failed" / f"{case.package_id}.json",
        "ready_sha256": package / "READY",
        "handoff_sha256": package / "handoff.json",
        "candidate_sha256": package / "candidate.json",
        "report_sha256": package / "report.md",
    }
    if revision == 1:
        assert attempt is not None
        paths.update(
            {
                "local_retry_authorization_sha256": state_root
                / "generation/retry-authorized"
                / f"{attempt}-r1.json",
                "local_retry_consumed_sha256": state_root
                / "generation/retry-consumed"
                / f"{attempt}-r1.json",
                "ready_retry_authorization_sha256": state_root
                / "ready-retry/authorized"
                / f"{case.package_id}.json",
                "ready_retry_consumed_sha256": state_root
                / "ready-retry/consumed"
                / f"{case.package_id}.json",
                "ready_retry_failure_sha256": state_root
                / "ready-retry/failed"
                / f"{case.package_id}.json",
            }
        )
    elif revision == 2:
        assert attempt is not None
        paths.update(
            {
                "content_retry_authorization_sha256": state_root
                / "generation/retry-authorized"
                / f"{attempt}-r2.json",
                "content_retry_consumed_sha256": state_root
                / "generation/retry-consumed"
                / f"{attempt}-r2.json",
            }
        )
    if set(paths) != set(case.evidence_names):
        raise HistoricalDispositionError("INTERNAL_EVIDENCE_POLICY_MISMATCH")
    return paths


def require_identity(
    value: dict, package_id: str, label: str, field: str = "package_id"
) -> None:
    if value.get(field) != package_id:
        raise HistoricalDispositionError(f"{label.upper()}_PACKAGE_MISMATCH")


def verify_historical_failure(
    case: HistoricalCase, state_root: Path, evidence_values: dict[str, dict]
) -> None:
    failed = evidence_values["failed_sha256"]
    require_identity(failed, case.package_id, "failed")
    if failed.get("schema") != "gneu-aihot-ready-failure-v1":
        raise HistoricalDispositionError("FAILED_SCHEMA_MISMATCH")

    if case.failure_stage == "build":
        if failed.get("failed_stage") != "build":
            raise HistoricalDispositionError("FAILURE_STAGE_MISMATCH")
        stages = failed.get("stages")
        if not isinstance(stages, list) or not stages:
            raise HistoricalDispositionError("FAILURE_EVIDENCE_MISSING")
        build = stages[-1]
        if (
            not isinstance(build, dict)
            or build.get("stage") != "build"
            or not isinstance(build.get("returncode"), int)
            or build["returncode"] == 0
        ):
            raise HistoricalDispositionError("FAILURE_EVIDENCE_MISMATCH")
        output = build.get("output")
        expected_line = f"BLOCKED: {case.failure_detail}"
        if not isinstance(output, str) or expected_line not in output.splitlines():
            raise HistoricalDispositionError("FAILURE_CODE_MISMATCH")
        return

    if case.package_id.endswith("--r1"):
        local_authorized = evidence_values["local_retry_authorization_sha256"]
        local_consumed = evidence_values["local_retry_consumed_sha256"]
        ready_authorized = evidence_values["ready_retry_authorization_sha256"]
        ready_consumed = evidence_values["ready_retry_consumed_sha256"]
        ready_failed = evidence_values["ready_retry_failure_sha256"]
        require_identity(
            local_authorized,
            case.package_id,
            "local retry authorization",
            "target_package_id",
        )
        require_identity(
            local_consumed,
            case.package_id,
            "local retry consumed",
            "target_package_id",
        )
        for value, label in (
            (ready_authorized, "ready retry authorization"),
            (ready_consumed, "ready retry consumed"),
            (ready_failed, "ready retry failure"),
        ):
            require_identity(value, case.package_id, label)
        if ready_failed.get("schema") != "gneu-aihot-ready-retry-failure-v1":
            raise HistoricalDispositionError("READY_RETRY_FAILURE_SCHEMA_MISMATCH")
        if ready_failed.get("failure_code") != "DISPATCH_FAILED":
            raise HistoricalDispositionError("READY_RETRY_FAILURE_CODE_MISMATCH")
        if ready_authorized.get("runtime_source_commit") == ready_consumed.get(
            "runtime_source_commit"
        ) and ready_authorized.get("runtime_source_commit"):
            return
        raise HistoricalDispositionError("READY_RETRY_LINEAGE_MISMATCH")

    if case.package_id.endswith("--r2"):
        authorized = evidence_values["content_retry_authorization_sha256"]
        consumed = evidence_values["content_retry_consumed_sha256"]
        for value, label in (
            (authorized, "content retry authorization"),
            (consumed, "content retry consumed"),
        ):
            require_identity(value, case.package_id, label, "target_package_id")
        if authorized.get("runtime_source_commit") != consumed.get("runtime_source_commit"):
            raise HistoricalDispositionError("CONTENT_RETRY_LINEAGE_MISMATCH")
        if authorized.get("reason") != "TRUSTED_CONTENT_CONTRACT_MISSING_EVIDENCE":
            raise HistoricalDispositionError("CONTENT_RETRY_REASON_MISMATCH")
        return

    raise HistoricalDispositionError("UNSUPPORTED_HISTORICAL_FAILURE")


def recompute_evidence(
    case: HistoricalCase, state_root: Path, outbox_root: Path
) -> dict[str, str]:
    processed = state_root / "processed" / f"{case.package_id}.json"
    if processed.exists() or processed.is_symlink():
        raise HistoricalDispositionError("PROCESSED_STATE_CONFLICT")
    paths = evidence_paths(state_root, outbox_root, case)
    values: dict[str, dict] = {}
    hashes: dict[str, str] = {}
    for name, path in paths.items():
        raw = read_regular(path, name, 5 * 1024 * 1024)
        hashes[name] = hashlib.sha256(raw).hexdigest()
        if name.endswith("authorization_sha256") or name.endswith("consumed_sha256") or name in {
            "failed_sha256",
            "ready_retry_failure_sha256",
        }:
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HistoricalDispositionError(f"INVALID_{name.upper()}_JSON") from exc
            if not isinstance(value, dict):
                raise HistoricalDispositionError(f"INVALID_{name.upper()}_JSON")
            values[name] = value
    verify_historical_failure(case, state_root, values)
    return hashes


def receipt_identity(case: HistoricalCase) -> dict[str, object]:
    edition, attempt, revision = parse_package_id(case.package_id)
    return {
        "package_id": case.package_id,
        "edition": edition,
        "attempt": attempt,
        "revision": revision,
    }


def parse_timestamp(value: object) -> None:
    if not isinstance(value, str):
        raise HistoricalDispositionError("INVALID_DISPOSED_AT")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HistoricalDispositionError("INVALID_DISPOSED_AT") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise HistoricalDispositionError("INVALID_DISPOSED_AT")


def validate_receipt_shape(receipt: dict, case: HistoricalCase) -> None:
    expected_keys = {
        "schema",
        "disposition",
        "status",
        "retry_allowed",
        "package_id",
        "edition",
        "attempt",
        "revision",
        "failure_code",
        "failure_stage",
        "failure_detail",
        "evidence_sha256",
        "human_approval",
        "operator_reason",
        "disposed_at",
    }
    if set(receipt) != expected_keys:
        raise HistoricalDispositionError("RECEIPT_KEYS_MISMATCH")
    if (
        receipt.get("schema") != SCHEMA
        or receipt.get("disposition") != DISPOSITION
        or receipt.get("status") != STATUS
        or receipt.get("retry_allowed") is not False
    ):
        raise HistoricalDispositionError("RECEIPT_POLICY_MISMATCH")
    for key, value in receipt_identity(case).items():
        if receipt.get(key) != value:
            raise HistoricalDispositionError("RECEIPT_IDENTITY_MISMATCH")
    if (
        receipt.get("failure_code") != case.failure_code
        or receipt.get("failure_stage") != case.failure_stage
        or receipt.get("failure_detail") != case.failure_detail
    ):
        raise HistoricalDispositionError("RECEIPT_FAILURE_MISMATCH")
    evidence = receipt.get("evidence_sha256")
    if not isinstance(evidence, dict) or set(evidence) != set(case.evidence_names):
        raise HistoricalDispositionError("RECEIPT_EVIDENCE_KEYS_MISMATCH")
    for name, value in evidence.items():
        require_sha256(value, name)
    require_safe_text(receipt.get("human_approval"), "human_approval")
    require_safe_text(receipt.get("operator_reason"), "operator_reason")
    parse_timestamp(receipt.get("disposed_at"))


def verify_receipt(
    package_id: str, *, state_root: Path, outbox_root: Path
) -> dict:
    case = HISTORICAL_CASES.get(package_id)
    if case is None:
        raise HistoricalDispositionError("PACKAGE_NOT_HISTORICALLY_ALLOWLISTED")
    path = disposition_path(state_root, package_id)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise HistoricalDispositionError("MISSING_HISTORICAL_DISPOSITION") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (metadata.st_mode & 0o777) != 0o600
    ):
        raise HistoricalDispositionError("INVALID_HISTORICAL_DISPOSITION_MODE")
    receipt, raw = read_json(path, "historical disposition")
    if raw != canonical_json(receipt):
        raise HistoricalDispositionError("NONCANONICAL_HISTORICAL_DISPOSITION")
    validate_receipt_shape(receipt, case)
    if receipt["evidence_sha256"] != recompute_evidence(case, state_root, outbox_root):
        raise HistoricalDispositionError("EVIDENCE_HASH_MISMATCH")
    return receipt


def find_verified_disposition(
    package_id: str, *, state_root: Path, outbox_root: Path
) -> dict | None:
    directory = state_root / "historical-terminal-dispositions"
    if directory.is_symlink():
        raise HistoricalDispositionError("INVALID_DISPOSITION_DIRECTORY")
    if not directory.exists():
        return None
    if not directory.is_dir():
        raise HistoricalDispositionError("INVALID_DISPOSITION_DIRECTORY")
    metadata = directory.stat()
    if metadata.st_uid != os.geteuid() or (metadata.st_mode & 0o777) != 0o700:
        raise HistoricalDispositionError("INVALID_DISPOSITION_DIRECTORY_MODE")
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".json":
            raise HistoricalDispositionError("INVALID_DISPOSITION_ENTRY")
        if entry.stem not in HISTORICAL_CASES:
            raise HistoricalDispositionError("UNKNOWN_DISPOSITION_ENTRY")
    path = disposition_path(state_root, package_id)
    if not path.exists():
        return None
    return verify_receipt(package_id, state_root=state_root, outbox_root=outbox_root)


def append_disposition(
    package_id: str,
    failure_code: str,
    evidence_sha256: dict[str, str],
    human_approval: str,
    operator_reason: str,
    *,
    state_root: Path,
    outbox_root: Path,
    now: Callable[[], dt.datetime] | None = None,
) -> str:
    case = HISTORICAL_CASES.get(package_id)
    if case is None:
        raise HistoricalDispositionError("PACKAGE_NOT_HISTORICALLY_ALLOWLISTED")
    if failure_code != case.failure_code:
        raise HistoricalDispositionError("FAILURE_CODE_MISMATCH")
    if set(evidence_sha256) != set(case.evidence_names):
        raise HistoricalDispositionError("EVIDENCE_KEYS_MISMATCH")
    supplied = {
        name: require_sha256(value, name) for name, value in evidence_sha256.items()
    }
    approval = require_safe_text(human_approval, "human_approval")
    reason = require_safe_text(operator_reason, "operator_reason")
    with exclusive_process_lock(state_root):
        computed = recompute_evidence(case, state_root, outbox_root)
        if supplied != computed:
            raise HistoricalDispositionError("EVIDENCE_HASH_MISMATCH")
        directory = state_root / "historical-terminal-dispositions"
        try:
            directory.mkdir(mode=0o700)
            parent_fd = os.open(state_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except FileExistsError:
            pass
        if directory.is_symlink() or not directory.is_dir():
            raise HistoricalDispositionError("INVALID_DISPOSITION_DIRECTORY")
        metadata = directory.stat()
        if metadata.st_uid != os.geteuid() or (metadata.st_mode & 0o777) != 0o700:
            raise HistoricalDispositionError("INVALID_DISPOSITION_DIRECTORY_MODE")
        path = disposition_path(state_root, package_id)
        if path.exists() or path.is_symlink():
            existing = verify_receipt(
                package_id, state_root=state_root, outbox_root=outbox_root
            )
            if (
                existing["failure_code"] == failure_code
                and existing["evidence_sha256"] == supplied
                and existing["human_approval"] == approval
                and existing["operator_reason"] == reason
            ):
                return "ALREADY_HISTORICAL_TERMINAL"
            raise HistoricalDispositionError("CONFLICTING_HISTORICAL_DISPOSITION")
        timestamp = (now or (lambda: dt.datetime.now(dt.timezone.utc)))()
        if timestamp.tzinfo is None or timestamp.utcoffset() != dt.timedelta(0):
            raise HistoricalDispositionError("INVALID_DISPOSITION_CLOCK")
        receipt = {
            "schema": SCHEMA,
            "disposition": DISPOSITION,
            "status": STATUS,
            "retry_allowed": False,
            **receipt_identity(case),
            "failure_code": case.failure_code,
            "failure_stage": case.failure_stage,
            "failure_detail": case.failure_detail,
            "evidence_sha256": supplied,
            "human_approval": approval,
            "operator_reason": reason,
            "disposed_at": timestamp.replace(microsecond=0).isoformat(),
        }
        raw = canonical_json(receipt)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=directory
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError as exc:
                raise HistoricalDispositionError(
                    "CONCURRENT_HISTORICAL_DISPOSITION"
                ) from exc
            directory_fd = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        verify_receipt(package_id, state_root=state_root, outbox_root=outbox_root)
        return "HISTORICAL_TERMINAL_DISPOSED"
