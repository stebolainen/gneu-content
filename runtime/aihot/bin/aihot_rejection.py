#!/usr/bin/env python3
"""Fail-closed verification and creation of AI-hot rejection receipts."""

from __future__ import annotations

import base64
import datetime as dt
import fcntl
import gzip
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator


BRIDGE = Path("/root/gneu-aihot-bridge")
STATE_ROOT = BRIDGE / "state"
OUTBOX_ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")

REJECTION_SCHEMA = "gneu-aihot-rejection-v1"
FAILURE_SCHEMA = "gneu-aihot-ready-failure-v1"
HANDOFF_SCHEMA = "gneu-aihot-handoff-v1"
FAILURE_REASON_ALLOWLIST = frozenset({"ARTICLE_DATE_OUTSIDE_EDITION"})

WEEK_RE = re.compile(r"^(20\d{2})-W(0[1-9]|[1-4]\d|5[0-3])$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[1-9]\d*$")
SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{8,500}$")
SECRET_MARKERS = (
    "-----BEGIN ",
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "Bearer ",
)

RECEIPT_KEYS = {
    "schema",
    "disposition",
    "edition",
    "rejected_at",
    "disposition_reason",
    "failing_article",
    "article_date",
    "article_iso_year",
    "article_iso_week",
    "failure_reason_code",
    "validator_failure",
    "failed_state_sha256",
    "ready_sha256",
    "handoff_sha256",
    "candidate_sha256",
    "report_sha256",
    "transport_sha256",
    "payload_sha256",
    "base_main_sha",
    "github_run_id",
    "github_conclusion",
    "workflow_head_sha",
    "machine_verified_local_evidence",
    "operator_attested_remote_evidence",
    "article_ids",
}


class RejectionError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise RejectionError(f"missing {label}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise RejectionError(f"symlink forbidden: {label}")
    return metadata


def require_directory(path: Path, label: str, *, private: bool = True) -> None:
    metadata = _lstat(path, label)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RejectionError(f"not a directory: {label}")
    forbidden_mode = 0o077 if private else 0o022
    if metadata.st_mode & forbidden_mode:
        raise RejectionError(f"directory permissions too broad: {label}")
    if metadata.st_uid != os.geteuid():
        raise RejectionError(f"unexpected directory owner: {label}")


def path_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def read_regular(path: Path, label: str, maximum: int = 5 * 1024 * 1024) -> bytes:
    metadata = _lstat(path, label)
    if not stat.S_ISREG(metadata.st_mode):
        raise RejectionError(f"not a regular file: {label}")
    if metadata.st_size < 0 or metadata.st_size > maximum:
        raise RejectionError(f"invalid file size: {label}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RejectionError(f"cannot safely open {label}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RejectionError(f"not a regular file: {label}")
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RejectionError(f"file changed while opening: {label}")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > maximum:
            raise RejectionError(f"invalid file size: {label}")
        if (
            len(raw) != opened.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise RejectionError(f"file changed while reading: {label}")
        return raw
    finally:
        os.close(descriptor)


def load_json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RejectionError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        raise RejectionError(f"JSON object required: {label}")
    return value


def parse_edition(edition: str) -> tuple[int, int]:
    match = WEEK_RE.fullmatch(edition)
    if not match:
        raise RejectionError("invalid edition")
    year, week = (int(part) for part in match.groups())
    try:
        dt.date.fromisocalendar(year, week, 1)
    except ValueError as exc:
        raise RejectionError("invalid ISO edition") from exc
    return year, week


def require_sha(value: str, label: str, pattern: re.Pattern[str] = SHA256_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RejectionError(f"invalid {label}")
    return value


def require_safe_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not SAFE_TEXT_RE.fullmatch(value):
        raise RejectionError(f"invalid {label}")
    if any(marker.lower() in value.lower() for marker in SECRET_MARKERS):
        raise RejectionError(f"secret-like data forbidden in {label}")
    return value


def _one_output_value(output: str, name: str, pattern: str) -> str:
    values = re.findall(rf"(?m)^{re.escape(name)}: ({pattern})$", output)
    if len(values) != 1:
        raise RejectionError(f"missing or ambiguous dispatch evidence: {name}")
    return values[0]


def _decode_payload(transport: dict) -> tuple[dict, bytes, bytes]:
    if set(transport) != {
        "edition",
        "mode",
        "base_main_sha",
        "payload_sha256",
        "payload_b64",
    }:
        raise RejectionError("transport schema mismatch")
    encoded = transport.get("payload_b64")
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,55000}", encoded):
        raise RejectionError("invalid encoded payload")
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        compressed = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise RejectionError("payload base64 invalid") from exc
    if len(compressed) > 1024 * 1024:
        raise RejectionError("compressed payload too large")
    if sha256_bytes(compressed) != transport.get("payload_sha256"):
        raise RejectionError("transport payload hash mismatch")
    try:
        raw = gzip.decompress(compressed)
    except Exception as exc:
        raise RejectionError("payload gzip invalid") from exc
    if not raw or len(raw) > 5 * 1024 * 1024:
        raise RejectionError("decoded payload size invalid")
    payload = load_json(raw, "decoded payload")
    expected_raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if raw != expected_raw:
        raise RejectionError("decoded payload is not canonical transport JSON")
    return payload, raw, compressed


def _validate_package(
    edition: str,
    package: Path,
    handoff: dict,
    candidate: dict,
    report_raw: bytes,
    ready_raw: bytes,
    payload: dict,
) -> list[dict]:
    if handoff.get("schema") != HANDOFF_SCHEMA:
        raise RejectionError("handoff schema mismatch")
    if handoff.get("producer") != "adam" or handoff.get("edition") != edition:
        raise RejectionError("handoff identity mismatch")
    if handoff.get("mode") != "edition":
        raise RejectionError("only edition packages are disposition eligible")
    if set(candidate) != {"generated", "editions", "articles"}:
        raise RejectionError("candidate schema mismatch")
    if set(payload) != {
        "version",
        "edition",
        "mode",
        "base_main_sha",
        "base_aihot_sha256",
        "base_generated",
        "delta",
        "report",
    }:
        raise RejectionError("payload schema mismatch")
    if payload.get("version") != 1 or payload.get("edition") != edition:
        raise RejectionError("payload identity mismatch")
    if payload.get("mode") != "edition" or payload.get("mode") != handoff.get("mode"):
        raise RejectionError("payload mode mismatch")
    if payload.get("base_generated") != handoff.get("base_generated"):
        raise RejectionError("payload base generation mismatch")
    if (
        not isinstance(handoff.get("base_sha256"), str)
        or not SHA256_RE.fullmatch(handoff["base_sha256"])
        or payload.get("base_aihot_sha256") != handoff["base_sha256"]
    ):
        raise RejectionError("payload base AI-hot hash mismatch")
    if candidate.get("generated") != payload.get("base_generated"):
        raise RejectionError("candidate generation mismatch")
    delta = payload.get("delta")
    if not isinstance(delta, dict) or set(delta) != {"editions", "articles"}:
        raise RejectionError("payload delta schema mismatch")
    editions = delta.get("editions")
    articles = delta.get("articles")
    if not isinstance(editions, list) or len(editions) != 1:
        raise RejectionError("payload edition delta invalid")
    if not isinstance(editions[0], dict) or editions[0].get("id") != edition:
        raise RejectionError("payload edition mismatch")
    if not isinstance(articles, list) or not 1 <= len(articles) <= 6:
        raise RejectionError("payload article delta invalid")
    candidate_editions = candidate.get("editions")
    candidate_articles = candidate.get("articles")
    if not isinstance(candidate_editions, list) or not isinstance(candidate_articles, list):
        raise RejectionError("candidate arrays invalid")
    if candidate_editions[-len(editions):] != editions:
        raise RejectionError("payload editions do not bind to candidate")
    if candidate_articles[-len(articles):] != articles:
        raise RejectionError("payload articles do not bind to candidate")
    try:
        report = report_raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RejectionError("report is not UTF-8") from exc
    if payload.get("report") != report:
        raise RejectionError("payload report mismatch")
    ready_expected = (
        f"PASS {edition} mode=edition base={handoff.get('base_sha256')}\n"
    ).encode("utf-8")
    if ready_raw != ready_expected:
        raise RejectionError("READY marker mismatch")
    seen: set[str] = set()
    for article in articles:
        if not isinstance(article, dict):
            raise RejectionError("article object required")
        article_id = article.get("id")
        if not isinstance(article_id, str) or not article_id or article_id in seen:
            raise RejectionError("article identity invalid")
        if article.get("edition") != edition:
            raise RejectionError("article edition mismatch")
        seen.add(article_id)
    return articles


def _eligible_failure(edition: str, articles: list[dict]) -> dict:
    edition_year, edition_week = parse_edition(edition)
    for article in articles:
        article_id = article["id"]
        value = article.get("date")
        if not isinstance(value, str):
            raise RejectionError(f"article date missing or invalid: {article_id}")
        try:
            parsed = dt.date.fromisoformat(value)
        except ValueError as exc:
            raise RejectionError(f"article date is not ISO format: {article_id}") from exc
        iso = parsed.isocalendar()
        if (iso.year, iso.week) != (edition_year, edition_week):
            reason = "ARTICLE_DATE_OUTSIDE_EDITION"
            if reason not in FAILURE_REASON_ALLOWLIST:
                raise RejectionError("failure reason is not disposition eligible")
            return {
                "failing_article": article_id,
                "article_date": value,
                "article_iso_year": iso.year,
                "article_iso_week": iso.week,
                "failure_reason_code": reason,
                "validator_failure": (
                    f"{article_id}: article date {value} is outside {edition}"
                ),
            }
    raise RejectionError("no disposition-eligible deterministic failure")


def collect_evidence(
    edition: str,
    *,
    state_root: Path = STATE_ROOT,
    outbox_root: Path = OUTBOX_ROOT,
) -> dict:
    parse_edition(edition)
    require_directory(state_root, "state root")
    require_directory(outbox_root, "outbox root")
    failed_dir = state_root / "failed"
    intake_dir = state_root / "intake"
    require_directory(failed_dir, "failed directory")
    require_directory(intake_dir, "intake directory")

    processed_dir = state_root / "processed"
    if path_present(processed_dir):
        require_directory(processed_dir, "processed directory")
        processed_path = processed_dir / f"{edition}.json"
        if path_present(processed_path):
            _lstat(processed_path, "processed state")
            raise RejectionError("processed state conflicts with rejection")

    package = outbox_root / edition
    require_directory(package, "READY package", private=False)
    names = {entry.name for entry in package.iterdir()}
    required_names = {"READY", "handoff.json", "candidate.json", "report.md"}
    if names != required_names:
        raise RejectionError("READY package file set mismatch")

    failed_path = failed_dir / f"{edition}.json"
    transport_path = intake_dir / f"{edition}.transport.json"
    paths = {
        "failed_state_sha256": (failed_path, "failed latch"),
        "ready_sha256": (package / "READY", "READY marker"),
        "handoff_sha256": (package / "handoff.json", "handoff"),
        "candidate_sha256": (package / "candidate.json", "candidate"),
        "report_sha256": (package / "report.md", "report"),
        "transport_sha256": (transport_path, "transport"),
    }
    raw: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for key, (path, label) in paths.items():
        raw[key] = read_regular(path, label)
        hashes[key] = sha256_bytes(raw[key])

    failed = load_json(raw["failed_state_sha256"], "failed latch")
    if set(failed) != {"schema", "edition", "failed_at", "failed_stage", "stages"}:
        raise RejectionError("failed latch schema mismatch")
    if failed.get("schema") != FAILURE_SCHEMA or failed.get("edition") != edition:
        raise RejectionError("failed latch identity mismatch")
    if failed.get("failed_stage") != "dispatch":
        raise RejectionError("unknown or ineligible failure stage")
    stages = failed.get("stages")
    if not isinstance(stages, list) or [row.get("stage") for row in stages if isinstance(row, dict)] != [
        "validate",
        "build",
        "dispatch",
    ]:
        raise RejectionError("failed stage evidence mismatch")
    if stages[0].get("returncode") != 0 or stages[1].get("returncode") != 0:
        raise RejectionError("pre-dispatch stage did not pass")
    if not isinstance(stages[2].get("returncode"), int) or stages[2]["returncode"] == 0:
        raise RejectionError("dispatch failure evidence missing")
    dispatch_output = stages[2].get("output")
    if not isinstance(dispatch_output, str) or "INTAKE_DISPATCH: ACCEPTED" not in dispatch_output:
        raise RejectionError("dispatch acceptance evidence missing")

    transport = load_json(raw["transport_sha256"], "transport")
    payload, payload_raw, compressed = _decode_payload(transport)
    handoff = load_json(raw["handoff_sha256"], "handoff")
    candidate = load_json(raw["candidate_sha256"], "candidate")
    articles = _validate_package(
        edition,
        package,
        handoff,
        candidate,
        raw["report_sha256"],
        raw["ready_sha256"],
        payload,
    )

    base_main_sha = require_sha(str(transport.get("base_main_sha")), "base main SHA", SHA_RE)
    if payload.get("base_main_sha") != base_main_sha:
        raise RejectionError("payload base main mismatch")
    if transport.get("edition") != edition or transport.get("mode") != "edition":
        raise RejectionError("transport identity mismatch")

    validate_output = stages[0].get("output")
    build_output = stages[1].get("output")
    if not isinstance(validate_output, str) or not re.search(
        rf"(?m)^PASS_INTAKE {re.escape(edition)}(?: |$)", validate_output
    ):
        raise RejectionError("validate success evidence mismatch")
    if not isinstance(build_output, str) or "AIHOT_PAYLOAD_BUILD: PASS" not in build_output:
        raise RejectionError("build success evidence mismatch")
    build_edition = _one_output_value(build_output, "edition", r"20\d{2}-W\d{2}")
    build_main = _one_output_value(build_output, "base_main", r"[0-9a-f]{40}")
    build_payload = _one_output_value(build_output, "payload_sha256", r"[0-9a-f]{64}")
    if build_edition != edition or build_main != base_main_sha:
        raise RejectionError("build identity evidence mismatch")
    if build_payload != sha256_bytes(compressed):
        raise RejectionError("build payload SHA mismatch")

    run_id = _one_output_value(dispatch_output, "run_id", r"[1-9]\d*")
    conclusion = _one_output_value(dispatch_output, "conclusion", r"[a-z_]+")
    status_value = _one_output_value(dispatch_output, "status", r"[a-z_]+")
    expected_main = _one_output_value(dispatch_output, "expected_main", r"[0-9a-f]{40}")
    logged_payload = _one_output_value(dispatch_output, "payload_sha256", r"[0-9a-f]{64}")
    logged_edition = _one_output_value(dispatch_output, "edition", r"20\d{2}-W\d{2}")
    if conclusion != "failure" or status_value != "completed":
        raise RejectionError("workflow is not a completed failure")
    if expected_main != base_main_sha:
        raise RejectionError("dispatch head SHA mismatch")
    if logged_edition != edition:
        raise RejectionError("dispatch edition mismatch")
    if logged_payload != sha256_bytes(compressed):
        raise RejectionError("dispatch payload SHA mismatch")

    failure = _eligible_failure(edition, articles)
    evidence = {
        **hashes,
        "payload_sha256": sha256_bytes(payload_raw),
        "transport_payload_sha256": sha256_bytes(compressed),
        "base_main_sha": base_main_sha,
        "github_run_id": int(run_id),
        "github_conclusion": conclusion,
        "workflow_head_sha": expected_main,
        "article_ids": [article["id"] for article in articles],
        **failure,
    }
    evidence["machine_verified_local_evidence"] = {
        "dispatch_accepted": True,
        "dispatch_evidence_source": "failed_state.stages[dispatch].output",
        "failed_stage": "dispatch",
        "package_file_hashes_verified": True,
        "payload_binding_verified": True,
        "transport_payload_hash_verified": True,
        "validator_rule": "date.fromisoformat(article.date).isocalendar()",
    }
    return evidence


def _receipt_bound_fields(evidence: dict) -> dict:
    return {
        key: evidence[key]
        for key in (
            "failing_article",
            "article_date",
            "article_iso_year",
            "article_iso_week",
            "failure_reason_code",
            "validator_failure",
            "failed_state_sha256",
            "ready_sha256",
            "handoff_sha256",
            "candidate_sha256",
            "report_sha256",
            "transport_sha256",
            "payload_sha256",
            "base_main_sha",
            "github_run_id",
            "github_conclusion",
            "workflow_head_sha",
            "machine_verified_local_evidence",
            "article_ids",
        )
    }


def build_receipt(
    edition: str,
    evidence: dict,
    reason: str,
    remote_proof: str,
    *,
    rejected_at: str | None = None,
) -> dict:
    require_safe_text(reason, "disposition reason")
    require_safe_text(remote_proof, "remote proof")
    return {
        "schema": REJECTION_SCHEMA,
        "disposition": "rejected",
        "edition": edition,
        "rejected_at": rejected_at or dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat(),
        "disposition_reason": reason,
        **_receipt_bound_fields(evidence),
        "operator_attested_remote_evidence": {
            "attestation": remote_proof,
            "verified_by_tool": False,
        },
    }


def _validate_timestamp(value: object) -> None:
    if not isinstance(value, str):
        raise RejectionError("invalid rejected timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise RejectionError("invalid rejected timestamp") from exc
    if parsed.tzinfo is None:
        raise RejectionError("rejected timestamp lacks timezone")
    if parsed.utcoffset() != dt.timedelta(0):
        raise RejectionError("rejected timestamp is not UTC")


def verify_receipt(
    edition: str,
    *,
    state_root: Path = STATE_ROOT,
    outbox_root: Path = OUTBOX_ROOT,
) -> dict:
    evidence = collect_evidence(edition, state_root=state_root, outbox_root=outbox_root)
    rejected_dir = state_root / "rejected"
    require_directory(rejected_dir, "rejected directory")
    receipt_path = rejected_dir / f"{edition}.json"
    receipt_metadata = _lstat(receipt_path, "rejection receipt")
    if stat.S_IMODE(receipt_metadata.st_mode) != 0o600:
        raise RejectionError("rejection receipt mode mismatch")
    if receipt_metadata.st_uid != os.geteuid():
        raise RejectionError("rejection receipt owner mismatch")
    receipt_raw = read_regular(receipt_path, "rejection receipt")
    receipt = load_json(receipt_raw, "rejection receipt")
    if receipt_raw != canonical_json(receipt):
        raise RejectionError("rejection receipt is not canonical JSON")
    if set(receipt) != RECEIPT_KEYS:
        raise RejectionError("rejection receipt schema mismatch")
    if receipt.get("schema") != REJECTION_SCHEMA or receipt.get("disposition") != "rejected":
        raise RejectionError("rejection receipt disposition mismatch")
    if receipt.get("edition") != edition:
        raise RejectionError("rejection receipt edition mismatch")
    _validate_timestamp(receipt.get("rejected_at"))
    require_safe_text(receipt.get("disposition_reason"), "disposition reason")
    remote = receipt.get("operator_attested_remote_evidence")
    if not isinstance(remote, dict) or set(remote) != {"attestation", "verified_by_tool"}:
        raise RejectionError("remote attestation schema mismatch")
    if remote.get("verified_by_tool") is not False:
        raise RejectionError("tool must not claim remote verification")
    require_safe_text(remote.get("attestation"), "remote proof")
    for key, expected in _receipt_bound_fields(evidence).items():
        if receipt.get(key) != expected:
            raise RejectionError(f"rejection receipt binding mismatch: {key}")
    return receipt


@contextmanager
def exclusive_process_lock(state_root: Path = STATE_ROOT) -> Iterator[None]:
    require_directory(state_root, "state root")
    lock_path = state_root / "process-ready.lock"
    metadata = _lstat(lock_path, "process lock")
    if not stat.S_ISREG(metadata.st_mode):
        raise RejectionError("process lock is not a regular file")
    if metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
        raise RejectionError("process lock permissions or owner mismatch")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as exc:
        raise RejectionError("AI-hot READY processor is active") from exc
    finally:
        os.close(descriptor)


def _require_expected(evidence: dict, expected: dict) -> None:
    for key in (
        "failure_sha256",
        "ready_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "report_sha256",
        "transport_sha256",
        "payload_sha256",
    ):
        require_sha(expected[key], key.replace("_", " "))
    require_sha(expected["base_main_sha"], "base main SHA", SHA_RE)
    if not RUN_ID_RE.fullmatch(str(expected["run_id"])):
        raise RejectionError("invalid run id")
    mapping = {
        "failure_sha256": "failed_state_sha256",
        "ready_sha256": "ready_sha256",
        "handoff_sha256": "handoff_sha256",
        "candidate_sha256": "candidate_sha256",
        "report_sha256": "report_sha256",
        "transport_sha256": "transport_sha256",
        "payload_sha256": "payload_sha256",
        "base_main_sha": "base_main_sha",
    }
    for supplied, actual in mapping.items():
        if expected[supplied] != evidence[actual]:
            raise RejectionError(f"state binding mismatch: {supplied}")
    if int(expected["run_id"]) != evidence["github_run_id"]:
        raise RejectionError("state binding mismatch: run_id")
    if expected["failing_article"] != evidence["failing_article"]:
        raise RejectionError("state binding mismatch: failing_article")


def _ensure_rejected_directory(state_root: Path) -> Path:
    rejected = state_root / "rejected"
    try:
        os.mkdir(rejected, 0o700)
        directory_fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError:
        pass
    require_directory(rejected, "rejected directory")
    return rejected


def write_receipt_once(
    path: Path,
    receipt: dict,
    *,
    test_hook: Callable[[str, Path], None] | None = None,
) -> None:
    raw = canonical_json(receipt)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if test_hook:
            test_hook("before_commit", path)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise RejectionError("rejection receipt appeared concurrently") from exc
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if test_hook:
            test_hook("after_commit", path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def reject(
    edition: str,
    *,
    failing_article: str,
    run_id: str,
    failure_sha256: str,
    ready_sha256: str,
    handoff_sha256: str,
    candidate_sha256: str,
    report_sha256: str,
    transport_sha256: str,
    payload_sha256: str,
    base_main_sha: str,
    reason: str,
    remote_proof: str,
    state_root: Path = STATE_ROOT,
    outbox_root: Path = OUTBOX_ROOT,
    test_hook: Callable[[str, Path], None] | None = None,
) -> str:
    expected = {
        "failing_article": failing_article,
        "run_id": run_id,
        "failure_sha256": failure_sha256,
        "ready_sha256": ready_sha256,
        "handoff_sha256": handoff_sha256,
        "candidate_sha256": candidate_sha256,
        "report_sha256": report_sha256,
        "transport_sha256": transport_sha256,
        "payload_sha256": payload_sha256,
        "base_main_sha": base_main_sha,
    }
    require_safe_text(reason, "disposition reason")
    require_safe_text(remote_proof, "remote proof")
    with exclusive_process_lock(state_root):
        evidence = collect_evidence(edition, state_root=state_root, outbox_root=outbox_root)
        _require_expected(evidence, expected)
        rejected_dir = state_root / "rejected"
        receipt_path = rejected_dir / f"{edition}.json"
        if path_present(rejected_dir):
            require_directory(rejected_dir, "rejected directory")
        if path_present(receipt_path):
            receipt = verify_receipt(edition, state_root=state_root, outbox_root=outbox_root)
            if receipt["disposition_reason"] != reason:
                raise RejectionError("existing receipt has a different operator reason")
            if receipt["operator_attested_remote_evidence"]["attestation"] != remote_proof:
                raise RejectionError("existing receipt has different remote evidence")
            return "ALREADY_REJECTED"
        rejected_dir = _ensure_rejected_directory(state_root)
        receipt = build_receipt(edition, evidence, reason, remote_proof)
        write_receipt_once(receipt_path, receipt, test_hook=test_hook)
        verify_receipt(edition, state_root=state_root, outbox_root=outbox_root)
        return "REJECTED"
