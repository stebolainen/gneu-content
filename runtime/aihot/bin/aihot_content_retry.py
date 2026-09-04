#!/usr/bin/env python3
"""Exact-once authorization for the bounded 2026-09-04 content retry."""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
from zoneinfo import ZoneInfo

from aihot_claim_resume import (
    ResumeError,
    atomic_create,
    canonical_bytes,
    generation_lock,
    parse_timestamp,
    sha256_bytes,
)
from aihot_content_contract import load_contract
from aihot_local_retry import (
    RetryError,
    RetryPaths,
    verify_target_consumed as verify_local_retry_consumed,
)
from aihot_package_identity import parse_package_id
from aihot_ready_retry import (
    RETRY_FAILURE_KEYS,
    ReadyRetryError,
    ReadyRetryPaths,
    load_authorization as load_ready_authorization,
    load_canonical as load_ready_canonical,
    load_consumed as load_ready_consumed,
    package_hashes as ready_package_hashes,
    retry_failure_path,
    verify_failure_receipt,
)


ZONE = ZoneInfo("Europe/Stockholm")
REASON = "TRUSTED_CONTENT_CONTRACT_MISSING_EVIDENCE"
REVISION = 2
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_REMOTE_RUN_ID = 33874811080
EXPECTED_REMOTE_HEAD_SHA = "4bb9ba39c74323a158460295ab04923c6d9fa53d"
EXPECTED_REMOTE_FAILURE = "BLOCKED: article keys mismatch missing=['evidence'] extra=[]"

# This is deliberately incident-specific. A future incident requires a new
# reviewed contract instead of turning this operator gate into a retry API.
INCIDENT = {
    "edition": "2026-W36",
    "attempt": "2026-09-04",
    "source_package_id": "2026-W36--2026-09-04--r1",
    "target_package_id": "2026-W36--2026-09-04--r2",
    "source_candidate_sha256": "593f334a75764552e069e995cc241d04d5e001d73d4ef3444cd706fa24b45b40",
    "source_handoff_sha256": "fdddf50e316bd31ce7560e10ca236f63402d733c80c953399efb219b2bb56774",
    "source_report_sha256": "9f9923c3c85f1754367d5cb4e15a3db0289c306ce7c84d2b75024b73f5f362b7",
    "source_ready_sha256": "afa8a974dcb3c021cc57e18a88e189001a0d2e08b694ff9312f595570db90b45",
    "original_failed_receipt_sha256": "aa6c27c42ace48775df1a6fffa8b2979699737656726f66d9a120136d5bff26e",
    "local_retry_authorization_sha256": "f2bbcbbd3d0a55bd2214e1ad654bf682be7511dd3bc3d63ece4d02fd9ced04a4",
    "local_retry_consumed_sha256": "6d5d898a356429dd79f557344b60aed17f4a567fefb41ad8f0c71ec40ee363f0",
    "ready_retry_authorization_sha256": "3ad3f006ea8a7e8adf65a7ef6338f0b468280813c2bfaf62c35672cc19e66cef",
    "ready_retry_consumed_sha256": "c68297f7803eac54050ed3d4a4ed5783247923eb75881e2e9308ffe527f40eb8",
    "ready_retry_failure_sha256": "17308264bbf57e9038998464e320b5fbc82674087e6af17c9ec1975aca277261",
    "transport_sha256": "c285210a5071a0ff3c481880f2849157d7a53eb32cda79f1f1754f8883b23d7c",
    "canonical_payload_sha256": "ba3f7db062c227f0bfb3c4f7c9b92dd9af38280f60de039724b7cf4ce1949084",
    "trusted_run_id": 33874811080,
    "remote_head_sha": "4bb9ba39c74323a158460295ab04923c6d9fa53d",
    "remote_validation_result": "BLOCKED: article keys mismatch missing=['evidence'] extra=[]",
    "remote_validate_conclusion": "failure",
    "remote_token_preparation": "skipped",
    "remote_scope_verification": "skipped",
    "remote_write_step": "skipped",
    "repository_writes": "none",
    "authoritative_contract_sha256": "8202d226bbd548425ab3a1d8ea7ea22d09decc5704e7a39dd1c6617b0c033468",
    "content_schema_sha256": "53f6c6ba8b9d2cc83d8123c5e7f30ae9966ad979b660749335e0c3f2969c0224",
    "content_contract_source_commit": "a27e75ff88be4d110ce5a6086b9b0263fce1a9db",
}

AUTHORIZATION_KEYS = {
    "schema",
    *INCIDENT.keys(),
    "revision",
    "reason",
    "runtime_source_commit",
    "operator_attested_remote_evidence",
    "authorized_at",
}
CONSUMED_KEYS = AUTHORIZATION_KEYS | {"authorization_sha256", "consumed_at"}

RUNTIME_FILES = {
    "runtime/aihot/bin/aihot-content-schema.json": ("schema", "0600"),
    "runtime/aihot/bin/aihot_content_contract.py": ("content_contract", "0600"),
    "runtime/aihot/bin/aihot_content_retry.py": ("content_retry", "0600"),
    "runtime/aihot/bin/authorize-content-retry.py": ("authorize_content_retry", "0700"),
    "runtime/aihot/bin/aihot_package_identity.py": ("package_identity", "0600"),
    "runtime/aihot/bin/process-ready.py": ("process_ready", "0700"),
    "runtime/aihot/bin/validate-intake.py": ("validate_intake", "0700"),
    "runtime/aihot/bin/build-intake-payload.py": ("build_intake", "0700"),
    "runtime/aihot/bin/dispatch-trusted-intake.py": ("dispatch_intake", "0700"),
    "runtime/aihot/generation/gneu-aihot-daily-gate.py": ("daily_gate", "0700"),
    "runtime/aihot/generation/gneu-aihot-handoff-validate.py": ("handoff_validator", "0700"),
    "runtime/aihot/generation/ADAM_DAILY.md": ("adam_daily", "0600"),
    "runtime/aihot/generation/CONTRACT.md": ("generation_contract", "0600"),
}


class ContentRetryError(RuntimeError):
    """A bounded, non-secret content-retry policy failure."""


class ContentRetryPaths(RetryPaths):
    def __init__(
        self,
        state: Path,
        outbox: Path,
        scheduler_config: Path,
        executions_db: Path,
        cron_output: Path,
        provenance: Path,
        runtime_paths: dict[str, Path],
        proc_root: Path = Path("/proc"),
    ) -> None:
        super().__init__(state, outbox, scheduler_config, executions_db, cron_output)
        self.provenance = provenance
        self.runtime_paths = runtime_paths
        self.proc_root = proc_root

    @property
    def authorizations(self) -> Path:
        return self.claims / "retry-authorized"

    @property
    def consumed(self) -> Path:
        return self.claims / "retry-consumed"


def production_paths() -> ContentRetryPaths:
    bin_root = Path("/root/gneu-aihot-bridge/bin")
    return ContentRetryPaths(
        state=Path("/root/gneu-aihot-bridge/state"),
        outbox=Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox"),
        scheduler_config=Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json"),
        executions_db=Path("/root/.hermes/profiles/gneu/cron/executions.db"),
        cron_output=Path("/root/.hermes/profiles/gneu/cron/output"),
        provenance=Path("/root/gneu-aihot-bridge/PROVENANCE.json"),
        runtime_paths={
            "schema": bin_root / "aihot-content-schema.json",
            "content_contract": bin_root / "aihot_content_contract.py",
            "content_retry": bin_root / "aihot_content_retry.py",
            "authorize_content_retry": bin_root / "authorize-content-retry.py",
            "package_identity": bin_root / "aihot_package_identity.py",
            "process_ready": bin_root / "process-ready.py",
            "validate_intake": bin_root / "validate-intake.py",
            "build_intake": bin_root / "build-intake-payload.py",
            "dispatch_intake": bin_root / "dispatch-trusted-intake.py",
            "daily_gate": Path(
                "/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py"
            ),
            "handoff_validator": Path(
                "/root/.hermes/profiles/gneu/scripts/gneu-aihot-handoff-validate.py"
            ),
            "adam_daily": Path(
                "/root/.hermes/profiles/gneu/aihot-handoff/ADAM_DAILY.md"
            ),
            "generation_contract": Path(
                "/root/.hermes/profiles/gneu/aihot-handoff/CONTRACT.md"
            ),
        },
    )


def require_regular(path: Path, code: str, maximum: int, *, root_state: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ContentRetryError(code)
    metadata = path.stat()
    if root_state and (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or (metadata.st_mode & 0o777) != 0o600
    ):
        raise ContentRetryError(code)
    data = path.read_bytes()
    if not data or len(data) > maximum:
        raise ContentRetryError(code)
    return data


def load_canonical(path: Path, keys: set[str], schema: str, code: str) -> tuple[dict, bytes]:
    data = require_regular(path, code, 131072, root_state=True)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContentRetryError(code) from exc
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value.get("schema") != schema
        or canonical_bytes(value) != data
    ):
        raise ContentRetryError(code)
    return value, data


def authorization_path(paths: ContentRetryPaths) -> Path:
    return paths.authorizations / f"{INCIDENT['attempt']}-r2.json"


def consumed_path(paths: ContentRetryPaths) -> Path:
    return paths.consumed / f"{INCIDENT['attempt']}-r2.json"


def require_same_local_day(now: dt.datetime) -> None:
    if (
        now.tzinfo is None
        or now.astimezone(ZONE).date().isoformat() != INCIDENT["attempt"]
    ):
        raise ContentRetryError("ATTEMPT_NOT_TODAY")


def hash_file(path: Path, code: str, maximum: int, *, root_state: bool = False) -> str:
    return hashlib.sha256(
        require_regular(path, code, maximum, root_state=root_state)
    ).hexdigest()


def decode_transport(data: bytes) -> tuple[dict, str]:
    try:
        transport = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContentRetryError("INVALID_SOURCE_TRANSPORT") from exc
    if not isinstance(transport, dict) or set(transport) != {
        "edition",
        "mode",
        "base_main_sha",
        "payload_sha256",
        "payload_b64",
    }:
        raise ContentRetryError("INVALID_SOURCE_TRANSPORT")
    encoded = transport.get("payload_b64")
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,55000}", encoded):
        raise ContentRetryError("INVALID_SOURCE_TRANSPORT")
    try:
        padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
        compressed = base64.urlsafe_b64decode(padded.encode("ascii"))
        if hashlib.sha256(compressed).hexdigest() != transport.get("payload_sha256"):
            raise ContentRetryError("INVALID_SOURCE_TRANSPORT")
        raw = gzip.decompress(compressed)
        payload = json.loads(raw)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise ContentRetryError("INVALID_SOURCE_TRANSPORT") from exc
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    if raw != canonical or not isinstance(payload, dict):
        raise ContentRetryError("INVALID_SOURCE_TRANSPORT")
    return payload, hashlib.sha256(raw).hexdigest()


def verify_runtime(paths: ContentRetryPaths, runtime_source_commit: str) -> None:
    if not COMMIT_RE.fullmatch(runtime_source_commit):
        raise ContentRetryError("INVALID_RUNTIME_SOURCE_COMMIT")
    data = require_regular(
        paths.provenance,
        "INVALID_RUNTIME_PROVENANCE",
        2 * 1024 * 1024,
        root_state=True,
    )
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContentRetryError("INVALID_RUNTIME_PROVENANCE") from exc
    files = value.get("files") if isinstance(value, dict) else None
    if (
        value.get("schema") != "gneu-aihot-runtime-provenance-v1"
        or value.get("source_commit") != runtime_source_commit
        or not isinstance(files, dict)
    ):
        raise ContentRetryError("INVALID_RUNTIME_PROVENANCE")
    if set(paths.runtime_paths) != {name for name, _ in RUNTIME_FILES.values()}:
        raise ContentRetryError("INVALID_RUNTIME_PATH_SET")
    for relative, (name, mode) in RUNTIME_FILES.items():
        path = paths.runtime_paths[name]
        raw = require_regular(path, "INVALID_RUNTIME_PROVENANCE", 2 * 1024 * 1024)
        metadata = path.stat()
        entry = files.get(relative)
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or f"{metadata.st_mode & 0o777:04o}" != mode
            or not isinstance(entry, dict)
            or entry.get("destination") != str(path)
            or entry.get("mode") != mode
            or entry.get("sha256") != hashlib.sha256(raw).hexdigest()
        ):
            raise ContentRetryError("INVALID_RUNTIME_PROVENANCE")
    if hash_file(paths.runtime_paths["schema"], "INVALID_CONTENT_CONTRACT", 65536) != INCIDENT[
        "content_schema_sha256"
    ]:
        raise ContentRetryError("CONTENT_CONTRACT_PROVENANCE_MISMATCH")
    contract = load_contract(paths.runtime_paths["schema"])
    provenance = contract.get("provenance", {})
    if provenance.get("sha256") != INCIDENT["authoritative_contract_sha256"]:
        raise ContentRetryError("CONTENT_CONTRACT_PROVENANCE_MISMATCH")


def no_active_generation(paths: ContentRetryPaths) -> None:
    markers = (
        b"gneu-aihot-daily-gate.py",
        b"gneu-aihot-base-refresh.py",
        b"gneu-aihot-handoff-validate.py",
    )
    if paths.proc_root.is_symlink() or not paths.proc_root.is_dir():
        raise ContentRetryError("INVALID_PROCESS_STATE")
    for process in paths.proc_root.glob("[0-9]*"):
        if process.name == str(os.getpid()):
            continue
        try:
            command = (process / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(marker in command for marker in markers):
            raise ContentRetryError("ACTIVE_GENERATION_PROCESS")


def verify_remote_boundary() -> None:
    if (
        INCIDENT.get("trusted_run_id") != EXPECTED_REMOTE_RUN_ID
        or INCIDENT.get("remote_head_sha") != EXPECTED_REMOTE_HEAD_SHA
        or INCIDENT.get("remote_validation_result") != EXPECTED_REMOTE_FAILURE
        or INCIDENT.get("remote_validate_conclusion") != "failure"
        or INCIDENT.get("remote_token_preparation") != "skipped"
        or INCIDENT.get("remote_scope_verification") != "skipped"
        or INCIDENT.get("remote_write_step") != "skipped"
        or INCIDENT.get("repository_writes") != "none"
    ):
        raise ContentRetryError("REMOTE_WRITE_BOUNDARY_NOT_PROVEN")


def verify_local_retry_lineage(paths: ContentRetryPaths) -> None:
    try:
        _, consumed_sha = verify_local_retry_consumed(
            RetryPaths(
                paths.state,
                paths.outbox,
                paths.scheduler_config,
                paths.executions_db,
                paths.cron_output,
            ),
            INCIDENT["source_package_id"],
        )
    except RetryError as exc:
        raise ContentRetryError("INVALID_LOCAL_RETRY_LINEAGE") from exc
    auth = paths.claims / "retry-authorized" / f"{INCIDENT['attempt']}-r1.json"
    if (
        hash_file(auth, "INVALID_LOCAL_RETRY_LINEAGE", 65536, root_state=True)
        != INCIDENT["local_retry_authorization_sha256"]
        or consumed_sha != INCIDENT["local_retry_consumed_sha256"]
    ):
        raise ContentRetryError("INVALID_LOCAL_RETRY_LINEAGE")


def verify_ready_retry_lineage(paths: ContentRetryPaths, hashes: dict[str, str]) -> None:
    ready_paths = ReadyRetryPaths(
        paths.state,
        paths.outbox,
        paths.provenance,
        paths.runtime_paths["schema"].parent,
        paths.proc_root,
    )
    package_id = INCIDENT["source_package_id"]
    failed_sha = INCIDENT["original_failed_receipt_sha256"]
    try:
        actual = ready_package_hashes(ready_paths, package_id)
        if actual != hashes:
            raise ContentRetryError("SOURCE_PACKAGE_HASH_MISMATCH")
        verify_failure_receipt(ready_paths, package_id, failed_sha)
        authorization, authorization_data = load_ready_authorization(
            ready_paths, package_id, hashes, failed_sha
        )
        authorization_sha = sha256_bytes(authorization_data)
        _, consumed_data = load_ready_consumed(
            ready_paths, package_id, authorization, authorization_sha
        )
        failure, failure_data = load_ready_canonical(
            retry_failure_path(ready_paths, package_id),
            RETRY_FAILURE_KEYS,
            "gneu-aihot-ready-retry-failure-v1",
            "INVALID_READY_RETRY_FAILURE",
        )
    except ReadyRetryError as exc:
        raise ContentRetryError("INVALID_READY_RETRY_LINEAGE") from exc
    if (
        authorization_sha != INCIDENT["ready_retry_authorization_sha256"]
        or sha256_bytes(consumed_data) != INCIDENT["ready_retry_consumed_sha256"]
        or sha256_bytes(failure_data) != INCIDENT["ready_retry_failure_sha256"]
        or failure.get("original_failed_receipt_sha256") != failed_sha
        or failure.get("authorization_sha256") != authorization_sha
        or failure.get("consumed_sha256") != INCIDENT["ready_retry_consumed_sha256"]
        or failure.get("failed_stage") != "dispatch"
        or failure.get("failure_code") != "DISPATCH_FAILED"
    ):
        raise ContentRetryError("INVALID_READY_RETRY_LINEAGE")
    stages = failure.get("stages")
    if (
        not isinstance(stages, list)
        or [(row.get("stage"), row.get("returncode")) for row in stages]
        != [("validate", 0), ("build", 0), ("dispatch", 1)]
        or f"run_id: {INCIDENT['trusted_run_id']}" not in stages[-1].get("output", "")
    ):
        raise ContentRetryError("INVALID_READY_RETRY_LINEAGE")


def verify_missing_evidence(payload: dict, candidate: dict, contract: dict) -> None:
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
        raise ContentRetryError("INVALID_SOURCE_PAYLOAD")
    delta = payload.get("delta")
    articles = delta.get("articles") if isinstance(delta, dict) else None
    editions = delta.get("editions") if isinstance(delta, dict) else None
    if (
        payload.get("edition") != INCIDENT["edition"]
        or payload.get("mode") != "edition"
        or not isinstance(articles, list)
        or not articles
        or not isinstance(editions, list)
    ):
        raise ContentRetryError("INVALID_SOURCE_PAYLOAD")
    candidate_articles = candidate.get("articles") if isinstance(candidate, dict) else None
    candidate_editions = candidate.get("editions") if isinstance(candidate, dict) else None
    if (
        not isinstance(candidate_articles, list)
        or not isinstance(candidate_editions, list)
        or candidate_articles[-len(articles) :] != articles
        or candidate_editions[-len(editions) :] != editions
    ):
        raise ContentRetryError("SOURCE_TRANSPORT_CONTENT_MISMATCH")
    required = set(contract["article"]["required_keys"])
    for article in articles:
        if not isinstance(article, dict):
            raise ContentRetryError("SOURCE_FAILURE_NOT_MISSING_EVIDENCE")
        missing = required - set(article)
        extra = set(article) - required
        if missing != {"evidence"} or extra:
            raise ContentRetryError("SOURCE_FAILURE_NOT_MISSING_EVIDENCE")


def verify_source(paths: ContentRetryPaths) -> dict[str, str]:
    source = paths.outbox / INCIDENT["source_package_id"]
    if source.is_symlink() or not source.is_dir():
        raise ContentRetryError("SOURCE_PACKAGE_MISSING")
    expected_names = {"candidate.json", "handoff.json", "report.md", "READY"}
    if {entry.name for entry in source.iterdir()} != expected_names:
        raise ContentRetryError("SOURCE_PACKAGE_FILE_SET_INVALID")
    hashes = {
        "candidate": hash_file(source / "candidate.json", "SOURCE_PACKAGE_INVALID", 5 * 1024 * 1024),
        "handoff": hash_file(source / "handoff.json", "SOURCE_PACKAGE_INVALID", 8192),
        "report": hash_file(source / "report.md", "SOURCE_PACKAGE_INVALID", 50000),
        "ready": hash_file(source / "READY", "SOURCE_PACKAGE_INVALID", 8192),
    }
    expected = {
        "candidate": INCIDENT["source_candidate_sha256"],
        "handoff": INCIDENT["source_handoff_sha256"],
        "report": INCIDENT["source_report_sha256"],
        "ready": INCIDENT["source_ready_sha256"],
    }
    if hashes != expected:
        raise ContentRetryError("SOURCE_PACKAGE_HASH_MISMATCH")
    try:
        handoff = json.loads((source / "handoff.json").read_text())
        candidate = json.loads((source / "candidate.json").read_text())
    except Exception as exc:
        raise ContentRetryError("SOURCE_PACKAGE_JSON_INVALID") from exc
    if (
        not isinstance(handoff, dict)
        or handoff.get("schema") != "gneu-aihot-handoff-v2"
        or handoff.get("edition") != INCIDENT["edition"]
        or handoff.get("attempt") != INCIDENT["attempt"]
        or handoff.get("revision") != 1
    ):
        raise ContentRetryError("SOURCE_HANDOFF_INVALID")
    transport_path = paths.state / "intake" / f"{INCIDENT['source_package_id']}.transport.json"
    transport_data = require_regular(
        transport_path, "INVALID_SOURCE_TRANSPORT", 65536, root_state=True
    )
    if hashlib.sha256(transport_data).hexdigest() != INCIDENT["transport_sha256"]:
        raise ContentRetryError("SOURCE_TRANSPORT_HASH_MISMATCH")
    payload, canonical_sha = decode_transport(transport_data)
    if canonical_sha != INCIDENT["canonical_payload_sha256"]:
        raise ContentRetryError("SOURCE_CANONICAL_PAYLOAD_MISMATCH")
    verify_missing_evidence(
        payload,
        candidate,
        load_contract(paths.runtime_paths["schema"]),
    )
    verify_local_retry_lineage(paths)
    verify_ready_retry_lineage(paths, hashes)
    if os.path.lexists(paths.state / "processed" / f"{INCIDENT['source_package_id']}.json"):
        raise ContentRetryError("SOURCE_PROCESSED_EXISTS")
    return hashes


def verify_target_absent(paths: ContentRetryPaths) -> None:
    target = INCIDENT["target_package_id"]
    for path in (
        paths.outbox / target,
        paths.state / "processed" / f"{target}.json",
        paths.state / "failed" / f"{target}.json",
        paths.state / "intake" / f"{target}.transport.json",
        paths.state / "ready-retry" / "authorized" / f"{target}.json",
        paths.state / "ready-retry" / "consumed" / f"{target}.json",
        paths.state / "ready-retry" / "failed" / f"{target}.json",
    ):
        if os.path.lexists(path):
            raise ContentRetryError("TARGET_STATE_EXISTS")


def authorization_values(runtime_source_commit: str) -> dict:
    return {
        **INCIDENT,
        "revision": REVISION,
        "reason": REASON,
        "runtime_source_commit": runtime_source_commit,
        "operator_attested_remote_evidence": {
            "verified_by_tool": False,
            "run_id": INCIDENT["trusted_run_id"],
            "head_sha": INCIDENT["remote_head_sha"],
            "validation_result": INCIDENT["remote_validation_result"],
            "validate_conclusion": INCIDENT["remote_validate_conclusion"],
            "token_preparation": INCIDENT["remote_token_preparation"],
            "scope_verification": INCIDENT["remote_scope_verification"],
            "write_step": INCIDENT["remote_write_step"],
            "repository_writes": INCIDENT["repository_writes"],
        },
    }


def load_authorization(paths: ContentRetryPaths) -> tuple[dict, bytes]:
    value, data = load_canonical(
        authorization_path(paths),
        AUTHORIZATION_KEYS,
        "gneu-aihot-content-retry-authorization-v1",
        "INVALID_CONTENT_RETRY_AUTHORIZATION",
    )
    expected = authorization_values(value.get("runtime_source_commit"))
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ContentRetryError("CONTENT_RETRY_AUTHORIZATION_BINDING_MISMATCH")
    try:
        authorized_at = parse_timestamp(
            value.get("authorized_at"), "INVALID_CONTENT_RETRY_AUTHORIZATION"
        )
    except ResumeError as exc:
        raise ContentRetryError("INVALID_CONTENT_RETRY_AUTHORIZATION") from exc
    if authorized_at.astimezone(ZONE).date().isoformat() != INCIDENT["attempt"]:
        raise ContentRetryError("INVALID_CONTENT_RETRY_AUTHORIZATION")
    return value, data


def load_consumed(
    paths: ContentRetryPaths, authorization: dict, authorization_sha: str
) -> tuple[dict, bytes]:
    value, data = load_canonical(
        consumed_path(paths),
        CONSUMED_KEYS,
        "gneu-aihot-content-retry-consumed-v1",
        "INVALID_CONTENT_RETRY_CONSUMED",
    )
    for key in AUTHORIZATION_KEYS - {"schema"}:
        if value.get(key) != authorization.get(key):
            raise ContentRetryError("CONTENT_RETRY_CONSUMED_BINDING_MISMATCH")
    if value.get("authorization_sha256") != authorization_sha:
        raise ContentRetryError("CONTENT_RETRY_CONSUMED_BINDING_MISMATCH")
    try:
        authorized_at = parse_timestamp(
            authorization.get("authorized_at"), "INVALID_CONTENT_RETRY_CONSUMED"
        )
        consumed_at = parse_timestamp(
            value.get("consumed_at"), "INVALID_CONTENT_RETRY_CONSUMED"
        )
    except ResumeError as exc:
        raise ContentRetryError("INVALID_CONTENT_RETRY_CONSUMED") from exc
    if consumed_at < authorized_at:
        raise ContentRetryError("INVALID_CONTENT_RETRY_CONSUMED")
    return value, data


def authorize(
    paths: ContentRetryPaths,
    attempt: str,
    runtime_source_commit: str,
    reason: str,
    now: dt.datetime | None = None,
) -> tuple[dict, str]:
    if os.geteuid() != 0 or attempt != INCIDENT["attempt"] or reason != REASON:
        raise ContentRetryError("INVALID_CONTENT_RETRY_REQUEST")
    now = now or dt.datetime.now(dt.timezone.utc)
    require_same_local_day(now)
    try:
        lock = generation_lock(paths)
    except ResumeError as exc:
        raise ContentRetryError("UNSAFE_GENERATION_STATE") from exc
    with lock:
        verify_remote_boundary()
        verify_source(paths)
        verify_runtime(paths, runtime_source_commit)
        no_active_generation(paths)
        verify_target_absent(paths)
        if os.path.lexists(authorization_path(paths)):
            raise ContentRetryError("CONTENT_RETRY_AUTHORIZATION_EXISTS")
        if os.path.lexists(consumed_path(paths)):
            raise ContentRetryError("CONTENT_RETRY_CONSUMED_EXISTS")
        value = {
            "schema": "gneu-aihot-content-retry-authorization-v1",
            **authorization_values(runtime_source_commit),
            "authorized_at": now.astimezone(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }
        try:
            receipt_sha = atomic_create(authorization_path(paths), value)
        except ResumeError as exc:
            raise ContentRetryError("CONTENT_RETRY_STATE_CREATE_FAILED") from exc
    return value, receipt_sha


def verify_authorization(
    paths: ContentRetryPaths, attempt: str, runtime_source_commit: str
) -> tuple[dict, str]:
    if attempt != INCIDENT["attempt"]:
        raise ContentRetryError("INVALID_CONTENT_RETRY_REQUEST")
    verify_remote_boundary()
    verify_source(paths)
    verify_runtime(paths, runtime_source_commit)
    value, data = load_authorization(paths)
    if value.get("runtime_source_commit") != runtime_source_commit:
        raise ContentRetryError("RUNTIME_SOURCE_COMMIT_MISMATCH")
    return value, sha256_bytes(data)


def consume_authorization(
    paths: ContentRetryPaths, attempt: str, now: dt.datetime
) -> tuple[str, dict | None]:
    if attempt != INCIDENT["attempt"]:
        return "not-authorized", None
    require_same_local_day(now)
    auth_path = authorization_path(paths)
    receipt_path = consumed_path(paths)
    if not os.path.lexists(auth_path):
        if os.path.lexists(receipt_path):
            raise ContentRetryError("CONTENT_RETRY_CONSUMED_WITHOUT_AUTHORIZATION")
        return "not-authorized", None
    verify_remote_boundary()
    verify_source(paths)
    authorization, data = load_authorization(paths)
    verify_runtime(paths, authorization["runtime_source_commit"])
    authorization_sha = sha256_bytes(data)
    if os.path.lexists(receipt_path):
        load_consumed(paths, authorization, authorization_sha)
        return "already-consumed", authorization
    verify_target_absent(paths)
    value = {
        **authorization,
        "schema": "gneu-aihot-content-retry-consumed-v1",
        "authorization_sha256": authorization_sha,
        "consumed_at": now.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }
    try:
        atomic_create(receipt_path, value)
    except ResumeError as exc:
        raise ContentRetryError("CONTENT_RETRY_STATE_CREATE_FAILED") from exc
    return "consumed", authorization


def verify_consumed(
    paths: ContentRetryPaths, attempt: str, runtime_source_commit: str
) -> tuple[dict, str]:
    authorization, authorization_sha = verify_authorization(
        paths, attempt, runtime_source_commit
    )
    consumed, data = load_consumed(paths, authorization, authorization_sha)
    return consumed, sha256_bytes(data)


def verify_target_consumed(
    paths: ContentRetryPaths, target_package_id: str
) -> tuple[dict, str]:
    try:
        edition, attempt, revision = parse_package_id(target_package_id)
    except ValueError as exc:
        raise ContentRetryError("INVALID_CONTENT_RETRY_TARGET") from exc
    if (
        edition != INCIDENT["edition"]
        or attempt != INCIDENT["attempt"]
        or revision != REVISION
        or target_package_id != INCIDENT["target_package_id"]
    ):
        raise ContentRetryError("INVALID_CONTENT_RETRY_TARGET")
    verify_remote_boundary()
    verify_source(paths)
    authorization, authorization_data = load_authorization(paths)
    verify_runtime(paths, authorization["runtime_source_commit"])
    consumed, data = load_consumed(
        paths, authorization, sha256_bytes(authorization_data)
    )
    return consumed, sha256_bytes(data)
