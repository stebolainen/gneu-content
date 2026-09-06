#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

REASON = "REMOTE_TARGET_BRANCH_COLLISION_NO_WRITE"
SCHEMA = "gneu-aihot-publication-retry-authorization-v1"
CONSUMED_SCHEMA = "gneu-aihot-publication-retry-consumed-v1"
FAILURE_SCHEMA = "gneu-aihot-publication-retry-failure-v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_RE = re.compile(r"^20\d{2}-W\d{2}--20\d{2}-\d{2}-\d{2}(?:--r[12])?$")
WRAPPER = Path("/usr/local/bin/gneu-admin-github")


class PublicationRetryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicationRetryPaths:
    state: Path
    outbox: Path
    provenance: Path
    bin_dir: Path


def production_paths() -> PublicationRetryPaths:
    bridge = Path("/root/gneu-aihot-bridge")
    return PublicationRetryPaths(
        bridge / "state",
        Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox"),
        bridge / "PROVENANCE.json",
        bridge / "bin",
    )


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def regular(path: Path, maximum: int = 1_000_000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PublicationRetryError("required regular file missing")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise PublicationRetryError("file size invalid")
    return raw


def json_file(path: Path) -> tuple[dict, bytes]:
    raw = regular(path)
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise PublicationRetryError("JSON invalid") from exc
    if not isinstance(value, dict):
        raise PublicationRetryError("JSON root invalid")
    return value, raw


def create_receipt(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    raw = canonical(value)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise PublicationRetryError("receipt already exists") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return digest(raw)


def auth_path(paths: PublicationRetryPaths, package_id: str) -> Path:
    return paths.state / "publication-retry/authorized" / f"{package_id}.json"


def consumed_path(paths: PublicationRetryPaths, package_id: str) -> Path:
    return paths.state / "publication-retry/consumed" / f"{package_id}.json"


def retry_failure_path(paths: PublicationRetryPaths, package_id: str) -> Path:
    return paths.state / "publication-retry/failed" / f"{package_id}.json"


def package_evidence(paths: PublicationRetryPaths, package_id: str) -> dict[str, object]:
    if not PACKAGE_RE.fullmatch(package_id):
        raise PublicationRetryError("package id invalid")
    package = paths.outbox / package_id
    result: dict[str, object] = {}
    for key, name in {
        "candidate_sha256": "candidate.json",
        "handoff_sha256": "handoff.json",
        "report_sha256": "report.md",
        "ready_sha256": "READY",
    }.items():
        result[key] = digest(regular(package / name))
    failed, failed_raw = json_file(paths.state / "failed" / f"{package_id}.json")
    transport, transport_raw = json_file(paths.state / "intake" / f"{package_id}.transport.json")
    result["failed_receipt_sha256"] = digest(failed_raw)
    result["transport_sha256"] = digest(transport_raw)
    encoded = transport.get("payload_b64")
    if not isinstance(encoded, str):
        raise PublicationRetryError("transport payload missing")
    try:
        compressed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        raw = gzip.decompress(compressed)
        value = json.loads(raw)
    except Exception as exc:
        raise PublicationRetryError("transport payload invalid") from exc
    if transport.get("payload_sha256") != digest(compressed):
        raise PublicationRetryError("transport compressed hash mismatch")
    if raw != json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode():
        raise PublicationRetryError("canonical payload invalid")
    result["canonical_payload_sha256"] = digest(raw)
    stages = failed.get("stages")
    if failed.get("failed_stage") != "dispatch" or not isinstance(stages, list):
        raise PublicationRetryError("failure is not dispatch-stage")
    if [(row.get("stage"), row.get("returncode")) for row in stages] != [
        ("validate", 0), ("build", 0), ("dispatch", 1)
    ]:
        raise PublicationRetryError("pre-dispatch stages did not pass")
    output = stages[-1].get("output")
    if not isinstance(output, str) or "INTAKE_DISPATCH: ACCEPTED" not in output:
        raise PublicationRetryError("dispatch acceptance missing")
    for key, pattern in (
        ("trusted_run_id", r"(?m)^run_id:\s*([1-9]\d*)\s*$"),
        ("remote_head_sha", r"(?m)^expected_main:\s*([0-9a-f]{40})\s*$"),
    ):
        found = re.findall(pattern, output)
        if len(found) != 1:
            raise PublicationRetryError(f"{key} missing")
        result[key] = int(found[0]) if key == "trusted_run_id" else found[0]
    return result


def verify_runtime(paths: PublicationRetryPaths, source_commit: str) -> None:
    if not SHA_RE.fullmatch(source_commit):
        raise PublicationRetryError("runtime commit invalid")
    provenance, _ = json_file(paths.provenance)
    if provenance.get("source_commit") != source_commit:
        raise PublicationRetryError("runtime provenance mismatch")
    files = provenance.get("files")
    required = {
        "runtime/aihot/bin/process-ready.py": "process-ready.py",
        "runtime/aihot/bin/build-intake-payload.py": "build-intake-payload.py",
        "runtime/aihot/bin/dispatch-trusted-intake.py": "dispatch-trusted-intake.py",
        "runtime/aihot/bin/aihot_publication_retry.py": "aihot_publication_retry.py",
        "runtime/aihot/bin/authorize-publication-retry.py": "authorize-publication-retry.py",
    }
    if not isinstance(files, dict):
        raise PublicationRetryError("provenance files invalid")
    for relative, name in required.items():
        row = files.get(relative)
        path = paths.bin_dir / name
        if not isinstance(row, dict) or row.get("destination") != str(path):
            raise PublicationRetryError("runtime file missing from provenance")
        if digest(regular(path)) != row.get("sha256"):
            raise PublicationRetryError("runtime file hash mismatch")


def remote_read(args: list[str], allow_absent: bool = False):
    cp = subprocess.run([str(WRAPPER), "gneu-se-read", *args], capture_output=True, text=True)
    if cp.returncode:
        if allow_absent and "HTTP 404" in cp.stdout + cp.stderr:
            return None
        raise PublicationRetryError("sanitized remote read failed")
    try:
        return json.loads(cp.stdout)
    except Exception as exc:
        raise PublicationRetryError("sanitized remote response invalid") from exc


def remote_no_write(package_id: str, evidence: dict[str, object], conflict_pr: int) -> dict:
    run_id = str(evidence["trusted_run_id"])
    head_sha = evidence["remote_head_sha"]
    run = remote_read(["workflow-run", run_id])
    jobs = remote_read(["workflow-jobs", run_id])
    if run.get("status") != "completed" or run.get("conclusion") != "failure" or run.get("head_sha") != head_sha:
        raise PublicationRetryError("trusted run identity invalid")
    rows = jobs.get("jobs") if isinstance(jobs, dict) else None
    if not isinstance(rows, list) or len(rows) != 1:
        raise PublicationRetryError("trusted jobs invalid")
    steps = {s.get("name"): s.get("conclusion") for s in rows[0].get("steps", [])}
    required = {
        "Validate transported intake": "success",
        "Run trusted AI-hot validators": "success",
        "Create short-lived PR Writer token": "success",
        "Verify writer repository scope": "success",
        "Execute constrained PR write": "failure",
    }
    if any(steps.get(k) != v for k, v in required.items()):
        raise PublicationRetryError("trusted write boundary invalid")
    edition = package_id.split("--", 1)[0]
    ref = f"aihot/{edition}"
    pr = remote_read(["pr-view", str(conflict_pr)])
    if pr.get("state") != "closed" or pr.get("merged_at") is not None or pr.get("head", {}).get("ref") != ref:
        raise PublicationRetryError("conflicting PR disposition invalid")
    if remote_read(["branch", ref], True) is not None:
        raise PublicationRetryError("conflicting branch remains")
    open_prs = remote_read(["pr-list"])
    if not isinstance(open_prs, list) or any(
        row.get("head", {}).get("ref", "").startswith("aihot/") for row in open_prs
    ):
        raise PublicationRetryError("replacement AI-hot PR exists")
    content = remote_read(["contents", "scripts/aihot_pr_execute.py", "--ref", str(head_sha)])
    try:
        source = base64.b64decode(content["content"]).decode()
    except Exception as exc:
        raise PublicationRetryError("trusted executor source invalid") from exc
    start = source.find("def execute(")
    guard = source.find("if branch(token, head_ref) is not None:", start)
    fingerprint = source.find('fail("target AI-hot branch already exists")', guard)
    first_write = source.find("candidate_blob = create_blob(", start)
    if min(start, guard, fingerprint, first_write) < 0 or not start < guard < fingerprint < first_write:
        raise PublicationRetryError("pre-write collision boundary not proven")
    return {
        "trusted_run_id": int(run_id), "remote_head_sha": head_sha,
        "conflicting_pr": conflict_pr, "conflicting_ref": ref,
        "failure_fingerprint": "target AI-hot branch already exists",
        "executor_blob_sha": content.get("sha"),
        "write_boundary": "branch_guard_before_first_blob_write",
    }


def authorize(paths: PublicationRetryPaths, package_id: str, source_commit: str, reason: str, conflict_pr: int, authorized_at: str) -> tuple[dict, str]:
    if reason != REASON:
        raise PublicationRetryError("reason not allowed")
    verify_runtime(paths, source_commit)
    evidence = package_evidence(paths, package_id)
    if (paths.state / "processed" / f"{package_id}.json").exists():
        raise PublicationRetryError("package already processed")
    if consumed_path(paths, package_id).exists() or retry_failure_path(paths, package_id).exists():
        raise PublicationRetryError("recovery already used")
    remote = remote_no_write(package_id, evidence, conflict_pr)
    value = {
        "schema": SCHEMA, "package_id": package_id, **evidence, **remote,
        "reason": reason, "runtime_source_commit": source_commit,
        "authorized_at": authorized_at,
    }
    return value, create_receipt(auth_path(paths, package_id), value)


def verify_authorization(paths: PublicationRetryPaths, package_id: str, source_commit: str) -> tuple[dict, str]:
    verify_runtime(paths, source_commit)
    value, raw = json_file(auth_path(paths, package_id))
    if raw != canonical(value) or value.get("schema") != SCHEMA or value.get("reason") != REASON:
        raise PublicationRetryError("authorization invalid")
    if value.get("package_id") != package_id or value.get("runtime_source_commit") != source_commit:
        raise PublicationRetryError("authorization identity mismatch")
    evidence = package_evidence(paths, package_id)
    if any(value.get(key) != item for key, item in evidence.items()):
        raise PublicationRetryError("authorization evidence changed")
    return value, digest(raw)


def consume_for_processing(paths: PublicationRetryPaths, package_id: str) -> dict | None:
    if not auth_path(paths, package_id).exists():
        return None
    if consumed_path(paths, package_id).exists() or retry_failure_path(paths, package_id).exists():
        raise PublicationRetryError("PUBLICATION_RETRY_ALREADY_CONSUMED")
    authorization, _ = json_file(auth_path(paths, package_id))
    source_commit = authorization.get("runtime_source_commit")
    verified, auth_sha = verify_authorization(paths, package_id, source_commit)
    value = {
        "schema": CONSUMED_SCHEMA, "package_id": package_id,
        "authorization_sha256": auth_sha,
        "failed_receipt_sha256": verified["failed_receipt_sha256"],
        "transport_sha256": verified["transport_sha256"],
        "canonical_payload_sha256": verified["canonical_payload_sha256"],
        "consumed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    consumed_sha = create_receipt(consumed_path(paths, package_id), value)
    return {**verified, **value, "consumed_sha256": consumed_sha, "recovery_type": "publication"}


def record_failure(paths: PublicationRetryPaths, recovery: dict, stage: str, code: str, stages: list) -> None:
    create_receipt(retry_failure_path(paths, recovery["package_id"]), {
        "schema": FAILURE_SCHEMA, "package_id": recovery["package_id"],
        "authorization_sha256": recovery["authorization_sha256"],
        "consumed_sha256": recovery["consumed_sha256"],
        "failed_stage": stage, "failure_code": code, "stages": stages,
    })


def processed_fields(recovery: dict) -> dict:
    return {
        "publication_retry_failed_sha256": recovery["failed_receipt_sha256"],
        "publication_retry_authorization_sha256": recovery["authorization_sha256"],
        "publication_retry_consumed_sha256": recovery["consumed_sha256"],
        "publication_retry_original_run_id": recovery["trusted_run_id"],
    }


def verify_processed_lineage(paths: PublicationRetryPaths, package_id: str, processed: dict) -> None:
    authorization, auth_raw = json_file(auth_path(paths, package_id))
    consumed, consumed_raw = json_file(consumed_path(paths, package_id))
    expected = {
        "publication_retry_failed_sha256": authorization.get("failed_receipt_sha256"),
        "publication_retry_authorization_sha256": digest(auth_raw),
        "publication_retry_consumed_sha256": digest(consumed_raw),
        "publication_retry_original_run_id": authorization.get("trusted_run_id"),
    }
    if any(processed.get(key) != value for key, value in expected.items()):
        raise PublicationRetryError("processed recovery lineage invalid")
