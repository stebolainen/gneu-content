#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import base64
import fcntl
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from aihot_rejection import RejectionError, path_present, verify_receipt
from aihot_local_retry import RetryError, RetryPaths, verify_target_consumed
from aihot_package_identity import PACKAGE_RE, parse_package_id
from aihot_ready_retry import (
    ReadyRetryError,
    ReadyRetryPaths,
    consume_for_processing,
    processed_lineage_fields,
    record_retry_failure,
    verify_processed_lineage,
)


BRIDGE = Path("/root/gneu-aihot-bridge")

BIN = BRIDGE / "bin"
STATE = BRIDGE / "state"
PROVENANCE = BRIDGE / "PROVENANCE.json"

OUTBOX = Path(
    "/root/.hermes/profiles/gneu/"
    "aihot-handoff/outbox"
)
SCHEDULER_CONFIG = BRIDGE / "config/hermes-scheduler.json"
EXECUTIONS_DB = Path("/root/.hermes/profiles/gneu/cron/executions.db")
CRON_OUTPUT = Path("/root/.hermes/profiles/gneu/cron/output")

PROCESSED = STATE / "processed"
FAILED = STATE / "failed"

LOCK = STATE / "process-ready.lock"

WEEK_RE = re.compile(r"^\d{4}-W\d{2}$")


def ready_retry_paths() -> ReadyRetryPaths:
    return ReadyRetryPaths(
        state=STATE,
        outbox=OUTBOX,
        provenance=PROVENANCE,
        bin_dir=BIN,
    )


def now_utc() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    tmp = path.with_name(
        path.name + ".tmp"
    )

    raw = (
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    fd = os.open(
        tmp,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC,
        0o600,
    )

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, path)

    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def run(
    argv: list[str],
) -> subprocess.CompletedProcess:

    return subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=1800,
    )


def latch_failure(
    failed_file: Path,
    payload: dict,
    recovery: dict | None,
    failure_code: str,
) -> bool:
    if recovery is None:
        atomic_json(failed_file, payload)
        return True
    try:
        record_retry_failure(
            ready_retry_paths(),
            recovery,
            payload["failed_stage"],
            failure_code,
            payload.get("stages", []),
        )
    except ReadyRetryError:
        print(
            "BLOCKED_READY_RETRY_FAILURE_STATE "
            f"{recovery['package_id']}"
        )
        return False
    return True


def package_ready(
    path: Path,
) -> bool:

    if path.is_symlink():
        return False

    if not path.is_dir():
        return False

    try:
        parse_package_id(path.name)
    except (ValueError, TypeError):
        return False

    required = {
        "READY",
        "handoff.json",
        "candidate.json",
        "report.md",
    }

    names = {
        p.name
        for p in path.iterdir()
    }

    if names != required:
        return False

    for name in required:
        p = path / name

        if p.is_symlink():
            return False

        if not p.is_file():
            return False

    return True


def verified_rejections() -> list[dict]:
    rejected = STATE / "rejected"
    if not path_present(rejected):
        return []
    if rejected.is_symlink() or not rejected.is_dir():
        raise RejectionError("rejected state directory invalid")
    receipts = []
    for path in sorted(rejected.iterdir()):
        if path.is_symlink() or not path.is_file() or not WEEK_RE.fullmatch(path.stem):
            raise RejectionError("unexpected rejected state entry")
        receipts.append(
            verify_receipt(path.stem, state_root=STATE, outbox_root=OUTBOX)
        )
    return receipts


def decoded_payload_sha256(transport: dict) -> str:
    encoded = transport.get("payload_b64")
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,55000}", encoded):
        raise ValueError("transport payload encoding invalid")
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    compressed = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(compressed) > 1024 * 1024:
        raise ValueError("transport payload too large")
    if hashlib.sha256(compressed).hexdigest() != transport.get("payload_sha256"):
        raise ValueError("transport payload hash mismatch")
    raw = gzip.decompress(compressed)
    if not raw or len(raw) > 5 * 1024 * 1024:
        raise ValueError("decoded payload size invalid")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("decoded payload shape invalid")
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if raw != canonical:
        raise ValueError("decoded payload is not canonical")
    return hashlib.sha256(raw).hexdigest()


def process_package(
    package_id: str,
) -> bool:

    try:
        edition, attempt, revision = parse_package_id(package_id)
    except (ValueError, TypeError):
        print(f"BLOCKED_INVALID_PACKAGE_ID {package_id}")
        return False

    identity = (
        {
            "package_id": package_id,
            "attempt": attempt,
            **({"revision": revision} if revision == 1 else {}),
        }
        if attempt is not None
        else {}
    )

    package = OUTBOX / package_id

    if revision == 1:
        try:
            verify_target_consumed(
                RetryPaths(
                    STATE,
                    OUTBOX,
                    SCHEDULER_CONFIG,
                    EXECUTIONS_DB,
                    CRON_OUTPUT,
                ),
                package_id,
            )
        except RetryError:
            print(f"BLOCKED_INVALID_RETRY_AUTHORIZATION {package_id}")
            return False

    processed_file = (
        PROCESSED
        / f"{package_id}.json"
    )

    failed_file = (
        FAILED
        / f"{package_id}.json"
    )

    rejected_file = (
        STATE
        / "rejected"
        / f"{package_id}.json"
    )

    processed_present = path_present(
        processed_file
    )
    failed_present = path_present(
        failed_file
    )
    rejected_present = attempt is None and path_present(rejected_file)

    if (
        processed_present
        and rejected_present
    ):
        print(
            f"BLOCKED_STATE_CONFLICT "
            f"{package_id}"
        )
        return False

    if processed_present:
        if failed_present:
            try:
                if processed_file.is_symlink() or not processed_file.is_file():
                    raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
                processed_metadata = processed_file.stat()
                if (
                    processed_metadata.st_uid != 0
                    or processed_metadata.st_gid != 0
                    or (processed_metadata.st_mode & 0o777) != 0o600
                ):
                    raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
                processed_data = processed_file.read_bytes()
                if not processed_data or len(processed_data) > 65536:
                    raise ReadyRetryError("INVALID_PROCESSED_LINEAGE")
                processed_value = json.loads(processed_data)
                verify_processed_lineage(
                    ready_retry_paths(), package_id, processed_value
                )
            except (ReadyRetryError, UnicodeDecodeError, json.JSONDecodeError):
                print(
                    f"BLOCKED_STATE_CONFLICT "
                    f"{package_id}"
                )
                return False
        print(
            f"ALREADY_PROCESSED {package_id}"
        )
        return True

    if rejected_present:
        try:
            verify_receipt(
                package_id,
                state_root=STATE,
                outbox_root=OUTBOX,
            )
        except RejectionError as exc:
            print(
                f"BLOCKED_INVALID_REJECTION "
                f"{package_id}: {exc}"
            )
            return False

        print(
            f"ALREADY_REJECTED {package_id}"
        )
        return True

    recovery = None

    # A failed run is latched. The only retry is an
    # append-only operator authorization for the
    # exact pre-dispatch runtime fingerprint.
    if failed_present:
        if revision != 1:
            print(
                f"FAILED_REQUIRES_OPERATOR {package_id}"
            )
            return False
        try:
            recovery = consume_for_processing(
                ready_retry_paths(), package_id
            )
        except ReadyRetryError as exc:
            if str(exc) == "READY_RETRY_ALREADY_FAILED":
                print(
                    "READY_RETRY_FAILED_REQUIRES_OPERATOR "
                    f"{package_id}"
                )
            elif str(exc) == "READY_RETRY_ALREADY_CONSUMED":
                print(
                    "READY_RETRY_CONSUMED_REQUIRES_OPERATOR "
                    f"{package_id}"
                )
            else:
                print(
                    "BLOCKED_INVALID_READY_RETRY_AUTHORIZATION "
                    f"{package_id}"
                )
            return False
        if recovery is None:
            print(
                f"FAILED_REQUIRES_OPERATOR {package_id}"
            )
            return False
        print(
            f"PROCESS_READY_RECOVERY {package_id}"
        )

    if not package_ready(package):
        if recovery is not None:
            if not latch_failure(
                failed_file,
                {
                    "failed_stage": "package",
                    "stages": [],
                },
                recovery,
                "PACKAGE_CHANGED_AFTER_CONSUMPTION",
            ):
                return False
        print(
            f"BLOCKED_INVALID_PACKAGE "
            f"{package_id}"
        )
        return False

    print(
        f"PROCESS_READY {package_id}"
    )

    try:
        rejection_receipts = verified_rejections()
    except RejectionError as exc:
        if recovery is not None:
            if not latch_failure(
                failed_file,
                {
                    "failed_stage": "rejection-state",
                    "stages": [],
                },
                recovery,
                "INVALID_REJECTION_STATE",
            ):
                return False
        print(f"BLOCKED_INVALID_REJECTION_STATE {package_id}: {exc}")
        return False

    stages = [
        (
            "validate",
            [
                "/usr/bin/python3",
                str(
                    BIN
                    / "validate-intake.py"
                ),
                package_id,
            ],
        ),
        (
            "build",
            [
                "/usr/bin/python3",
                str(
                    BIN
                    / "build-intake-payload.py"
                ),
                package_id,
            ],
        ),
    ]

    output = []

    for stage, argv in stages:
        cp = run(argv)

        output.append(
            {
                "stage": stage,
                "returncode":
                    cp.returncode,
                "output":
                    cp.stdout[-20000:],
            }
        )

        if cp.returncode != 0:
            payload = {
                "schema":
                    "gneu-aihot-ready-failure-v1",
                "edition":
                    edition,
                **identity,
                "failed_at":
                    now_utc(),
                "failed_stage":
                    stage,
                "stages":
                    output,
            }
            if not latch_failure(
                failed_file,
                payload,
                recovery,
                f"{stage.upper()}_FAILED",
            ):
                return False

            print(
                f"AIHOT_READY_FAILED "
                f"{package_id} "
                f"stage={stage}"
            )

            return False

    transport = (
        STATE
        / "intake"
        / f"{package_id}.transport.json"
    )

    if not transport.is_file():
        payload = {
            "schema":
                "gneu-aihot-ready-failure-v1",
            "edition":
                edition,
            **identity,
            "failed_at":
                now_utc(),
            "failed_stage":
                "receipt",
            "reason":
                "transport state missing",
            "stages":
                output,
        }
        if not latch_failure(
            failed_file,
            payload,
            recovery,
            "TRANSPORT_MISSING",
        ):
            return False

        print(
            f"AIHOT_READY_FAILED "
            f"{package_id} "
            "stage=receipt"
        )

        return False

    try:
        transport_data = json.loads(
            transport.read_text(
                encoding="utf-8"
            )
        )

    except Exception:
        payload = {
            "schema":
                "gneu-aihot-ready-failure-v1",
            "edition":
                edition,
            **identity,
            "failed_at":
                now_utc(),
            "failed_stage":
                "receipt-json",
            "reason":
                "transport state invalid JSON",
            "stages":
                output,
        }
        if not latch_failure(
            failed_file,
            payload,
            recovery,
            "TRANSPORT_JSON_INVALID",
        ):
            return False

        print(
            f"AIHOT_READY_FAILED "
            f"{package_id} "
            "stage=receipt-json"
        )
        return False

    if attempt is not None:
        try:
            payload_sha = decoded_payload_sha256(transport_data)
        except Exception:
            payload = {
                "schema": "gneu-aihot-ready-failure-v1",
                "edition": edition,
                **identity,
                "failed_at": now_utc(),
                "failed_stage": "replay-guard",
                "reason": "transport failed canonical payload verification",
                "stages": output,
            }
            if not latch_failure(
                failed_file,
                payload,
                recovery,
                "TRANSPORT_CANONICAL_INVALID",
            ):
                return False
            print(f"BLOCKED_INVALID_TRANSPORT {package_id}")
            return False
        if any(receipt.get("payload_sha256") == payload_sha for receipt in rejection_receipts):
            payload = {
                "schema": "gneu-aihot-ready-failure-v1",
                "edition": edition,
                **identity,
                "failed_at": now_utc(),
                "failed_stage": "replay-guard",
                "reason": "canonical payload matches a verified rejection",
                "stages": output,
            }
            if not latch_failure(
                failed_file,
                payload,
                recovery,
                "REJECTED_PAYLOAD_REPLAY",
            ):
                return False
            print(f"BLOCKED_REJECTED_PACKAGE_REPLAY {package_id}")
            return False

    dispatch_argv = [
        "/usr/bin/python3",
        str(BIN / "dispatch-trusted-intake.py"),
        package_id,
    ]
    cp = run(dispatch_argv)
    output.append(
        {
            "stage": "dispatch",
            "returncode": cp.returncode,
            "output": cp.stdout[-20000:],
        }
    )
    if cp.returncode != 0:
        payload = {
            "schema": "gneu-aihot-ready-failure-v1",
            "edition": edition,
            **identity,
            "failed_at": now_utc(),
            "failed_stage": "dispatch",
            "stages": output,
        }
        if not latch_failure(
            failed_file,
            payload,
            recovery,
            "DISPATCH_FAILED",
        ):
            return False
        print(f"AIHOT_READY_FAILED {package_id} stage=dispatch")
        return False

    receipt = {
        "schema":
            "gneu-aihot-ready-processed-v1",
        "edition":
            edition,
        **identity,
        "processed_at":
            now_utc(),
        "base_main_sha":
            transport_data.get(
                "base_main_sha"
            ),
        "payload_sha256":
            transport_data.get(
                "payload_sha256"
            ),
        "mode":
            transport_data.get(
                "mode"
            ),
        "result":
            "success",
    }

    if recovery is not None:
        receipt.update(
            processed_lineage_fields(recovery)
        )

    atomic_json(
        processed_file,
        receipt,
    )

    print(
        f"AIHOT_READY_PROCESSED "
        f"{package_id}"
    )

    return True


def main() -> int:
    PROCESSED.mkdir(
        parents=True,
        exist_ok=True,
    )

    FAILED.mkdir(
        parents=True,
        exist_ok=True,
    )

    with LOCK.open("a+") as lock:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_EX
            | fcntl.LOCK_NB,
        )

        candidates = []

        if OUTBOX.is_dir():
            for p in OUTBOX.iterdir():
                if (
                    p.is_dir()
                    and PACKAGE_RE.fullmatch(p.name)
                    and (
                        p
                        / "READY"
                    ).is_file()
                ):
                    candidates.append(
                        p.name
                    )

        candidates.sort()

        if not candidates:
            print(
                "AIHOT_READY_QUEUE: EMPTY"
            )
            return 0

        ok = True

        for package_id in candidates:
            if not process_package(
                package_id
            ):
                ok = False

        return 0 if ok else 1


process_week = process_package


if __name__ == "__main__":
    try:
        raise SystemExit(main())

    except BlockingIOError:
        print(
            "AIHOT_READY_PROCESSOR: "
            "ALREADY_RUNNING"
        )
        raise SystemExit(0)
