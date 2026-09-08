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
import stat
from pathlib import Path

from aihot_rejection import RejectionError, path_present, verify_receipt
from aihot_local_retry import (
    RetryError,
    RetryPaths,
    verify_target_consumed as verify_local_retry_consumed,
)
from aihot_content_retry import (
    ContentRetryError,
    production_paths as content_retry_paths,
    verify_target_consumed as verify_content_retry_consumed,
)
from aihot_package_identity import PACKAGE_RE, parse_package_id
from aihot_ready_retry import (
    ReadyRetryError,
    ReadyRetryPaths,
    consume_for_processing,
    processed_lineage_fields,
    record_retry_failure,
    verify_processed_lineage,
)
from aihot_publication_retry import (
    PublicationRetryError,
    consume_for_processing as consume_publication_retry,
    processed_fields as publication_processed_fields,
    production_paths as publication_retry_paths,
    record_failure as record_publication_retry_failure,
    verify_processed_lineage as verify_publication_processed_lineage,
)

# Backward-compatible test seam for the existing r1 authorization verifier.
verify_target_consumed = verify_local_retry_consumed


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

HISTORICAL_FAILURE_STAGES = frozenset(
    {
        "package",
        "rejection-state",
        "validate",
        "no-change",
        "build",
        "receipt",
        "receipt-json",
        "replay-guard",
        "dispatch",
    }
)


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
        if recovery.get("recovery_type") == "publication":
            record_publication_retry_failure(
                publication_retry_paths(),
                recovery,
                payload["failed_stage"],
                failure_code,
                payload.get("stages", []),
            )
            return True
        record_retry_failure(
            ready_retry_paths(),
            recovery,
            payload["failed_stage"],
            failure_code,
            payload.get("stages", []),
        )
    except (ReadyRetryError, PublicationRetryError):
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


def verify_historical_failed_latch(package_id: str, failed_file: Path) -> str:
    """Verify one immutable failed latch before treating it as historical."""

    try:
        edition, attempt, revision = parse_package_id(package_id)
        before = failed_file.lstat()
    except (ValueError, TypeError, FileNotFoundError) as exc:
        raise ValueError("historical failed latch missing or invalid") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
        or before.st_size < 1
        or before.st_size > 65536
    ):
        raise ValueError("historical failed latch metadata invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(failed_file, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("historical failed latch changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, 65537 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 65536:
                raise ValueError("historical failed latch size invalid")
        raw = b"".join(chunks)
        if not raw:
            raise ValueError("historical failed latch size invalid")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ValueError("historical failed latch changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("historical failed latch JSON invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("historical failed latch JSON object required")
    if value.get("schema") != "gneu-aihot-ready-failure-v1":
        raise ValueError("historical failed latch schema invalid")
    if value.get("edition") != edition:
        raise ValueError("historical failed latch edition mismatch")
    if attempt is not None:
        if value.get("package_id") != package_id or value.get("attempt") != attempt:
            raise ValueError("historical failed latch identity mismatch")
    if revision in {1, 2} and value.get("revision") != revision:
        raise ValueError("historical failed latch revision mismatch")
    stage = value.get("failed_stage")
    if stage not in HISTORICAL_FAILURE_STAGES:
        raise ValueError("historical failed latch stage invalid")
    stages = value.get("stages")
    if not isinstance(stages, list):
        raise ValueError("historical failed latch stage evidence invalid")
    for item in stages:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("stage"), str)
            or not isinstance(item.get("returncode"), int)
            or not isinstance(item.get("output"), str)
        ):
            raise ValueError("historical failed latch stage evidence invalid")
    return stage


def process_package(
    package_id: str,
    *,
    historical: bool = False,
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
            **({"revision": revision} if revision in {1, 2} else {}),
        }
        if attempt is not None
        else {}
    )

    package = OUTBOX / package_id

    processed_file = PROCESSED / f"{package_id}.json"
    failed_file = FAILED / f"{package_id}.json"
    rejected_file = STATE / "rejected" / f"{package_id}.json"

    processed_present = path_present(processed_file)
    failed_present = path_present(failed_file)
    rejected_present = attempt is None and path_present(rejected_file)

    if historical and failed_present and not processed_present and not rejected_present:
        if not package_ready(package):
            print(f"BLOCKED_INVALID_HISTORICAL_FAILURE {package_id}: package invalid")
            return False
        try:
            failed_stage = verify_historical_failed_latch(package_id, failed_file)
        except ValueError as exc:
            print(
                "BLOCKED_INVALID_HISTORICAL_FAILURE "
                f"{package_id}: {exc}"
            )
            return False
        print(
            "HISTORICAL_TERMINAL_SKIPPED "
            f"{package_id} stage={failed_stage}"
        )
        return True

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
    elif revision == 2:
        try:
            verify_content_retry_consumed(content_retry_paths(), package_id)
        except ContentRetryError:
            print(f"BLOCKED_INVALID_CONTENT_RETRY_AUTHORIZATION {package_id}")
            return False

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
                if "publication_retry_authorization_sha256" in processed_value:
                    verify_publication_processed_lineage(
                        publication_retry_paths(), package_id, processed_value
                    )
                else:
                    verify_processed_lineage(
                        ready_retry_paths(), package_id, processed_value
                    )
            except (
                ReadyRetryError,
                PublicationRetryError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
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
        try:
            recovery = consume_publication_retry(
                publication_retry_paths(), package_id
            )
        except PublicationRetryError:
            print(f"PUBLICATION_RETRY_REQUIRES_OPERATOR {package_id}")
            return False
        if recovery is not None:
            print(f"PROCESS_PUBLICATION_RECOVERY {package_id}")
        elif revision != 1:
            print(f"FAILED_REQUIRES_OPERATOR {package_id}")
            return False

    if failed_present and recovery is None:
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
                *(
                    ["--verify-existing"]
                    if recovery is not None
                    and recovery.get("recovery_type") == "publication"
                    else []
                ),
                package_id,
            ],
        ),
    ]

    output = []

    for stage, argv in stages:
        handoff_before = None
        if stage == "validate":
            try:
                handoff_before = (package / "handoff.json").read_bytes()
            except OSError:
                pass
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

        if stage == "validate":
            try:
                handoff_after = (package / "handoff.json").read_bytes()
                if not handoff_before or handoff_after != handoff_before:
                    raise ValueError("handoff changed during validation")
                handoff = json.loads(handoff_after)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                handoff = None
            except ValueError:
                handoff = None
            if not isinstance(handoff, dict):
                payload = {
                    "schema": "gneu-aihot-ready-failure-v1",
                    "edition": edition,
                    **identity,
                    "failed_at": now_utc(),
                    "failed_stage": "no-change",
                    "stages": output,
                }
                if not latch_failure(
                    failed_file,
                    payload,
                    recovery,
                    "HANDOFF_CHANGED_AFTER_VALIDATION",
                ):
                    return False
                print(f"AIHOT_READY_FAILED {package_id} stage=no-change")
                return False
            if handoff.get("mode") == "no-change" and recovery is None:
                receipt = {
                    "schema": "gneu-aihot-ready-processed-v1",
                    "edition": edition,
                    **identity,
                    "processed_at": now_utc(),
                    "base_main_sha": None,
                    "base_aihot_sha256": handoff.get("base_sha256"),
                    "payload_sha256": None,
                    "mode": "no-change",
                    "result": "success",
                }
                atomic_json(processed_file, receipt)
                print(f"AIHOT_READY_NO_CHANGE_PROCESSED {package_id}")
                return True

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
        if recovery.get("recovery_type") == "publication":
            receipt.update(publication_processed_fields(recovery))
        else:
            receipt.update(processed_lineage_fields(recovery))

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

        current_package_id = candidates[-1]

        for package_id in candidates:
            if not process_package(
                package_id,
                historical=package_id != current_package_id,
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
