#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import subprocess
import sys
from pathlib import Path


BRIDGE = Path("/root/gneu-aihot-bridge")

BIN = BRIDGE / "bin"
STATE = BRIDGE / "state"

OUTBOX = Path(
    "/root/.hermes/profiles/gneu/"
    "aihot-handoff/outbox"
)

PROCESSED = STATE / "processed"
FAILED = STATE / "failed"

LOCK = STATE / "process-ready.lock"

WEEK_RE = re.compile(r"^\d{4}-W\d{2}$")


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


def package_ready(
    path: Path,
) -> bool:

    if path.is_symlink():
        return False

    if not path.is_dir():
        return False

    if not WEEK_RE.fullmatch(path.name):
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


def process_week(
    edition: str,
) -> bool:

    package = OUTBOX / edition

    processed_file = (
        PROCESSED
        / f"{edition}.json"
    )

    failed_file = (
        FAILED
        / f"{edition}.json"
    )

    if processed_file.exists():
        print(
            f"ALREADY_PROCESSED {edition}"
        )
        return True

    # A failed run is latched. Never automatically
    # retry a package that may already have crossed
    # the GitHub dispatch boundary.
    if failed_file.exists():
        print(
            f"FAILED_REQUIRES_OPERATOR {edition}"
        )
        return False

    if not package_ready(package):
        print(
            f"BLOCKED_INVALID_PACKAGE "
            f"{edition}"
        )
        return False

    print(
        f"PROCESS_READY {edition}"
    )

    stages = [
        (
            "validate",
            [
                "/usr/bin/python3",
                str(
                    BIN
                    / "validate-intake.py"
                ),
                edition,
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
                edition,
            ],
        ),
        (
            "dispatch",
            [
                "/usr/bin/python3",
                str(
                    BIN
                    / "dispatch-trusted-intake.py"
                ),
                edition,
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
            atomic_json(
                failed_file,
                {
                    "schema":
                        "gneu-aihot-ready-failure-v1",
                    "edition":
                        edition,
                    "failed_at":
                        now_utc(),
                    "failed_stage":
                        stage,
                    "stages":
                        output,
                },
            )

            print(
                f"AIHOT_READY_FAILED "
                f"{edition} "
                f"stage={stage}"
            )

            return False

    transport = (
        STATE
        / "intake"
        / f"{edition}.transport.json"
    )

    if not transport.is_file():
        atomic_json(
            failed_file,
            {
                "schema":
                    "gneu-aihot-ready-failure-v1",
                "edition":
                    edition,
                "failed_at":
                    now_utc(),
                "failed_stage":
                    "receipt",
                "reason":
                    "transport state missing",
                "stages":
                    output,
            },
        )

        print(
            f"AIHOT_READY_FAILED "
            f"{edition} "
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
        atomic_json(
            failed_file,
            {
                "schema":
                    "gneu-aihot-ready-failure-v1",
                "edition":
                    edition,
                "failed_at":
                    now_utc(),
                "failed_stage":
                    "receipt-json",
                "reason":
                    "transport state invalid JSON",
                "stages":
                    output,
            },
        )

        print(
            f"AIHOT_READY_FAILED "
            f"{edition} "
            "stage=receipt-json"
        )
        return False

    receipt = {
        "schema":
            "gneu-aihot-ready-processed-v1",
        "edition":
            edition,
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

    atomic_json(
        processed_file,
        receipt,
    )

    try:
        failed_file.unlink()
    except FileNotFoundError:
        pass

    print(
        f"AIHOT_READY_PROCESSED "
        f"{edition}"
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
                    and WEEK_RE.fullmatch(
                        p.name
                    )
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

        for edition in candidates:
            if not process_week(
                edition
            ):
                ok = False

        return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())

    except BlockingIOError:
        print(
            "AIHOT_READY_PROCESSOR: "
            "ALREADY_RUNNING"
        )
        raise SystemExit(0)
