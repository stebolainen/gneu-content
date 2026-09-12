#!/usr/bin/env python3
"""Verify or reconcile the existing Hermes AI-hot generation job."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


CONFIG = Path("/root/gneu-aihot-bridge/config/hermes-scheduler.json")
JOBS = Path("/root/.hermes/profiles/gneu/cron/jobs.json")
HERMES = "/usr/local/bin/hermes"
GATE = Path("/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py")
UNHEALTHY_DAILY_STATES = {
    "PRIMARY_TRANSIENT_FAILURE",
    "PRIMARY_FAILURE_TERMINAL",
    "PRIMARY_NO_PACKAGE_TERMINAL",
    "FALLBACK_TRANSIENT_FAILURE_TERMINAL",
    "FALLBACK_FAILURE_TERMINAL",
    "FALLBACK_NO_PACKAGE_TERMINAL",
    "daily_attempt_requires_operator",
    "unsafe_pre_research_fallback_state",
}


class SchedulerError(RuntimeError):
    pass


def load_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise SchedulerError(f"unsafe or missing file: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SchedulerError(f"invalid JSON: {path.name}") from exc


def expected() -> dict:
    value = load_json(CONFIG)
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "job_id",
        "name",
        "schedule",
        "scheduler_timezone",
        "operator_timezone",
        "local_time",
        "script",
        "workdir",
        "prompt",
    }:
        raise SchedulerError("scheduler contract shape mismatch")
    if value["schema"] != "gneu-aihot-hermes-scheduler-v1":
        raise SchedulerError("scheduler contract schema mismatch")
    return value


def current_job(job_id: str) -> dict:
    value = load_json(JOBS)
    jobs = value if isinstance(value, list) else value.get("jobs") if isinstance(value, dict) else None
    if not isinstance(jobs, list):
        raise SchedulerError("Hermes jobs shape mismatch")
    matches = [job for job in jobs if isinstance(job, dict) and job.get("id") == job_id]
    if len(matches) != 1:
        raise SchedulerError("expected exactly one AI-hot scheduler job")
    return matches[0]


def daily_status() -> str:
    result = subprocess.run(
        [sys.executable, str(GATE), "inspect"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        value = json.loads(result.stdout)
        context = value["context"]
        reason = context["reason"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SchedulerError("invalid daily gate status") from exc
    if value.get("status") != "AIHOT_DAILY_GATE_INSPECT" or not isinstance(reason, str):
        raise SchedulerError("invalid daily gate status")
    return reason


def check() -> None:
    contract = expected()
    timezone = subprocess.run(
        ["timedatectl", "show", "--property=Timezone", "--value"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    if timezone != contract["scheduler_timezone"]:
        raise SchedulerError("Hermes host timezone differs from scheduler contract")
    job = current_job(contract["job_id"])
    schedule = job.get("schedule")
    if not isinstance(schedule, dict) or schedule.get("kind") != "cron":
        raise SchedulerError("AI-hot job is not a cron schedule")
    required = {
        "name": contract["name"],
        "script": contract["script"],
        "workdir": contract["workdir"],
        "prompt": contract["prompt"],
    }
    for key, value in required.items():
        if job.get(key) != value:
            raise SchedulerError(f"AI-hot job {key} mismatch")
    if schedule.get("expr") != contract["schedule"]:
        raise SchedulerError("AI-hot schedule mismatch")
    if job.get("enabled") is not True or job.get("state") == "paused":
        raise SchedulerError("AI-hot scheduler job is not active")
    status = daily_status()
    if status in UNHEALTHY_DAILY_STATES:
        raise SchedulerError(status)
    print(
        "AIHOT_GENERATION_SCHEDULER: PASS "
        f"job={contract['job_id']} schedule={contract['schedule']} "
        f"local={contract['local_time']} timezone={contract['operator_timezone']} "
        f"daily_status={status}"
    )


def install() -> None:
    if os.geteuid() != 0:
        raise SchedulerError("scheduler installation requires root")
    contract = expected()
    current_job(contract["job_id"])
    subprocess.run(
        [
            HERMES,
            "cron",
            "edit",
            contract["job_id"],
            "--name",
            contract["name"],
            "--schedule",
            contract["schedule"],
            "--script",
            contract["script"],
            "--workdir",
            contract["workdir"],
            "--prompt",
            contract["prompt"],
        ],
        check=True,
    )
    check()


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage tracked AI-hot generation schedule")
    parser.add_argument("action", choices=("check", "install"))
    args = parser.parse_args()
    install() if args.action == "install" else check()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SchedulerError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"BLOCKED: {exc}")
