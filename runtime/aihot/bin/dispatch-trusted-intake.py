#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from github_auth import AuthError, mint_token, revoke_token


BRIDGE = Path("/root/gneu-aihot-bridge")
REPO = BRIDGE / "work/gneu-se"
ADAPTER = BRIDGE / "bin/github-adapter.py"
STATE = BRIDGE / "state/intake"

OWNER = "stebolainen"
REPO_NAME = "gneu-se"

WORKFLOW = (
    "aihot-intake.yml"
)

API = "https://api.github.com"
API_VERSION = "2022-11-28"

WEEK_RE = re.compile(
    r"^\d{4}-W\d{2}$"
)

SHA_RE = re.compile(
    r"^[0-9a-f]{40}$"
)

SHA256_RE = re.compile(
    r"^[0-9a-f]{64}$"
)


def fail(msg: str) -> None:
    raise SystemExit(
        "BLOCKED: " + msg
    )


def run(
    cmd: list[str],
    *,
    capture: bool = False,
) -> str:

    cp = subprocess.run(
        cmd,
        cwd=REPO,
        text=True,
        stdout=(
            subprocess.PIPE
            if capture
            else None
        ),
        stderr=(
            subprocess.PIPE
            if capture
            else None
        ),
    )

    if cp.returncode != 0:
        fail("command failed")

    return (
        cp.stdout
        if capture
        else ""
    )


def api(
    method: str,
    path: str,
    token: str,
    body: dict | None = None,
) -> dict:

    data = (
        json.dumps(body).encode(
            "utf-8"
        )
        if body is not None
        else None
    )

    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization":
                f"Bearer {token}",
            "Accept":
                "application/"
                "vnd.github+json",
            "X-GitHub-Api-Version":
                API_VERSION,
            "User-Agent":
                "gneu-aihot-"
                "dispatch-intake/1.0",
            "Content-Type":
                "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=20,
        ) as response:
            raw = response.read()

    except urllib.error.HTTPError as exc:
        fail(
            f"GitHub API HTTP "
            f"{exc.code}"
        )

    except Exception as exc:
        fail(
            "GitHub API failure: "
            + type(exc).__name__
        )

    if not raw:
        return {}

    try:
        return json.loads(raw)
    except Exception:
        fail(
            "GitHub API returned "
            "invalid JSON"
        )


if len(sys.argv) != 2:
    fail(
        "usage: dispatch-intake.py "
        "YYYY-Www"
    )

edition = sys.argv[1]

if not WEEK_RE.fullmatch(edition):
    fail("invalid edition")

transport_path = (
    STATE
    / f"{edition}.transport.json"
)

if transport_path.is_symlink():
    fail(
        "transport symlink forbidden"
    )

if not transport_path.is_file():
    fail("transport missing")

if (
    transport_path.stat().st_mode
    & 0o077
):
    fail(
        "transport permissions "
        "too broad"
    )

try:
    transport = json.loads(
        transport_path.read_text(
            encoding="utf-8"
        )
    )
except Exception:
    fail("transport JSON invalid")

if set(transport) != {
    "edition",
    "mode",
    "base_main_sha",
    "payload_sha256",
    "payload_b64",
}:
    fail(
        "transport schema mismatch"
    )

if (
    transport["edition"]
    != edition
):
    fail(
        "transport edition mismatch"
    )

main_sha = transport[
    "base_main_sha"
]

payload_sha = transport[
    "payload_sha256"
]

payload_b64 = transport[
    "payload_b64"
]

if not (
    isinstance(main_sha, str)
    and SHA_RE.fullmatch(
        main_sha
    )
):
    fail("invalid main SHA")

if not (
    isinstance(payload_sha, str)
    and SHA256_RE.fullmatch(
        payload_sha
    )
):
    fail(
        "invalid payload SHA-256"
    )

if not isinstance(
    payload_b64,
    str,
):
    fail("payload missing")

if not (
    1 <= len(payload_b64)
    <= 55_000
):
    fail(
        "payload size invalid"
    )


# Refresh current main through
# read-only adapter.
run([
    "/usr/bin/python3",
    str(ADAPTER),
    "--",
    "git",
    "fetch",
    "--no-tags",
    "origin",
    "main",
])

current_main = run(
    [
        "git",
        "rev-parse",
        "origin/main",
    ],
    capture=True,
).strip()

if current_main != main_sha:
    fail(
        "main moved after "
        "payload build"
    )


# Verify exact trusted workflow
# currently exists on that SHA.
cp = subprocess.run(
    [
        "git",
        "show",
        (
            "origin/main:"
            ".github/workflows/"
            + WORKFLOW
        ),
    ],
    cwd=REPO,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)

if cp.returncode != 0:
    fail(
        "trusted intake workflow "
        "missing"
    )

workflow = cp.stdout

for required in (
    "workflow_dispatch:",
    "payload_b64:",
    "payload_sha256:",
    "permissions:",
    "contents: read",
):
    if required not in workflow:
        fail(
            "workflow contract "
            "missing: "
            + required
        )

for forbidden in (
    r"(?m)^\s*contents:"
    r"\s*write\s*$",

    r"(?m)^\s*pull-requests:"
    r"\s*",

    r"(?m)^\s*actions:"
    r"\s*",

    r"(?m)^\s*permissions:"
    r"\s*write-all\s*$",
):
    if re.search(
        forbidden,
        workflow,
    ):
        fail(
            "workflow contains "
            "forbidden permission"
        )


started = datetime.now(
    timezone.utc
)

token = None

try:
    token = mint_token(
        purpose="dispatch"
    )

    api(
        "POST",
        (
            f"/repos/{OWNER}/"
            f"{REPO_NAME}/actions/"
            f"workflows/{WORKFLOW}/"
            "dispatches"
        ),
        token,
        {
            "ref": "main",
            "inputs": {
                "payload_b64":
                    payload_b64,
                "payload_sha256":
                    payload_sha,
            },
        },
    )

    print(
        "INTAKE_DISPATCH: ACCEPTED"
    )
    print("edition:", edition)
    print(
        "expected_main:",
        main_sha,
    )
    print(
        "payload_sha256:",
        payload_sha,
    )

    run_row = None

    for _ in range(30):
        time.sleep(2)

        data = api(
            "GET",
            (
                f"/repos/{OWNER}/"
                f"{REPO_NAME}/actions/"
                f"workflows/{WORKFLOW}/"
                "runs"
                "?event=workflow_dispatch"
                "&branch=main"
                "&per_page=10"
            ),
            token,
        )

        candidates = []

        for row in data.get(
            "workflow_runs",
            [],
        ):
            if (
                row.get("head_sha")
                != main_sha
            ):
                continue

            if (
                row.get("event")
                != "workflow_dispatch"
            ):
                continue

            created_raw = row.get(
                "created_at"
            )

            if not isinstance(
                created_raw,
                str,
            ):
                continue

            try:
                created = (
                    datetime
                    .fromisoformat(
                        created_raw
                        .replace(
                            "Z",
                            "+00:00",
                        )
                    )
                )
            except Exception:
                continue

            if created >= (
                started
                - timedelta(
                    seconds=5
                )
            ):
                candidates.append(row)

        if len(candidates) > 1:
            fail(
                "ambiguous intake runs"
            )

        if len(candidates) == 1:
            run_row = candidates[0]
            break

    if run_row is None:
        fail(
            "intake workflow run "
            "not found"
        )

    run_id = run_row.get("id")

    if not isinstance(run_id, int):
        fail(
            "invalid workflow run id"
        )

    print("run_id:", run_id)

    result = None

    for _ in range(120):
        result = api(
            "GET",
            (
                f"/repos/{OWNER}/"
                f"{REPO_NAME}/actions/"
                f"runs/{run_id}"
            ),
            token,
        )

        if (
            result.get("status")
            == "completed"
        ):
            break

        time.sleep(2)

    else:
        fail(
            "workflow did not "
            "complete in time"
        )

    conclusion = result.get(
        "conclusion"
    )

    print(
        "status:",
        result.get("status"),
    )

    print(
        "conclusion:",
        conclusion,
    )

    if conclusion != "success":
        fail(
            "intake validation "
            "workflow failed"
        )

    jobs = api(
        "GET",
        (
            f"/repos/{OWNER}/"
            f"{REPO_NAME}/actions/"
            f"runs/{run_id}/jobs"
            "?per_page=100"
        ),
        token,
    )

    rows = jobs.get("jobs")

    if not isinstance(rows, list):
        fail("workflow jobs missing")

    matched = [
        row
        for row in rows
        if row.get("name")
        == "trusted-aihot-intake"
    ]

    if len(matched) != 1:
        fail(
            "expected intake job "
            "not found"
        )

    job = matched[0]

    if (
        job.get("conclusion")
        != "success"
    ):
        fail(
            "intake job failed"
        )

    print(
        "job:",
        job.get("name"),
    )

    for step in job.get(
        "steps",
        [],
    ):
        print(
            "step:",
            step.get("name"),
            "->",
            step.get("conclusion"),
        )

    print(
        "AIHOT_TRUSTED_INTAKE_E2E: PASS"
    )

except AuthError as exc:
    fail(
        "authentication refused: "
        + str(exc)
    )

finally:
    if token:
        try:
            revoke_token(token)
        except AuthError:
            fail(
                "dispatch token "
                "revoke failed"
            )
