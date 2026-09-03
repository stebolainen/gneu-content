#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from github_auth import AuthError, mint_token, revoke_token


ROOT = Path(
    "/root/gneu-aihot-bridge/work/gneu-se"
).resolve()

REMOTE = "https://github.com/stebolainen/gneu-se.git"


def fail(msg: str) -> None:
    raise SystemExit("BLOCKED: " + msg)


if len(sys.argv) < 3 or sys.argv[1] != "--":
    fail("usage: github-adapter.py -- <allowed command>")

cmd = sys.argv[2:]


if not ROOT.is_dir():
    fail("bridge repository missing")


gitdir = ROOT / ".git"

if not gitdir.exists():
    fail("bridge work directory is not a git repository")


cp = subprocess.run(
    ["git", "-C", str(ROOT), "remote", "get-url", "origin"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)

if cp.returncode != 0:
    fail("origin missing")

if cp.stdout.strip() != REMOTE:
    fail("unexpected origin URL")


allowed = False


# Phase 1 is intentionally READ-ONLY remotely.

if cmd == ["git", "fetch", "origin"]:
    allowed = True

elif cmd == [
    "git",
    "fetch",
    "--no-tags",
    "origin",
    "main",
]:
    allowed = True

elif cmd == ["git", "ls-remote", "origin"]:
    allowed = True


if not allowed:
    fail("command is not allowlisted")


try:
    token = mint_token(purpose="read")

except AuthError as exc:
    fail("authentication refused: " + str(exc))


rc = 1
revoke_error = None

try:
    with tempfile.TemporaryDirectory(
        prefix="gneu-aihot-askpass-"
    ) as td:

        askpass = Path(td) / "askpass.sh"

        askpass.write_text(
            """#!/bin/sh
case "$1" in
  *Username*) printf '%s\\n' 'x-access-token' ;;
  *Password*) printf '%s\\n' "$GNEU_AIHOT_TOKEN" ;;
  *) exit 1 ;;
esac
"""
        )

        askpass.chmod(0o700)

        env = os.environ.copy()

        env.update(
            {
                "GNEU_AIHOT_TOKEN": token,
                "GIT_ASKPASS": str(askpass),
                "GIT_ASKPASS_REQUIRE": "force",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            }
        )

        actual = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(ROOT),
            *cmd[1:],
        ]

        cp = subprocess.run(
            actual,
            env=env,
        )

        rc = cp.returncode

finally:
    try:
        revoke_token(token)

    except AuthError as exc:
        revoke_error = str(exc)


if revoke_error is not None:
    print(
        "BLOCKED: GitHub token revoke failed",
        file=sys.stderr,
    )
    raise SystemExit(78)


raise SystemExit(rc)
