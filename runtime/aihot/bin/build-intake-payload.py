#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from aihot_content_contract import transparent_delta
from aihot_package_identity import parse_package_id


BRIDGE = Path("/root/gneu-aihot-bridge")
REPO = BRIDGE / "work/gneu-se"
ADAPTER = BRIDGE / "bin/github-adapter.py"
INTAKE_VALIDATOR = BRIDGE / "bin/validate-intake.py"

OUTBOX = Path(
    "/root/.hermes/profiles/gneu/"
    "aihot-handoff/outbox"
)

STATE = BRIDGE / "state/intake"

EXPECTED_REMOTE = (
    "https://github.com/stebolainen/gneu-se.git"
)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

MAX_ENCODED = 55_000


def fail(msg: str) -> None:
    raise SystemExit("BLOCKED: " + msg)


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
) -> str:

    cp = subprocess.run(
        cmd,
        cwd=cwd,
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
        if capture and cp.stdout:
            print(cp.stdout.rstrip())

        if capture and cp.stderr:
            print(cp.stderr.rstrip())

        fail("command failed")

    return (
        cp.stdout
        if capture
        else ""
    )


def canonical_transport(
    value: object,
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_file(
    value: object,
) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def read_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        fail(
            f"invalid JSON: {path.name}"
        )


def require_regular_file(
    path: Path,
) -> None:

    if path.is_symlink():
        fail(
            f"symlink forbidden: {path.name}"
        )

    if not path.is_file():
        fail(
            f"missing file: {path.name}"
        )


if len(sys.argv) != 2:
    fail(
        "usage: build-intake-payload.py "
        "PACKAGE_ID"
    )

package_id = sys.argv[1]
try:
    edition, attempt, revision = parse_package_id(package_id)
except ValueError as exc:
    fail(str(exc))

if not REPO.is_dir():
    fail("bridge repository missing")

remote = run(
    [
        "git",
        "remote",
        "get-url",
        "origin",
    ],
    cwd=REPO,
    capture=True,
).strip()

if remote != EXPECTED_REMOTE:
    fail("unexpected origin remote")


# 1. Package must exist in the production outbox.
pkg = OUTBOX / package_id

try:
    resolved = pkg.resolve(
        strict=True
    )
except Exception:
    fail("outbox package missing")

if resolved.parent != OUTBOX.resolve():
    fail("package escaped outbox")

for name in (
    "handoff.json",
    "candidate.json",
    "report.md",
    "READY",
):
    require_regular_file(
        pkg / name
    )


# 2. Existing independent bridge validator
#    must accept the package first.
cp = subprocess.run(
    [
        "/usr/bin/python3",
        str(INTAKE_VALIDATOR),
        package_id,
    ],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

if cp.stdout:
    print(cp.stdout.rstrip())

if cp.returncode != 0:
    fail(
        "bridge intake validator rejected "
        "package"
    )


# 3. Refresh authoritative GitHub main
#    through the READ-only adapter.
run(
    [
        "/usr/bin/python3",
        str(ADAPTER),
        "--",
        "git",
        "fetch",
        "--no-tags",
        "origin",
        "main",
    ],
    cwd=REPO,
)

main_sha = run(
    [
        "git",
        "rev-parse",
        "origin/main",
    ],
    cwd=REPO,
    capture=True,
).strip()

if not SHA_RE.fullmatch(main_sha):
    fail("invalid origin/main SHA")


# 4. Read exact authoritative AI-hot base
#    directly from origin/main.
cp = subprocess.run(
    [
        "git",
        "show",
        (
            "origin/main:"
            "data/aihot.json"
        ),
    ],
    cwd=REPO,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

if cp.returncode != 0:
    fail(
        "cannot read AI-hot base "
        "from origin/main"
    )

main_raw = cp.stdout

try:
    main = json.loads(
        main_raw.decode("utf-8")
    )
except Exception:
    fail(
        "origin/main AI-hot JSON invalid"
    )

if (
    not isinstance(main, dict)
    or set(main)
    != {
        "generated",
        "editions",
        "articles",
    }
):
    fail(
        "unexpected origin/main schema"
    )

if main_raw != canonical_file(main):
    fail(
        "origin/main AI-hot JSON "
        "is not canonical"
    )

if (
    not isinstance(
        main["editions"],
        list,
    )
    or not isinstance(
        main["articles"],
        list,
    )
):
    fail(
        "origin/main arrays invalid"
    )


# 5. Read untrusted package again.
handoff = read_json(
    pkg / "handoff.json"
)

candidate = read_json(
    pkg / "candidate.json"
)

if not isinstance(handoff, dict):
    fail("handoff not object")

if not isinstance(candidate, dict):
    fail("candidate not object")

if handoff.get("edition") != edition:
    fail("handoff edition mismatch")

expected_handoff_schema = (
    "gneu-aihot-handoff-v2" if attempt is not None else "gneu-aihot-handoff-v1"
)
if handoff.get("schema") != expected_handoff_schema:
    fail("handoff schema mismatch")
if attempt is not None and handoff.get("attempt") != attempt:
    fail("handoff attempt mismatch")
if attempt is None and "attempt" in handoff:
    fail("legacy handoff contains attempt")
if revision == 1 and handoff.get("revision") != 1:
    fail("handoff revision mismatch")
if revision != 1 and "revision" in handoff:
    fail("unexpected handoff revision")

mode = handoff.get("mode")

if mode not in {
    "edition",
    "no-change",
}:
    fail("invalid handoff mode")

if set(candidate) != {
    "generated",
    "editions",
    "articles",
}:
    fail(
        "candidate top-level mutation"
    )

ce = candidate["editions"]
ca = candidate["articles"]

if (
    not isinstance(ce, list)
    or not isinstance(ca, list)
):
    fail(
        "candidate arrays invalid"
    )


# 6. GitHub main is authoritative here.
#    Candidate must contain main as an
#    exact semantic prefix.
be = main["editions"]
ba = main["articles"]

if len(ce) < len(be):
    fail(
        "candidate lost main editions"
    )

if len(ca) < len(ba):
    fail(
        "candidate lost main articles"
    )

if ce[:len(be)] != be:
    fail(
        "candidate edition prefix "
        "differs from origin/main"
    )

if ca[:len(ba)] != ba:
    fail(
        "candidate article prefix "
        "differs from origin/main"
    )

delta = transparent_delta(main, candidate)
added_editions = delta["editions"]
added_articles = delta["articles"]


# 7. Re-assert delta shape.
if mode == "no-change":
    if (
        added_editions
        or added_articles
    ):
        fail(
            "no-change contains delta"
        )

elif mode == "edition":
    if len(added_editions) != 1:
        fail(
            "edition mode requires "
            "exactly one edition"
        )

    if not (
        1 <= len(added_articles) <= 6
    ):
        fail(
            "edition mode requires "
            "1-6 articles"
        )

    new_edition = added_editions[0]

    if (
        not isinstance(
            new_edition,
            dict,
        )
        or new_edition.get("id")
        != edition
    ):
        fail(
            "new edition mismatch"
        )

    for article in added_articles:
        if (
            not isinstance(article, dict)
            or article.get("edition")
            != edition
        ):
            fail(
                "new article edition "
                "mismatch"
            )


# 8. Report is transported as data.
report_raw = (
    pkg / "report.md"
).read_bytes()

if len(report_raw) > 50_000:
    fail("report too large")

try:
    report = report_raw.decode(
        "utf-8"
    )
except UnicodeDecodeError:
    fail("report is not UTF-8")

report = report.strip()

if len(report) < 200:
    fail("report too short")

if "\x00" in report:
    fail("report contains NUL")


# 9. Construct new trust-boundary payload.
#    Do NOT propagate Adam/live raw SHA.
payload = {
    "version": 1,
    "edition": edition,
    "mode": mode,
    "base_main_sha": main_sha,
    "base_aihot_sha256":
        hashlib.sha256(
            main_raw
        ).hexdigest(),
    "base_generated":
        main["generated"],
    "delta": delta,
    "report": report,
}

raw = canonical_transport(
    payload
)

compressed = gzip.compress(
    raw,
    mtime=0,
)

encoded = (
    base64.urlsafe_b64encode(
        compressed
    )
    .rstrip(b"=")
    .decode("ascii")
)

if len(encoded) > MAX_ENCODED:
    fail(
        "encoded payload exceeds "
        "55,000 characters"
    )

payload_sha = hashlib.sha256(
    compressed
).hexdigest()


# 10. Atomic trusted state output.
STATE.mkdir(
    parents=True,
    exist_ok=True,
)

os.chmod(
    STATE,
    0o700,
)

out = STATE / (
    f"{package_id}.transport.json"
)

transport = {
    "edition": edition,
    "mode": mode,
    "base_main_sha": main_sha,
    "payload_sha256":
        payload_sha,
    "payload_b64":
        encoded,
}

fd, tmp_name = tempfile.mkstemp(
    prefix=f".{package_id}.",
    suffix=".tmp",
    dir=STATE,
)

try:
    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            transport,
            handle,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        handle.write("\n")
        handle.flush()
        os.fsync(
            handle.fileno()
        )

    os.chmod(
        tmp_name,
        0o600,
    )

    os.replace(
        tmp_name,
        out,
    )

except Exception:
    try:
        os.unlink(tmp_name)
    except FileNotFoundError:
        pass
    raise


print("AIHOT_PAYLOAD_BUILD: PASS")
print("edition:", edition)
print("package_id:", package_id)
if attempt is not None:
    print("attempt:", attempt)
if revision == 1:
    print("revision:", revision)
print("mode:", mode)
print("base_main:", main_sha)
print(
    "base_aihot_sha256:",
    payload[
        "base_aihot_sha256"
    ],
)
print(
    "new_editions:",
    len(added_editions),
)
print(
    "new_articles:",
    len(added_articles),
)
print(
    "encoded_chars:",
    len(encoded),
)
print(
    "payload_sha256:",
    payload_sha,
)
print("transport:", out)
