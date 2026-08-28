#!/usr/bin/env python3
"""gneu-content 9.9 — trusted autonomous publisher gate.

This script treats PR content as untrusted DATA. It never imports or executes code
from the PR branch. The trusted validator is supplied separately from the main
control branch and executed in a temporary directory together with head
events.json + manifest.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_FILES = {"events.json", "manifest.json"}
HEAD_RE = re.compile(r"^adam/gen(?P<generation>[1-9][0-9]*)-[a-z0-9][a-z0-9._-]{0,79}$")
MAX_RAW_BYTES = 512 * 1024

# These source families are already represented natively by gneu.se and must
# not be duplicated as autonomous Class A events.
NATIVE_SOURCE_IDS = {"msrc", "cert-se"}
CISA_KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class GateError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GateError(message)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path.name}: invalid JSON: {exc}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def normalize_source_url(value: object) -> str:
    """Normalize a primary-source URL for deterministic duplicate checks."""
    try:
        parsed = urlparse(str(value or "").strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except Exception:
        return ""

    if not scheme or not host:
        return ""

    authority = host
    if port and not (scheme == "https" and port == 443):
        authority += f":{port}"

    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"

    result = f"{scheme}://{authority}{path}"
    if parsed.query:
        result += "?" + parsed.query

    return result


def verify_manifest(events_path: Path, manifest_path: Path, label: str) -> tuple[dict, dict]:
    require(events_path.stat().st_size <= MAX_RAW_BYTES, f"{label}: events.json too large")
    require(manifest_path.stat().st_size <= 64 * 1024, f"{label}: manifest.json too large")

    events = load_json(events_path)
    manifest = load_json(manifest_path)

    require(isinstance(events, dict), f"{label}: events root must be object")
    require(isinstance(manifest, dict), f"{label}: manifest root must be object")
    require(events.get("schema") == "gneu-content-events-v1", f"{label}: events schema")
    require(manifest.get("schema") == "gneu-content-manifest-v1", f"{label}: manifest schema")
    require(isinstance(events.get("generation"), int), f"{label}: events generation")
    require(manifest.get("generation") == events["generation"], f"{label}: generation mismatch")

    rows = events.get("events")
    require(isinstance(rows, list), f"{label}: events must be list")
    require(manifest.get("event_count") == len(rows), f"{label}: event_count mismatch")

    actual = hashlib.sha256(events_path.read_bytes()).hexdigest()
    require(manifest.get("events_sha256") == actual, f"{label}: events_sha256 mismatch")

    return events, manifest


def run_trusted_validator(validator: Path, events: Path, manifest: Path) -> str:
    require(validator.is_file(), "trusted validator missing")

    with tempfile.TemporaryDirectory(prefix="gneu-publisher-gate-") as td:
        root = Path(td)
        shutil.copy2(validator, root / "validate_content.py")
        shutil.copy2(events, root / "events.json")
        shutil.copy2(manifest, root / "manifest.json")

        proc = subprocess.run(
            [sys.executable, str(root / "validate_content.py")],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            detail = (proc.stdout + "\n" + proc.stderr).strip().replace("\n", " | ")
            fail("trusted validator rejected head: " + detail[:500])

        return proc.stdout.strip()


def validate(args: argparse.Namespace) -> dict:
    pr = load_json(args.pr)
    files = load_json(args.files)
    checks = load_json(args.checks)
    compare = load_json(args.compare)

    require(pr.get("state") == "open", "PR is not open")
    require(pr.get("draft") is False, "PR is draft")
    require(pr.get("base", {}).get("ref") == "published", "base must be published")

    head = pr.get("head", {})
    base = pr.get("base", {})
    require(head.get("repo", {}).get("full_name") == args.repository, "fork PRs are not eligible")
    require(base.get("repo", {}).get("full_name") == args.repository, "unexpected base repository")

    head_ref = str(head.get("ref") or "")
    match = HEAD_RE.fullmatch(head_ref)
    require(match is not None, "head branch must match adam/genN-description")

    head_sha = str(head.get("sha") or "")
    current_base_sha = str(args.current_base_sha or "")
    require(re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None, "invalid head SHA")
    require(re.fullmatch(r"[0-9a-f]{40}", current_base_sha) is not None, "invalid current base SHA")
    require(str(base.get("sha") or "") == current_base_sha, "PR base SHA is not current published")

    require(compare.get("status") == "ahead", "head must be strictly ahead of current published")
    require(int(compare.get("behind_by", -1)) == 0, "head is behind/diverged from current published")
    require(int(compare.get("ahead_by", 0)) >= 1, "head contains no new commit")

    require(isinstance(files, list), "files payload must be list")
    names = {str(x.get("filename")) for x in files if isinstance(x, dict)}
    require(names == ALLOWED_FILES, "changed files must be exactly events.json and manifest.json")
    require(len(files) == 2, "PR must change exactly two files")
    for row in files:
        require(row.get("status") == "modified", f"{row.get('filename')}: must be modified, not added/deleted")

    runs = checks.get("check_runs", [])
    require(isinstance(runs, list), "check-runs payload invalid")
    validate_runs = [
        r for r in runs
        if isinstance(r, dict)
        and r.get("name") == "validate"
        and r.get("head_sha") == head_sha
        and r.get("status") == "completed"
        and r.get("conclusion") == "success"
        and r.get("app", {}).get("slug") == "github-actions"
    ]
    require(len(validate_runs) >= 1, "required validate check has not succeeded on current head")

    base_events, base_manifest = verify_manifest(args.base_events, args.base_manifest, "base")
    head_events, head_manifest = verify_manifest(args.head_events, args.head_manifest, "head")

    base_generation = int(base_events["generation"])
    head_generation = int(head_events["generation"])
    require(head_generation == base_generation + 1, "generation must increment by exactly one")
    require(int(match.group("generation")) == head_generation, "branch generation must equal manifest generation")

    before = base_events["events"]
    after = head_events["events"]
    require(len(after) == len(before) + 1, "autopublish permits exactly one appended event")
    require(after[:-1] == before, "existing published events are immutable in autopublish")

    new_event = after[-1]
    require(isinstance(new_event, dict), "new event must be object")
    require(new_event.get("publication_class") == "A", "autopublish permits publication_class A only")
    require(new_event.get("confidence", "verified") == "verified", "autopublish requires verified confidence")

    sources = new_event.get("sources", [])
    require(isinstance(sources, list), "new event sources must be list")

    native_hits = []
    for source in sources:
        if not isinstance(source, dict):
            continue

        source_id = str(source.get("id") or "").lower()
        source_url = str(source.get("url") or "")

        if source_id in NATIVE_SOURCE_IDS:
            native_hits.append(source_id)
            continue

        if source_id == "cisa-kev":
            parsed = urlparse(source_url)
            if parsed.path.rstrip("/") == CISA_KEV_PATH:
                native_hits.append("cisa-kev")

    require(
        not native_hits,
        "native source already covered by gneu.se: "
        + ", ".join(sorted(set(native_hits))),
    )

    # A CVE already represented in published content must not be introduced
    # again under a different event ID. A material update requires editorial
    # handling rather than autonomous append-only publication.
    base_cves = set()
    for row in before:
        if not isinstance(row, dict):
            continue
        cves = row.get("cves", [])
        if isinstance(cves, list):
            base_cves.update(str(cve).upper() for cve in cves)

    new_cves_raw = new_event.get("cves", [])
    require(isinstance(new_cves_raw, list), "new event cves must be list")
    new_cves = {str(cve).upper() for cve in new_cves_raw}
    duplicate_cves = sorted(base_cves & new_cves)

    require(
        not duplicate_cves,
        "CVE already covered by published content: "
        + ", ".join(duplicate_cves),
    )

    # Likewise, the same primary advisory/document URL must not be republished
    # under a new event ID. Trailing slash differences are normalized.
    base_source_urls = set()
    for row in before:
        if not isinstance(row, dict):
            continue
        row_sources = row.get("sources", [])
        if not isinstance(row_sources, list):
            continue
        for source in row_sources:
            if not isinstance(source, dict):
                continue
            normalized = normalize_source_url(source.get("url"))
            if normalized:
                base_source_urls.add(normalized)

    new_source_urls = {
        normalized
        for source in sources
        if isinstance(source, dict)
        for normalized in [normalize_source_url(source.get("url"))]
        if normalized
    }

    duplicate_source_urls = sorted(base_source_urls & new_source_urls)
    require(
        not duplicate_source_urls,
        "primary source URL already covered by published content: "
        + ", ".join(duplicate_source_urls),
    )

    base_ids = {row.get("id") for row in before if isinstance(row, dict)}
    require(new_event.get("id") not in base_ids, "new event id already exists")

    validator_output = run_trusted_validator(
        args.trusted_validator,
        args.head_events,
        args.head_manifest,
    )

    return {
        "decision": "PASS_AUTOPUBLISH",
        "pr_number": int(pr["number"]),
        "head_sha": head_sha,
        "head_ref": head_ref,
        "base_generation": base_generation,
        "generation": head_generation,
        "event_id": str(new_event.get("id", "")),
        "event_count": len(after),
        "events_sha256": str(head_manifest["events_sha256"]),
        "validator": validator_output,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repository", required=True)
    ap.add_argument("--current-base-sha", required=True)
    ap.add_argument("--pr", type=Path, required=True)
    ap.add_argument("--files", type=Path, required=True)
    ap.add_argument("--checks", type=Path, required=True)
    ap.add_argument("--compare", type=Path, required=True)
    ap.add_argument("--base-events", type=Path, required=True)
    ap.add_argument("--base-manifest", type=Path, required=True)
    ap.add_argument("--head-events", type=Path, required=True)
    ap.add_argument("--head-manifest", type=Path, required=True)
    ap.add_argument("--trusted-validator", type=Path, required=True)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    try:
        result = validate(args)
    except GateError as exc:
        print("BLOCKED:", exc, file=sys.stderr)
        return 2

    payload = json.dumps(result, ensure_ascii=False, sort_keys=True)
    print(payload)
    if args.json_out:
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
