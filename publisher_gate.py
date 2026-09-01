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
MAX_AIHOT_BYTES = 2 * 1024 * 1024

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ADVISORY_RE = re.compile(r"\bAA\d{2}-\d{3}[A-Z]\b", re.I)

# These source families are already represented natively by gneu.se and must
# not be duplicated as autonomous Class A events.
NATIVE_SOURCE_IDS = {"msrc", "cert-se"}
# Mirrors the trusted validator. A value outside this set is unknown, not a
# known-but-lower confidence, so it is BLOCKED rather than NEEDS_HUMAN.
KNOWN_CONFIDENCE = {"verified", "corroborated"}
CISA_KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# Deterministic outcome contract shared by the autonomous publisher and the
# required PR-head policy check.
#
#   ACTIONABLE   the candidate passed every check and may be published
#   NOOP_STALE   the candidate has no net diff against current published
#   POLICY_SKIP  an expected editorial coverage decision declined the candidate
#   NEEDS_HUMAN  we know exactly what the candidate is, and policy reserves it
#                for a human editor
#   BLOCKED      we cannot safely continue: malformed, contradictory or
#                untrustworthy data, an integrity violation, or an unknown state
#
# The dividing line is knowledge, not severity. NEEDS_HUMAN means the candidate
# is understood and deliberately not autopublishable. BLOCKED means we cannot
# be sure what we are looking at, so we stop. An unrecognised value is always
# BLOCKED and never NEEDS_HUMAN.
#
# NOOP_STALE, POLICY_SKIP and NEEDS_HUMAN are all terminal for exactly one
# candidate and must never fail the publisher workflow. Only NEEDS_HUMAN
# notifies a person.
OUTCOME_ACTIONABLE = "ACTIONABLE"
OUTCOME_NOOP_STALE = "NOOP_STALE"
OUTCOME_POLICY_SKIP = "POLICY_SKIP"
OUTCOME_NEEDS_HUMAN = "NEEDS_HUMAN"
OUTCOME_BLOCKED = "BLOCKED"

EXIT_ACTIONABLE = 0
EXIT_BLOCKED = 2
EXIT_NOOP_STALE = 3
EXIT_POLICY_SKIP = 4
EXIT_NEEDS_HUMAN = 5

# Terminal, non-BLOCKED outcomes. The publisher may move to the next candidate
# on any of these; none of them may mint a token or merge.
NON_ACTIONABLE_EXIT_CODES = {
    OUTCOME_NOOP_STALE: EXIT_NOOP_STALE,
    OUTCOME_POLICY_SKIP: EXIT_POLICY_SKIP,
    OUTCOME_NEEDS_HUMAN: EXIT_NEEDS_HUMAN,
}

# Only an understood candidate that a person must handle raises a person.
NOTIFY_OUTCOMES = {OUTCOME_NEEDS_HUMAN}


class GateError(RuntimeError):
    pass


class GateOutcome(GateError):
    """A deterministic terminal outcome for exactly one candidate.

    Deliberately a subclass of ``GateError`` so that any consumer which does
    not distinguish outcomes keeps failing closed and never publishes.
    """

    def __init__(self, outcome: str, reason_code: str, message: str) -> None:
        super().__init__(message)
        if outcome not in NON_ACTIONABLE_EXIT_CODES:
            raise GateError(f"unknown gate outcome: {outcome}")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,47}", reason_code):
            raise GateError(f"invalid reason code: {reason_code}")
        self.outcome = outcome
        self.reason_code = reason_code


def fail(message: str) -> None:
    raise GateError(message)


def policy_skip(reason_code: str, message: str) -> None:
    """An expected editorial coverage decision, not a technical failure."""
    raise GateOutcome(OUTCOME_POLICY_SKIP, reason_code, message)


def needs_human(reason_code: str, message: str) -> None:
    """An understood candidate that policy reserves for a human editor."""
    raise GateOutcome(OUTCOME_NEEDS_HUMAN, reason_code, message)


def require_policy(condition: bool, reason_code: str, message: str) -> None:
    if not condition:
        policy_skip(reason_code, message)


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


def load_aihot_coverage(path: Path) -> dict:
    """Load bounded, untrusted AI-hot coverage data fail-closed."""
    try:
        require(path.is_file(), "AI-hot coverage missing")
        require(
            path.stat().st_size <= MAX_AIHOT_BYTES,
            "AI-hot coverage too large",
        )
        data = load_json(path)
    except OSError as exc:
        fail(f"AI-hot coverage unavailable: {exc}")

    require(isinstance(data, dict), "AI-hot coverage root must be object")

    articles = data.get("articles")
    require(isinstance(articles, list), "AI-hot coverage articles must be list")
    require(len(articles) <= 1000, "AI-hot coverage contains too many articles")

    for article in articles:
        require(isinstance(article, dict), "AI-hot article must be object")

        sources = article.get("sources", [])
        require(isinstance(sources, list), "AI-hot article sources must be list")
        require(len(sources) <= 20, "AI-hot article has too many sources")

        for source in sources:
            require(isinstance(source, dict), "AI-hot source must be object")
            if "url" in source:
                require(
                    isinstance(source["url"], str),
                    "AI-hot source URL must be string",
                )

    return data


def extract_aihot_coverage(data: dict) -> tuple[set[str], set[str], set[str]]:
    urls: set[str] = set()
    cves: set[str] = set()
    advisories: set[str] = set()

    for article in data["articles"]:
        blob = json.dumps(article, ensure_ascii=False)
        cves.update(x.upper() for x in CVE_RE.findall(blob))
        advisories.update(x.upper() for x in ADVISORY_RE.findall(blob))

        for source in article.get("sources", []):
            normalized = normalize_source_url(source.get("url"))
            if normalized:
                urls.add(normalized)

    return urls, cves, advisories


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    """Read a bounded untrusted file, failing closed on size or IO problems."""
    try:
        require(path.is_file(), f"{label}: file missing")
        require(path.stat().st_size <= limit, f"{label}: file too large")
        return path.read_bytes()
    except OSError as exc:
        fail(f"{label}: unavailable: {exc}")


def detect_noop_stale(args: argparse.Namespace, files: list, compare: dict) -> None:
    """Classify a PR whose net diff against current published is empty.

    A revert-of-its-own-commit branch is legitimately uninteresting rather than
    broken: there is nothing to publish, so it must not be merged, must not
    fail the workflow and must not hold up the next candidate.

    This is deliberately narrow. It fires only when every independent piece of
    evidence agrees that the net diff is empty. Evidence that disagrees is an
    inconsistency in untrusted API data and stays a hard failure.
    """
    if files:
        return

    status = str(compare.get("status") or "")
    if status not in {"identical", "ahead"}:
        return

    compare_files = compare.get("files", [])
    require(isinstance(compare_files, list), "compare files payload must be list")
    require(
        not compare_files,
        "PR files payload is empty but compare reports changed files",
    )
    # A head that is behind current published is the stale-base case, which is
    # classified separately. Hand it on rather than treating it as a no-op.
    try:
        behind_by = int(compare.get("behind_by", -1))
    except (TypeError, ValueError):
        fail("compare behind_by is not an integer")
    if behind_by != 0:
        return

    base_events = read_bounded(args.base_events, MAX_RAW_BYTES, "base events.json")
    head_events = read_bounded(args.head_events, MAX_RAW_BYTES, "head events.json")
    base_manifest = read_bounded(args.base_manifest, 64 * 1024, "base manifest.json")
    head_manifest = read_bounded(args.head_manifest, 64 * 1024, "head manifest.json")

    require(
        base_events == head_events and base_manifest == head_manifest,
        "PR reports no changed files but head content differs from published",
    )

    raise GateOutcome(
        OUTCOME_NOOP_STALE,
        "NO_NET_DIFF",
        "no net diff against current published base",
    )


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


def validate(
    args: argparse.Namespace,
    *,
    require_validate_check: bool = True,
) -> dict:
    pr = load_json(args.pr)
    files = load_json(args.files)
    compare = load_json(args.compare)

    require(pr.get("state") == "open", "PR is not open")
    require(pr.get("base", {}).get("ref") == "published", "base must be published")

    head = pr.get("head", {})
    base = pr.get("base", {})
    require(head.get("repo", {}).get("full_name") == args.repository, "fork PRs are not eligible")
    require(base.get("repo", {}).get("full_name") == args.repository, "unexpected base repository")

    head_ref = str(head.get("ref") or "")
    match = HEAD_RE.fullmatch(head_ref)
    require(match is not None, "head branch must match adam/genN-description")

    head_sha = str(head.get("sha") or "")
    base_sha = str(base.get("sha") or "")
    current_base_sha = str(args.current_base_sha or "")
    require(re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None, "invalid head SHA")
    require(re.fullmatch(r"[0-9a-f]{40}", current_base_sha) is not None, "invalid current base SHA")
    # Base metadata we cannot verify is never a human-review case.
    require(re.fullmatch(r"[0-9a-f]{40}", base_sha) is not None, "invalid PR base SHA")

    # The trust boundary is settled by here, so a draft is a known editorial
    # state rather than an untrustworthy one.
    require(isinstance(pr.get("draft"), bool), "PR draft flag is not boolean")
    if pr["draft"]:
        needs_human("DRAFT_PR", "PR is a draft and needs a human to mark it ready")

    require(isinstance(files, list), "files payload must be list")
    detect_noop_stale(args, files, compare)

    # Valid metadata that deterministically shows an old base. We know exactly
    # what this is: the candidate must be rebased by a person. It is never
    # merged and never mints a token, and the published ruleset independently
    # requires an up-to-date branch.
    if base_sha != current_base_sha:
        needs_human(
            "STALE_BASE",
            "PR base SHA is not current published; candidate needs a rebase",
        )

    require(compare.get("status") == "ahead", "head must be strictly ahead of current published")
    require(int(compare.get("behind_by", -1)) == 0, "head is behind/diverged from current published")
    require(int(compare.get("ahead_by", 0)) >= 1, "head contains no new commit")

    names = {str(x.get("filename")) for x in files if isinstance(x, dict)}
    require(names == ALLOWED_FILES, "changed files must be exactly events.json and manifest.json")
    require(len(files) == 2, "PR must change exactly two files")
    for row in files:
        require(row.get("status") == "modified", f"{row.get('filename')}: must be modified, not added/deleted")

    if require_validate_check:
        checks = load_json(args.checks)
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
        require(
            len(validate_runs) >= 1,
            "required validate check has not succeeded on current head",
        )

    base_events, base_manifest = verify_manifest(args.base_events, args.base_manifest, "base")
    head_events, head_manifest = verify_manifest(args.head_events, args.head_manifest, "head")

    base_generation = int(base_events["generation"])
    head_generation = int(head_events["generation"])
    require(head_generation == base_generation + 1, "generation must increment by exactly one")
    require(int(match.group("generation")) == head_generation, "branch generation must equal manifest generation")

    before = base_events["events"]
    after = head_events["events"]

    # Integrity first. Removing or rewriting published history is never a
    # review case; it means the candidate cannot be trusted at all.
    require(
        len(after) >= len(before),
        "published events must not be removed in autopublish",
    )
    require(
        after[:len(before)] == before,
        "existing published events are immutable in autopublish",
    )

    appended = len(after) - len(before)
    require(appended >= 1, "head contains no appended event")
    if appended > 1:
        # Purely additive, published history intact: a known editorial shape
        # that policy reserves for a human.
        needs_human(
            "MULTIPLE_EVENTS",
            f"autopublish permits one appended event; head appends {appended}",
        )

    new_event = after[-1]
    require(isinstance(new_event, dict), "new event must be object")

    publication_class = new_event.get("publication_class")
    require(
        publication_class in {"A", "B"},
        "unknown publication_class",
    )
    if publication_class == "B":
        needs_human(
            "CLASS_B_EDITORIAL",
            "publication_class B requires human editorial handling",
        )

    confidence = new_event.get("confidence", "verified")
    require(
        confidence in KNOWN_CONFIDENCE,
        "unknown confidence value",
    )
    if confidence != "verified":
        needs_human(
            "UNVERIFIED_CONFIDENCE",
            f"confidence {confidence} is below the autopublish threshold",
        )

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

    require_policy(
        not native_hits,
        "NATIVE_SOURCE_COVERED",
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

    require_policy(
        not duplicate_cves,
        "CVE_COVERED_PUBLISHED",
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
    require_policy(
        not duplicate_source_urls,
        "SOURCE_URL_COVERED_PUBLISHED",
        "primary source URL already covered by published content: "
        + ", ".join(duplicate_source_urls),
    )

    # Cross-surface coverage: AI-hot is an independent editorial surface.
    # Treat its public JSON strictly as untrusted blocking data. It can never
    # authorize publication; failure to load or validate it blocks autopublish.
    aihot = load_aihot_coverage(args.aihot_coverage)
    aihot_urls, aihot_cves, aihot_advisories = extract_aihot_coverage(aihot)

    cross_urls = sorted(new_source_urls & aihot_urls)
    require_policy(
        not cross_urls,
        "SOURCE_URL_COVERED_AIHOT",
        "primary source URL already covered by AI-hot: "
        + ", ".join(cross_urls),
    )

    cross_cves = sorted(new_cves & aihot_cves)
    require_policy(
        not cross_cves,
        "CVE_COVERED_AIHOT",
        "CVE already covered by AI-hot: "
        + ", ".join(cross_cves),
    )

    new_event_blob = json.dumps(new_event, ensure_ascii=False)
    new_advisories = {
        x.upper() for x in ADVISORY_RE.findall(new_event_blob)
    }
    cross_advisories = sorted(new_advisories & aihot_advisories)

    require_policy(
        not cross_advisories,
        "ADVISORY_COVERED_AIHOT",
        "advisory already covered by AI-hot: "
        + ", ".join(cross_advisories),
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
        "outcome": OUTCOME_ACTIONABLE,
        "reason_code": "ACTIONABLE",
        "notify_human": False,
        "technical_error": False,
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


def pr_context(path: Path) -> dict:
    """Best-effort PR identity for a skip payload. Never raises."""
    context: dict = {}
    try:
        pr = json.loads(path.read_text(encoding="utf-8"))
        number = pr.get("number")
        head_sha = str(pr.get("head", {}).get("sha") or "")
        head_ref = str(pr.get("head", {}).get("ref") or "")
    except Exception:
        return context

    if isinstance(number, int):
        context["pr_number"] = number
    if re.fullmatch(r"[0-9a-f]{40}", head_sha):
        context["head_sha"] = head_sha
    if head_ref and len(head_ref) <= 100 and head_ref.isprintable():
        context["head_ref"] = head_ref
    return context


def outcome_payload(exc: GateOutcome, pr_path: Path) -> dict:
    """Machine-readable terminal outcome for one candidate.

    ``notify_human`` is the contract for the notifier. A benign skip is a
    decision nobody can or needs to act on and must stay silent; NEEDS_HUMAN
    is the one non-publishable outcome a person genuinely has to see.
    """
    payload = {
        "decision": exc.outcome,
        "outcome": exc.outcome,
        "reason_code": exc.reason_code,
        "reason": str(exc),
        "notify_human": exc.outcome in NOTIFY_OUTCOMES,
        "technical_error": False,
    }
    payload.update(pr_context(pr_path))
    return payload


def blocked_payload(exc: GateError, pr_path: Path) -> dict:
    """A state we cannot safely act on. Always a technical error."""
    payload = {
        "decision": OUTCOME_BLOCKED,
        "outcome": OUTCOME_BLOCKED,
        "reason_code": "BLOCKED",
        "reason": str(exc),
        "notify_human": True,
        "technical_error": True,
    }
    payload.update(pr_context(pr_path))
    return payload


def emit(result: dict, json_out: Path | None) -> None:
    payload = json.dumps(result, ensure_ascii=False, sort_keys=True)
    print(payload)
    if json_out:
        json_out.write_text(payload + "\n", encoding="utf-8")


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
    ap.add_argument("--aihot-coverage", type=Path, required=True)
    ap.add_argument("--trusted-validator", type=Path, required=True)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    try:
        result = validate(args)
    except GateOutcome as exc:
        # Understood, deterministic and terminal for this candidate only.
        print(f"{exc.outcome} [{exc.reason_code}]: {exc}", file=sys.stderr)
        emit(outcome_payload(exc, args.pr), args.json_out)
        return NON_ACTIONABLE_EXIT_CODES[exc.outcome]
    except GateError as exc:
        print("BLOCKED:", exc, file=sys.stderr)
        emit(blocked_payload(exc, args.pr), args.json_out)
        return EXIT_BLOCKED

    emit(result, args.json_out)
    return EXIT_ACTIONABLE


if __name__ == "__main__":
    raise SystemExit(main())
