#!/usr/bin/env python3
"""State-free editorial checks for one newly generated AI-hot article.

This is deliberately a pre-handoff authoring aid, not a READY, retry, release,
or fast-lane control.  It reads only the supplied draft and persists nothing.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


# Small on purpose: these are terms whose unexplained use repeatedly made the
# published archive hard to read.  A match requests an editorial rewrite; it
# does not claim that every occurrence is wrong or alter the candidate.
TERM_HINTS = {
    "CI/CD": ("bygg", "driftsätt", "pipeline"),
    "MCP": ("model context protocol", "protokoll", "verktyg"),
    "RBAC": ("rollbaserad", "behörighet", "åtkomst"),
    "RCE": ("kodkörning", "köra kod", "fjärrkörning"),
    "CVSS": ("allvarlighetsgrad", "poäng", "bedömning"),
    "API": ("programmeringsgränssnitt", "gränssnitt", "tjänst"),
    "OAuth": ("delegerad", "inloggning", "auktorisering"),
    "EDR": ("endpoint", "ändpunkt", "detektering"),
    "IAM": ("identitet", "åtkomsthantering", "behörighet"),
    "NVD": ("sårbarhetsdatabas", "nationella sårbarhetsdatabasen"),
    "KEV": ("kända utnyttjade sårbarheter", "aktivt utnyttjade"),
    "ATT&CK": ("ramverk", "teknik", "taktik"),
}

ACTOR_HINTS = {
    "Unit 42": ("palo alto networks", "hotforskningsgrupp", "hotforskning"),
    "CISA": ("myndighet", "amerikanska", "usa"),
    "NCSC": ("national cyber security centre", "myndighet", "brittiska", "svenska"),
    "MITRE": ("organisation", "ramverk", "ideell"),
}

INTERNAL_REFERENCES = (
    r"samma intrång som tidigare",
    r"som tidigare bevakning",
    r"som vi tidigare rapporterat",
    r"denna kampanj",
    r"rapporten",
)
STOP_WORDS = {
    "att", "det", "den", "denna", "de", "en", "ett", "er", "era", "från",
    "för", "har", "i", "inte", "med", "ni", "och", "om", "på", "som", "till",
    "var", "vad", "är", "så", "utan", "vid", "av", "nu", "kan", "ska",
}
PROTECTED_FIELDS = ("sources", "evidence", "severity")


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    findings: tuple[str, ...]


def article_text(article: dict) -> str:
    body = article.get("body", [])
    if not isinstance(body, list):
        body = []
    return " ".join(str(article.get(key, "")) for key in ("summary",)) + " " + " ".join(map(str, body))


def first_sentences(text: str, count: int = 2) -> str:
    pieces = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(pieces[:count])


def introduced(text: str, term: str, hints: tuple[str, ...]) -> bool:
    match = re.search(rf"\b{re.escape(term)}\b", text, flags=re.IGNORECASE)
    if not match:
        return True
    window = text[max(0, match.start() - 80) : match.end() + 140].casefold()
    return any(hint in window for hint in hints)


def actor_terms_check(article: dict) -> Check:
    text = article_text(article)
    findings = []
    for actor, hints in ACTOR_HINTS.items():
        if re.search(rf"\b{re.escape(actor)}\b", text, re.IGNORECASE) and not introduced(text, actor, hints):
            findings.append(f"introducera aktören {actor} med roll eller organisation")
    for term, hints in TERM_HINTS.items():
        if re.search(rf"\b{re.escape(term)}\b", text, re.IGNORECASE) and not introduced(text, term, hints):
            findings.append(f"förklara första relevanta {term}")
    return Check("reader_context_actor_terms", "REWRITE" if findings else "PASS", tuple(findings))


def standalone_check(article: dict) -> Check:
    opening = first_sentences(article_text(article)).casefold()
    findings = []
    for pattern in INTERNAL_REFERENCES:
        if re.search(pattern, opening):
            # A named incident before the backward reference is sufficient for
            # this deliberately modest heuristic; a human/editorial rewrite
            # remains responsible for the actual context.
            before = opening[: re.search(pattern, opening).start()]
            if not re.search(r"\b(?:intrång|attack|sårbarhet|kampanj)\b.{0,90}\b(?:hos|mot|i)\b", before):
                findings.append(f"återintroducera referenten för '{pattern}'")
    return Check("reader_context_standalone", "REWRITE" if findings else "PASS", tuple(findings))


def tokens(text: str) -> set[str]:
    return {
        word for word in re.findall(r"[a-zåäö0-9]{3,}", text.casefold())
        if word not in STOP_WORDS
    }


def similarity(left: str, right: str) -> float:
    a, b = tokens(left), tokens(right)
    return len(a & b) / len(a | b) if a and b else 0.0


def distinct_fields_check(article: dict) -> Check:
    fields = {key: str(article.get(key, "")) for key in ("summary", "why", "action")}
    findings = []
    for left, right in (("summary", "why"), ("summary", "action"), ("why", "action")):
        score = similarity(fields[left], fields[right])
        if score >= 0.72:
            findings.append(f"{left}/{right} överlappar (tokenlikhet {score:.2f})")
    return Check("reader_context_distinct_fields", "REWRITE" if findings else "PASS", tuple(findings))


def check_article(article: dict) -> tuple[Check, Check, Check]:
    """Return the three required checks without mutating article or state."""
    return actor_terms_check(article), standalone_check(article), distinct_fields_check(article)


def bounded_rewrite(
    article: dict, rewrite: Callable[[dict], dict],
) -> tuple[dict, tuple[Check, Check, Check], int]:
    """Permit one caller-supplied rewrite and protect factual/evidence fields."""
    checks = check_article(article)
    if all(check.status == "PASS" for check in checks):
        return article, checks, 0
    original = copy.deepcopy(article)
    rewritten = rewrite(copy.deepcopy(article))
    if not isinstance(rewritten, dict):
        raise ValueError("rewrite must return an article object")
    for field in PROTECTED_FIELDS:
        if rewritten.get(field) != original.get(field):
            raise ValueError(f"rewrite changed protected {field}")
    return rewritten, check_article(rewritten), 1


def render(checks: tuple[Check, Check, Check]) -> dict:
    return {
        "status": "PASS" if all(check.status == "PASS" for check in checks) else "REWRITE",
        "checks": [
            {"name": check.name, "status": check.status, "findings": list(check.findings)}
            for check in checks
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-hot reader-context check")
    parser.add_argument("--article", type=Path, required=True)
    args = parser.parse_args()
    try:
        article = json.loads(args.article.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"EDITORIAL_REVIEW_REQUIRED invalid article draft: {exc}")
    if not isinstance(article, dict):
        raise SystemExit("EDITORIAL_REVIEW_REQUIRED article draft is not an object")
    result = render(check_article(article))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if result["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
