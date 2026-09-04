#!/usr/bin/env python3
"""Pure, state-free validation of generated AI-hot article content."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse


SCHEMA_PATH = Path(__file__).with_name("aihot-content-schema.json")


class ContentContractError(ValueError):
    pass


def fail(message: str) -> None:
    raise ContentContractError(message)


def load_contract(path: Path = SCHEMA_PATH) -> dict:
    if path.is_symlink() or not path.is_file():
        fail("content contract is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        fail("content contract JSON invalid")
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "provenance",
        "article",
    }:
        fail("content contract root invalid")
    if value.get("schema") != "gneu-aihot-content-contract-v1":
        fail("content contract schema invalid")
    if not isinstance(value.get("provenance"), dict):
        fail("content contract provenance invalid")
    if not isinstance(value.get("article"), dict):
        fail("content contract article invalid")
    return value


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{label} keys mismatch missing={missing} extra={extra}")


def text(value: object, label: str, max_bytes: int) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be string")
    value = value.strip()
    if not value:
        fail(f"{label} is empty")
    if "\x00" in value:
        fail(f"{label} contains NUL")
    if len(value.encode("utf-8")) > max_bytes:
        fail(f"{label} too large")
    return value


def parse_week(edition: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d{4})-W(\d{2})", edition)
    if not match:
        fail("invalid edition id")
    year, week = int(match.group(1)), int(match.group(2))
    try:
        date.fromisocalendar(year, week, 1)
    except ValueError:
        fail("invalid ISO week")
    return year, week


def date_in_week(value: object, edition: str, label: str) -> None:
    value = text(value, label, 32)
    try:
        article_date = date.fromisoformat(value)
    except ValueError:
        fail(f"{label} invalid ISO date")
    iso = article_date.isocalendar()
    if (iso.year, iso.week) != parse_week(edition):
        fail(f"{label} is outside {edition}")


def source_host(value: str) -> str:
    try:
        parsed = urlparse(value)
    except Exception:
        fail("invalid source URL")
    if parsed.scheme != "https":
        fail("source URL must use https")
    if not parsed.hostname:
        fail("source URL missing hostname")
    if parsed.username or parsed.password:
        fail("source URL must not contain credentials")
    host = parsed.hostname.lower().rstrip(".")
    if "." not in host or host == "localhost" or host.endswith(".local"):
        fail("source URL host is not public")
    try:
        if not ipaddress.ip_address(host).is_global:
            fail("source URL IP is not public")
    except ValueError:
        pass
    return host[4:] if host.startswith("www.") else host


def validate_string_array(value: object, label: str, min_items: int) -> None:
    if not isinstance(value, list) or len(value) < min_items:
        fail(f"{label} invalid")
    if not all(isinstance(item, str) and item.strip() for item in value):
        fail(f"{label} contains invalid item")


def validate_sources(article_id: str, value: object, rules: dict) -> set[str]:
    if not isinstance(value, list) or len(value) < rules["min_items"]:
        fail(f"article {article_id} has fewer than {rules['min_items']} sources")
    if len(value) > rules["max_items"]:
        fail(f"article {article_id} has too many sources")
    required = set(rules["required_keys"])
    limits = rules["field_max_bytes"]
    urls: set[str] = set()
    publishers: set[str] = set()
    hosts: set[str] = set()
    for index, source in enumerate(value):
        label = f"article {article_id} source[{index}]"
        if not isinstance(source, dict):
            fail(f"{label} invalid")
        exact_keys(source, required, label)
        publisher = text(source["publisher"], f"{label}.publisher", limits["publisher"])
        text(source["title"], f"{label}.title", limits["title"])
        url = text(source["url"], f"{label}.url", limits["url"])
        host = source_host(url)
        if url in urls:
            fail(f"article {article_id} has duplicate source URL")
        urls.add(url)
        publishers.add(re.sub(r"\s+", " ", publisher).casefold())
        hosts.add(host)
    if len(publishers) < rules["min_distinct_publishers"]:
        fail(f"article {article_id} lacks 2 distinct publishers")
    if len(hosts) < rules["min_distinct_hosts"]:
        fail(f"article {article_id} lacks 2 distinct source hosts")
    return urls


def validate_evidence(article_id: str, value: object, rules: dict, source_urls: set[str]) -> None:
    if not isinstance(value, dict):
        fail(f"article {article_id}.evidence invalid")
    required = set(rules["required_keys"])
    optional = set(rules["optional_keys"])
    if frozenset(value) not in {frozenset(required), frozenset(required | optional)}:
        fail(f"article {article_id}.evidence keys invalid")
    if value.get("grade") not in rules["grade_values"]:
        fail(f"article {article_id}.evidence.grade invalid")
    if value.get("verification") not in rules["verification_values"]:
        fail(f"article {article_id}.evidence.verification invalid")
    text(value.get("basis"), f"article {article_id}.evidence.basis", rules["basis_max_bytes"])
    if "claims" not in value:
        return
    claim_rules = rules["claims"]
    claims = value["claims"]
    if not isinstance(claims, list) or len(claims) < claim_rules["min_items"]:
        fail(f"article {article_id}.evidence.claims invalid")
    required_claim = set(claim_rules["required_keys"])
    for index, claim in enumerate(claims):
        label = f"article {article_id}.evidence.claims[{index}]"
        if not isinstance(claim, dict):
            fail(f"{label} invalid")
        exact_keys(claim, required_claim, label)
        claim_id = text(claim["id"], f"{label}.id", claim_rules["id_max_bytes"])
        if not re.fullmatch(claim_rules["id_pattern"], claim_id):
            fail(f"{label}.id invalid")
        text(claim["value"], f"{label}.value", claim_rules["value_max_bytes"])
        claim_url = text(
            claim["source_url"],
            f"{label}.source_url",
            claim_rules["source_url_max_bytes"],
        )
        source_host(claim_url)
        if claim_url not in source_urls:
            fail(f"{label} references unknown source_url")


def validate_article(
    article: object,
    edition: str,
    forbidden_ids: set[str],
    seen_ids: set[str],
    contract: dict,
) -> str:
    if not isinstance(article, dict):
        fail("delta article is not object")
    rules = contract["article"]
    exact_keys(article, set(rules["required_keys"]), "article")
    article_id = text(article["id"], "article.id", rules["id"]["max_bytes"])
    if not re.fullmatch(rules["id"]["pattern"], article_id):
        fail(f"invalid article id: {article_id}")
    if article_id in forbidden_ids or article_id in seen_ids:
        fail(f"article id already exists: {article_id}")
    if article["edition"] != edition:
        fail(f"article {article_id} points to wrong edition")
    date_in_week(article["date"], edition, f"article {article_id}.date")
    for field, maximum in rules["text_fields"].items():
        text(article[field], f"article {article_id}.{field}", maximum)
    validate_string_array(article["body"], f"article {article_id}.body", rules["body"]["min_items"])
    validate_string_array(
        article["builds_on"],
        f"article {article_id}.builds_on",
        rules["builds_on"]["min_items"],
    )
    source_urls = validate_sources(article_id, article["sources"], rules["sources"])
    validate_evidence(article_id, article["evidence"], rules["evidence"], source_urls)
    return article_id


def transparent_delta(base: dict, candidate: dict) -> dict[str, list]:
    """Return the append-only content suffix without enrichment or rewriting."""
    return {
        "editions": candidate["editions"][len(base["editions"]) :],
        "articles": candidate["articles"][len(base["articles"]) :],
    }
