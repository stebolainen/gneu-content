#!/usr/bin/env python3
"""Standalone validator for the gneu-content repository."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
EVENTS = ROOT / "events.json"
MANIFEST = ROOT / "manifest.json"

CATALOG = {
    "cisa-kev": {"cisa.gov", "www.cisa.gov"},
    "cert-se": {"cert.se", "www.cert.se"},
    "msrc": {"msrc.microsoft.com", "support.microsoft.com", "www.microsoft.com"},
    "first-epss": {"first.org", "www.first.org"},
    "ransomware-live": {"ransomware.live", "www.ransomware.live"},
    "uk-ncsc": {"ncsc.gov.uk", "www.ncsc.gov.uk"},
    "ncsc-fi": {"kyberturvallisuuskeskus.fi", "www.kyberturvallisuuskeskus.fi"},
    "cert-eu": {"cert.europa.eu"},
    "samsik": {"samsik.dk", "www.samsik.dk"},
}

TYPES = {"vulnerability","patch","advisory","incident","threat_report","ai_security"}
EVENT_KEYS = {
    "id","type","publication_class","occurred_at","updated_at","title","summary",
    "action","cves","deadline","sources","confidence","metrics"
}

def fail(msg: str) -> None:
    raise SystemExit("FAIL: " + msg)

def text(value, max_len: int, label: str) -> str:
    value = str(value or "").strip()
    if re.search(r"<[A-Za-z!/][^>]*>", value):
        fail(f"{label}: HTML is not allowed")
    if re.search(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", value):
        fail(f"{label}: control character")
    if re.search(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", value, re.I):
        fail(f"{label}: email address is not allowed")
    value = re.sub(r"\s+", " ", value)
    if len(value) > max_len:
        fail(f"{label}: too long")
    return value

def iso_datetime(value: str, label: str) -> None:
    try:
        dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    except Exception:
        fail(f"{label}: invalid ISO datetime")

def validate_event(e: dict) -> None:
    unknown = set(e) - EVENT_KEYS
    if unknown:
        fail("unknown event fields: " + ", ".join(sorted(unknown)))

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,119}", str(e.get("id",""))):
        fail("invalid event id")
    if e.get("type") not in TYPES:
        fail("invalid type")
    if e.get("publication_class") not in {"A","B"}:
        fail("publication_class must be A or B")

    iso_datetime(str(e.get("occurred_at","")), "occurred_at")
    iso_datetime(str(e.get("updated_at", e.get("occurred_at",""))), "updated_at")

    if not text(e.get("title"),160,"title"):
        fail("title is required")
    text(e.get("summary"),320,"summary")
    text(e.get("action"),280,"action")

    cves = e.get("cves", [])
    if not isinstance(cves,list) or len(cves) > 20:
        fail("cves must be a list with max 20 entries")
    for cve in cves:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(cve).upper()):
            fail("invalid CVE")

    deadline = e.get("deadline")
    if deadline:
        try:
            dt.date.fromisoformat(str(deadline))
        except Exception:
            fail("invalid deadline")

    sources = e.get("sources")
    if not isinstance(sources,list) or not (1 <= len(sources) <= 5):
        fail("sources must contain 1-5 primary sources")

    source_ids = set()
    for source in sources:
        if set(source) - {"id","url"}:
            fail("source may contain only id and url")
        sid = str(source.get("id","")).lower()
        if sid not in CATALOG:
            fail("unknown source id: " + sid)
        p = urlparse(str(source.get("url","")))
        if p.scheme != "https" or (p.hostname or "").lower() not in CATALOG[sid]:
            fail("source URL host is not allowed for " + sid)
        source_ids.add(sid)

    confidence = e.get("confidence","verified")
    if confidence not in {"verified","corroborated"}:
        fail("invalid confidence")
    if confidence == "corroborated" and len(source_ids) < 2:
        fail("corroborated requires at least two distinct source IDs")

    metrics = e.get("metrics", [])
    if not isinstance(metrics,list) or len(metrics) > 4:
        fail("metrics must be a list with max 4 entries")
    for m in metrics:
        if set(m) != {"label","value"}:
            fail("metric must contain exactly label and value")
        text(m["label"],40,"metric label")
        text(m["value"],60,"metric value")

def load_events() -> dict:
    try:
        data = json.loads(EVENTS.read_text())
    except Exception as exc:
        fail("events.json: " + str(exc))
    if data.get("schema") != "gneu-content-events-v1":
        fail("events schema")
    if not isinstance(data.get("generation"),int) or data["generation"] < 1:
        fail("events generation")
    events = data.get("events")
    if not isinstance(events,list) or len(events) > 200:
        fail("events list")
    ids = set()
    for event in events:
        if not isinstance(event,dict):
            fail("event must be an object")
        validate_event(event)
        if event["id"] in ids:
            fail("duplicate event id: " + event["id"])
        ids.add(event["id"])
    return data

def build_manifest(events: dict) -> dict:
    raw = EVENTS.read_bytes()
    return {
        "schema":"gneu-content-manifest-v1",
        "generation":events["generation"],
        "generated_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),
        "events_sha256":hashlib.sha256(raw).hexdigest(),
        "event_count":len(events["events"]),
    }

def validate_manifest(events: dict) -> None:
    try:
        manifest = json.loads(MANIFEST.read_text())
    except Exception as exc:
        fail("manifest.json: " + str(exc))
    if manifest.get("schema") != "gneu-content-manifest-v1":
        fail("manifest schema")
    if manifest.get("generation") != events["generation"]:
        fail("generation mismatch")
    if manifest.get("event_count") != len(events["events"]):
        fail("event_count mismatch")
    if manifest.get("events_sha256") != hashlib.sha256(EVENTS.read_bytes()).hexdigest():
        fail("events_sha256 mismatch")
    iso_datetime(str(manifest.get("generated_at","")), "manifest generated_at")

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-manifest", action="store_true")
    args = ap.parse_args()

    events = load_events()
    if args.write_manifest:
        MANIFEST.write_text(json.dumps(build_manifest(events), indent=2, ensure_ascii=False) + "\n")
    validate_manifest(events)
    print(f"OK: generation {events['generation']} · {len(events['events'])} events")

if __name__ == "__main__":
    main()
