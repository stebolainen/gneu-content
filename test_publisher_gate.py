#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("publisher_gate", ROOT / "publisher_gate.py")
gate = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(gate)

N = 0
def ok(cond, label):
    global N
    N += 1
    if not cond:
        raise SystemExit("FAIL: " + label)

VALIDATOR = ROOT / "validate_content.py"

base_event = {
    "id":"cisa-kev:CVE-2025-62593",
    "type":"vulnerability",
    "publication_class":"A",
    "occurred_at":"2026-08-17T00:00:00Z",
    "updated_at":"2026-08-17T00:00:00Z",
    "title":"CVE-2025-62593 i Ray tillagd i CISA KEV",
    "summary":"CISA har lagt till CVE-2025-62593 i KEV.",
    "action":"Tillämpa leverantörens åtgärder.",
    "cves":["CVE-2025-62593"],
    "deadline":"2026-08-20",
    "sources":[{"id":"cisa-kev","url":"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}],
    "confidence":"verified"
}
new_event = {
    "id":"uk-ncsc:CVE-2026-12345",
    "type":"vulnerability",
    "publication_class":"A",
    "occurred_at":"2026-08-19T00:00:00Z",
    "updated_at":"2026-08-19T00:00:00Z",
    "title":"Testevent för publisher gate",
    "summary":"Verifierbart testevent.",
    "action":"Tillämpa leverantörens säkerhetsuppdatering.",
    "cves":["CVE-2026-12345"],
    "sources":[{"id":"uk-ncsc","url":"https://www.ncsc.gov.uk/news/test-event"}],
    "confidence":"verified"
}

def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def make_manifest(events_path, generation, count):
    return {
        "schema":"gneu-content-manifest-v1",
        "generation":generation,
        "generated_at":"2026-08-19T07:30:00Z",
        "events_sha256":hashlib.sha256(events_path.read_bytes()).hexdigest(),
        "event_count":count,
    }

class Args: pass

with tempfile.TemporaryDirectory(prefix="gate-test-") as td:
    d=Path(td)
    base_events={"schema":"gneu-content-events-v1","generation":2,"events":[base_event]}
    head_events={"schema":"gneu-content-events-v1","generation":3,"events":[base_event,new_event]}
    write_json(d/"base-events.json",base_events)
    write_json(d/"head-events.json",head_events)
    write_json(d/"base-manifest.json",make_manifest(d/"base-events.json",2,1))
    write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))

    empty_aihot = {
        "generated": "2026-08-26T04:07:10+00:00",
        "editions": [],
        "articles": [],
    }
    write_json(d/"aihot.json", empty_aihot)

    sha_head="b"*40
    sha_base="a"*40
    pr={
        "number":7,"state":"open","draft":False,
        "base":{"ref":"published","sha":sha_base,"repo":{"full_name":"stebolainen/gneu-content"}},
        "head":{"ref":"adam/gen3-test-event","sha":sha_head,"repo":{"full_name":"stebolainen/gneu-content"}},
    }
    files=[
        {"filename":"events.json","status":"modified"},
        {"filename":"manifest.json","status":"modified"},
    ]
    checks={"check_runs":[{"name":"validate","head_sha":sha_head,"status":"completed","conclusion":"success","app":{"slug":"github-actions"}}]}
    compare={"status":"ahead","behind_by":0,"ahead_by":1}

    for name,obj in [("pr.json",pr),("files.json",files),("checks.json",checks),("compare.json",compare)]:
        write_json(d/name,obj)

    def args():
        a=Args()
        a.repository="stebolainen/gneu-content"
        a.current_base_sha=sha_base
        a.pr=d/"pr.json"; a.files=d/"files.json"; a.checks=d/"checks.json"; a.compare=d/"compare.json"
        a.base_events=d/"base-events.json"; a.base_manifest=d/"base-manifest.json"
        a.head_events=d/"head-events.json"; a.head_manifest=d/"head-manifest.json"
        a.aihot_coverage=d/"aihot.json"
        a.trusted_validator=VALIDATOR
        return a

    res=gate.validate(args())
    ok(res["decision"]=="PASS_AUTOPUBLISH","happy path")
    ok(res["generation"]==3,"generation 3")
    ok(res["event_id"]=="uk-ncsc:CVE-2026-12345","event id")

    native_sources = [
        (
            "cisa-kev",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        (
            "msrc",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
        ),
        (
            "cert-se",
            "https://www.cert.se/2026/08/test-event.html",
        ),
    ]

    for source_id, source_url in native_sources:
        native = deepcopy(head_events)
        native["events"][-1]["id"] = f"{source_id}:CVE-2026-12345"
        native["events"][-1]["sources"] = [
            {"id": source_id, "url": source_url}
        ]
        write_json(d/"head-events.json", native)
        write_json(
            d/"head-manifest.json",
            make_manifest(d/"head-events.json", 3, 2),
        )
        try:
            gate.validate(args())
            ok(False, f"native source {source_id} must block")
        except gate.GateError:
            ok(True, f"native source {source_id} blocked")

    write_json(d/"head-events.json", head_events)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )

    cisa_advisory = deepcopy(head_events)
    cisa_advisory["events"][-1]["id"] = "cisa:AA26-999A"
    cisa_advisory["events"][-1]["sources"] = [{
        "id": "cisa-kev",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-999a",
    }]
    write_json(d/"head-events.json", cisa_advisory)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )
    res = gate.validate(args())
    ok(
        res["event_id"] == "cisa:AA26-999A",
        "non-KEV CISA advisory remains eligible",
    )

    write_json(d/"head-events.json", head_events)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )

    # A different event ID/source must not allow an already-covered CVE
    # to be autopublished again.
    duplicate_cve = deepcopy(head_events)
    duplicate_cve["events"][-1]["id"] = "uk-ncsc:duplicate-cve-test"
    duplicate_cve["events"][-1]["cves"] = ["CVE-2025-62593"]
    duplicate_cve["events"][-1]["sources"] = [{
        "id": "uk-ncsc",
        "url": "https://www.ncsc.gov.uk/news/different-advisory",
    }]
    write_json(d/"head-events.json", duplicate_cve)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )
    try:
        gate.validate(args())
        ok(False, "existing CVE must block")
    except gate.GateError:
        ok(True, "existing CVE blocked")

    # Same primary-source URL under a different event ID must also block.
    source_base = deepcopy(base_events)
    source_base["events"][0]["id"] = "uk-ncsc:prior-advisory"
    source_base["events"][0]["sources"] = [{
        "id": "uk-ncsc",
        "url": "https://www.ncsc.gov.uk/news/existing-advisory/",
    }]
    source_base["events"][0]["cves"] = []

    source_head = deepcopy(source_base)
    source_head["generation"] = 3
    duplicate_source_event = deepcopy(new_event)
    duplicate_source_event["id"] = "uk-ncsc:different-event-id"
    duplicate_source_event["cves"] = []
    duplicate_source_event["sources"] = [{
        "id": "uk-ncsc",
        "url": "https://www.ncsc.gov.uk/news/existing-advisory",
    }]
    source_head["events"].append(duplicate_source_event)

    write_json(d/"base-events.json", source_base)
    write_json(
        d/"base-manifest.json",
        make_manifest(d/"base-events.json", 2, 1),
    )
    write_json(d/"head-events.json", source_head)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )

    try:
        gate.validate(args())
        ok(False, "existing source URL must block")
    except gate.GateError:
        ok(True, "existing source URL blocked")

    # Restore canonical fixtures for remaining tests.
    write_json(d/"base-events.json", base_events)
    write_json(
        d/"base-manifest.json",
        make_manifest(d/"base-events.json", 2, 1),
    )
    write_json(d/"head-events.json", head_events)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )

    # Cross-surface duplicate: exact primary-source URL already exists in AI-hot.
    aihot_url = deepcopy(empty_aihot)
    aihot_url["articles"] = [{
        "id": "2026-w99-existing-source",
        "title": "Already covered in AI-hot",
        "sources": [{
            "title": "Primary source",
            "url": "https://www.ncsc.gov.uk/news/test-event/",
            "publisher": "NCSC",
        }],
    }]
    write_json(d/"aihot.json", aihot_url)

    try:
        gate.validate(args())
        ok(False, "AI-hot source URL overlap must block")
    except gate.GateError:
        ok(True, "AI-hot source URL overlap blocked")

    write_json(d/"aihot.json", empty_aihot)

    # Cross-surface duplicate: same advisory ID, even when source URLs differ.
    advisory_head = deepcopy(head_events)
    advisory_head["events"][-1]["id"] = "cisa:AA26-999A"
    advisory_head["events"][-1]["cves"] = []
    advisory_head["events"][-1]["sources"] = [{
        "id": "cisa-kev",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-999a",
    }]
    write_json(d/"head-events.json", advisory_head)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )

    aihot_advisory = deepcopy(empty_aihot)
    aihot_advisory["articles"] = [{
        "id": "2026-w99-existing-advisory",
        "title": "AI-hot already covers advisory AA26-999A",
        "sources": [{
            "title": "Secondary source",
            "url": "https://example.com/report/related",
            "publisher": "Example",
        }],
    }]
    write_json(d/"aihot.json", aihot_advisory)

    try:
        gate.validate(args())
        ok(False, "AI-hot advisory overlap must block")
    except gate.GateError:
        ok(True, "AI-hot advisory overlap blocked")

    # Restore canonical event fixture.
    write_json(d/"head-events.json", head_events)
    write_json(
        d/"head-manifest.json",
        make_manifest(d/"head-events.json", 3, 2),
    )
    write_json(d/"aihot.json", empty_aihot)

    # Cross-surface duplicate: CVE occurs in AI-hot article data.
    aihot_cve = deepcopy(empty_aihot)
    aihot_cve["articles"] = [{
        "id": "2026-w99-existing-cve",
        "title": "Patch CVE-2026-12345 immediately",
        "sources": [{
            "title": "Separate source",
            "url": "https://example.com/security/article",
            "publisher": "Example",
        }],
    }]
    write_json(d/"aihot.json", aihot_cve)

    try:
        gate.validate(args())
        ok(False, "AI-hot CVE overlap must block")
    except gate.GateError:
        ok(True, "AI-hot CVE overlap blocked")

    # Coverage is fail-closed: malformed JSON must never permit autopublish.
    (d/"aihot.json").write_text("{broken", encoding="utf-8")
    try:
        gate.validate(args())
        ok(False, "malformed AI-hot coverage must block")
    except gate.GateError:
        ok(True, "malformed AI-hot coverage blocked")

    # Coverage is also fail-closed when the file is unavailable.
    (d/"aihot.json").unlink()
    try:
        gate.validate(args())
        ok(False, "missing AI-hot coverage must block")
    except gate.GateError:
        ok(True, "missing AI-hot coverage blocked")

    # Restore valid coverage for all remaining regression tests.
    write_json(d/"aihot.json", empty_aihot)

    bad=deepcopy(files); bad.append({"filename":"AGENTS.md","status":"modified"}); write_json(d/"files.json",bad)
    try: gate.validate(args()); ok(False,"workflow file set must block")
    except gate.GateError: ok(True,"extra file blocked")
    write_json(d/"files.json",files)

    bad=deepcopy(pr); bad["head"]["ref"]="feature/gen3"; write_json(d/"pr.json",bad)
    try: gate.validate(args()); ok(False,"bad branch")
    except gate.GateError: ok(True,"bad branch blocked")
    write_json(d/"pr.json",pr)

    bad=deepcopy(pr); bad["head"]["repo"]["full_name"]="attacker/fork"; write_json(d/"pr.json",bad)
    try: gate.validate(args()); ok(False,"fork")
    except gate.GateError: ok(True,"fork blocked")
    write_json(d/"pr.json",pr)

    bad=deepcopy(compare); bad["status"]="diverged"; bad["behind_by"]=1; write_json(d/"compare.json",bad)
    try: gate.validate(args()); ok(False,"diverged")
    except gate.GateError: ok(True,"diverged blocked")
    write_json(d/"compare.json",compare)

    bad=deepcopy(checks); bad["check_runs"][0]["conclusion"]="failure"; write_json(d/"checks.json",bad)
    try: gate.validate(args()); ok(False,"failed CI")
    except gate.GateError: ok(True,"failed CI blocked")
    write_json(d/"checks.json",checks)

    mutated=deepcopy(head_events); mutated["events"][0]["title"]="MUTATED"; write_json(d/"head-events.json",mutated)
    write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))
    try: gate.validate(args()); ok(False,"existing event mutation")
    except gate.GateError: ok(True,"existing event mutation blocked")
    write_json(d/"head-events.json",head_events); write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))

    class_b=deepcopy(head_events); class_b["events"][-1]["publication_class"]="B"; write_json(d/"head-events.json",class_b)
    write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))
    try: gate.validate(args()); ok(False,"class B")
    except gate.GateError: ok(True,"class B blocked")
    write_json(d/"head-events.json",head_events); write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))

    jump=deepcopy(head_events); jump["generation"]=4; write_json(d/"head-events.json",jump)
    write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",4,2))
    try: gate.validate(args()); ok(False,"generation jump")
    except gate.GateError: ok(True,"generation jump blocked")
    write_json(d/"head-events.json",head_events); write_json(d/"head-manifest.json",make_manifest(d/"head-events.json",3,2))

    broken=json.loads((d/"head-manifest.json").read_text()); broken["events_sha256"]="0"*64; write_json(d/"head-manifest.json",broken)
    try: gate.validate(args()); ok(False,"hash mismatch")
    except gate.GateError: ok(True,"hash mismatch blocked")

print(f"gneu-content 9.9 publisher gate OK · {N} kontroller")
