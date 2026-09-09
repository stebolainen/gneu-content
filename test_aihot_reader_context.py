#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PATH = ROOT / "runtime/aihot/generation/gneu-aihot-reader-context.py"
SPEC = importlib.util.spec_from_file_location("aihot_reader_context", PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def article(summary: str, why: str, action: str) -> dict:
    return {
        "id": "2026-w36-reader-context",
        "severity": "high",
        "summary": summary,
        "body": ["Den tekniska beskrivningen ger tillräcklig avgränsning."],
        "why": why,
        "action": action,
        "sources": [{"publisher": "Example", "url": "https://example.test/a"}],
        "evidence": {"claims": [{"id": "one", "value": "v", "source_url": "https://example.test/a"}]},
    }


def statuses(value: tuple) -> dict[str, str]:
    return {check.name: check.status for check in value}


class ReaderContextTests(unittest.TestCase):
    def test_unintroduced_unit42_and_cicd_request_rewrite(self) -> None:
        value = article(
            "Unit 42 beskriver en attack mot CI/CD som gav angriparen åtkomst.",
            "Attacken visar att processen behöver skyddas.",
            "Granska era byggflöden.",
        )
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_actor_terms"], "REWRITE")

    def test_introduced_unit42_and_cicd_pass(self) -> None:
        value = article(
            "Palo Alto Networks hotforskningsgrupp Unit 42 beskriver en attack mot CI/CD, automatiserade bygg- och driftsättningsflöden, i ett företags utvecklingsmiljö.",
            "En angripare kan annars gå från byggmiljön till känsliga system.",
            "Begränsa behörigheter i byggflöden och rotera exponerade nycklar.",
        )
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_actor_terms"], "PASS")

    def test_internal_reference_without_reintroduction_requests_rewrite(self) -> None:
        value = article(
            "Samma intrång som tidigare bevakning visar att angriparen blev snabbare.",
            "Det förkortar organisationens tid att upptäcka angreppet.",
            "Kontrollera loggning och åtkomstvägar.",
        )
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_standalone"], "REWRITE")

    def test_reintroduced_incident_can_refer_to_previous_coverage(self) -> None:
        value = article(
            "Ett intrång hos exempelorganisationen via en felkonfigurerad AI-agent har nu fått en ny tidslinje. Samma intrång som tidigare bevakning beskrev visar att angriparen förberedde sig längre än känt.",
            "Den längre förberedelsen minskar tiden för försvararen att upptäcka nästa steg.",
            "Kontrollera att agenten saknar onödiga åtkomster.",
        )
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_standalone"], "PASS")

    def test_duplicate_summary_why_action_requests_rewrite(self) -> None:
        same = "En angripare kan använda en sårbar AI-agent för att nå interna system."
        value = article(same, same, same)
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_distinct_fields"], "REWRITE")

    def test_distinct_fields_and_advanced_context_pass(self) -> None:
        value = article(
            "En oautentiserad API-tjänst i AI-agentplattformen Langflow kunde ge angripare administrativ åtkomst till organisationens agentflöden.",
            "Eftersom flöden ofta får läsa data och använda tjänstekonton kan ett intrång ge bredare åtkomst än den exponerade tjänsten.",
            "Uppdatera Langflow och begränsa tjänsten till autentiserade interna nät.",
        )
        result = statuses(CHECKER.check_article(value))
        self.assertEqual(result["reader_context_actor_terms"], "PASS")
        self.assertEqual(result["reader_context_standalone"], "PASS")
        self.assertEqual(result["reader_context_distinct_fields"], "PASS")

    def test_one_rewrite_preserves_facts_and_does_not_persist_state(self) -> None:
        original = article(
            "Unit 42 beskriver en attack mot CI/CD.",
            "Attacken visar att processen behöver skyddas.",
            "Granska era byggflöden.",
        )
        calls = 0

        def rewrite(draft: dict) -> dict:
            nonlocal calls
            calls += 1
            draft["summary"] = "Palo Alto Networks hotforskningsgrupp Unit 42 beskriver en attack mot CI/CD, automatiserade bygg- och driftsättningsflöden, i en utvecklingsmiljö."
            return draft

        rewritten, _, count = CHECKER.bounded_rewrite(original, rewrite)
        self.assertEqual(count, 1)
        self.assertEqual(calls, 1)
        for field in CHECKER.PROTECTED_FIELDS:
            self.assertEqual(rewritten[field], original[field])

        # A failed package is just a local return value: no package ID, READY,
        # retry or liveness state is accepted or created by this pure helper.
        second, result, count = CHECKER.bounded_rewrite(
            original, lambda draft: copy.deepcopy(draft)
        )
        self.assertEqual(count, 1)
        self.assertTrue(any(check.status == "REWRITE" for check in result))
        self.assertEqual(second["id"], original["id"])

    def test_rewrite_cannot_change_evidence_or_sources(self) -> None:
        original = article(
            "Unit 42 beskriver en attack mot CI/CD.",
            "Attacken visar att processen behöver skyddas.",
            "Granska era byggflöden.",
        )

        def bad_rewrite(draft: dict) -> dict:
            draft["sources"] = []
            return draft

        with self.assertRaisesRegex(ValueError, "protected sources"):
            CHECKER.bounded_rewrite(original, bad_rewrite)


if __name__ == "__main__":
    unittest.main(verbosity=2)
