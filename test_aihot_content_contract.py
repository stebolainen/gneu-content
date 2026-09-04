#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "runtime/aihot/bin"
GENERATION = ROOT / "runtime/aihot/generation"
FIXTURES = ROOT / "runtime/aihot/tests/fixtures"
R1_CANDIDATE_SHA256 = "593f334a75764552e069e995cc241d04d5e001d73d4ef3444cd706fa24b45b40"
R1_ARTICLE_CANONICAL_SHA256 = "0d4864352368b0d74f0ea3792d42a3d01f50882f9440a1052cde42fbfcdf2e95"
sys.path.insert(0, str(BIN))

import aihot_content_contract as contract


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


handoff_validator = load(
    "aihot_evidence_handoff_validator",
    GENERATION / "gneu-aihot-handoff-validate.py",
)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def authoritative_simulation(article: object, edition: str = "2026-W36") -> None:
    oracle = fixture("gneu-se-aihot-article-contract-4bb9ba39.json")
    if not isinstance(article, dict):
        raise ValueError("article is not object")
    expected = set(oracle["article_keys"])
    actual = set(article)
    if actual != expected:
        raise ValueError(
            f"article keys mismatch missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )
    if article["edition"] != edition:
        raise ValueError("article edition mismatch")
    iso = date.fromisoformat(article["date"]).isocalendar()
    if (iso.year, iso.week) != (2026, 36):
        raise ValueError("article date outside edition")
    sources = article["sources"]
    if not isinstance(sources, list) or not 2 <= len(sources) <= 12:
        raise ValueError("source count")
    for source in sources:
        if not isinstance(source, dict) or set(source) != set(oracle["source_keys"]):
            raise ValueError("source keys")
    evidence = article["evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("evidence type")
    required = set(oracle["evidence_required_keys"])
    optional = set(oracle["evidence_optional_keys"])
    if set(evidence) not in (required, required | optional):
        raise ValueError("evidence keys")
    if evidence["grade"] not in oracle["grade_values"]:
        raise ValueError("evidence grade")
    if evidence["verification"] not in oracle["verification_values"]:
        raise ValueError("evidence verification")
    if not isinstance(evidence["basis"], str) or not evidence["basis"].strip():
        raise ValueError("evidence basis")
    if "claims" in evidence:
        if not isinstance(evidence["claims"], list) or not evidence["claims"]:
            raise ValueError("claims")
        for claim in evidence["claims"]:
            if not isinstance(claim, dict) or set(claim) != set(oracle["claim_keys"]):
                raise ValueError("claim keys")


class PureContentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = contract.load_contract()
        self.valid = fixture("valid-article.json")

    def validate(self, article: object, *, forbidden=None, seen=None) -> str:
        return contract.validate_article(
            article,
            "2026-W36",
            forbidden or set(),
            seen or set(),
            self.schema,
        )

    def test_schema_matches_pinned_authoritative_contract(self) -> None:
        oracle = fixture("gneu-se-aihot-article-contract-4bb9ba39.json")
        article = self.schema["article"]
        provenance = self.schema["provenance"]
        self.assertEqual(set(article["required_keys"]), set(oracle["article_keys"]))
        self.assertEqual(
            set(article["sources"]["required_keys"]), set(oracle["source_keys"])
        )
        self.assertEqual(
            set(article["evidence"]["required_keys"]),
            set(oracle["evidence_required_keys"]),
        )
        self.assertEqual(
            set(article["evidence"]["optional_keys"]),
            set(oracle["evidence_optional_keys"]),
        )
        self.assertEqual(
            set(article["evidence"]["claims"]["required_keys"]),
            set(oracle["claim_keys"]),
        )
        self.assertEqual(
            set(article["evidence"]["grade_values"]), set(oracle["grade_values"])
        )
        self.assertEqual(
            set(article["evidence"]["verification_values"]),
            set(oracle["verification_values"]),
        )
        self.assertEqual(provenance["repository"], "stebolainen/gneu-se")
        self.assertEqual(provenance["ref"], oracle["source_ref"])
        self.assertEqual(provenance["validator_path"], oracle["source_path"])
        self.assertEqual(provenance["blob_sha"], oracle["source_blob_sha"])
        self.assertEqual(provenance["sha256"], oracle["source_sha256"])

    def test_adam_contract_requires_original_evidence(self) -> None:
        generation_contract = (GENERATION / "CONTRACT.md").read_text(encoding="utf-8")
        adam_daily = (GENERATION / "ADAM_DAILY.md").read_text(encoding="utf-8")
        self.assertIn("aihot-content-schema.json", generation_contract)
        self.assertIn("`evidence` is mandatory", generation_contract)
        self.assertIn("must never invent", generation_contract)
        self.assertIn("strict `no-change`", generation_contract)
        self.assertIn("`evidence` is mandatory content", adam_daily)
        self.assertIn("Never ask or rely on the bridge to invent", adam_daily)
        self.assertIn("strict `no-change`", adam_daily)

    def test_valid_fixture_passes_local_and_authoritative(self) -> None:
        self.assertEqual(self.validate(self.valid), self.valid["id"])
        authoritative_simulation(self.valid)

    def test_current_r1_shape_missing_evidence_is_blocked(self) -> None:
        invalid = fixture("invalid-missing-evidence.json")
        canonical = json.dumps(
            invalid,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            R1_ARTICLE_CANONICAL_SHA256,
            f"fixture derived from immutable candidate {R1_CANDIDATE_SHA256}",
        )
        expected = "article keys mismatch missing=['evidence'] extra=[]"
        with self.assertRaisesRegex(contract.ContentContractError, "missing=.*evidence") as caught:
            self.validate(invalid)
        self.assertEqual(str(caught.exception), expected)
        with self.assertRaisesRegex(ValueError, "missing=.*evidence") as remote:
            authoritative_simulation(invalid)
        self.assertEqual(str(remote.exception), expected)

    def test_malformed_evidence_is_blocked(self) -> None:
        variants = []
        value = copy.deepcopy(self.valid)
        value["evidence"] = "strong"
        variants.append(value)
        value = copy.deepcopy(self.valid)
        del value["evidence"]["basis"]
        variants.append(value)
        value = copy.deepcopy(self.valid)
        value["evidence"]["grade"] = "unbounded"
        variants.append(value)
        value = copy.deepcopy(self.valid)
        value["evidence"]["verification"] = "assumed"
        variants.append(value)
        value = copy.deepcopy(self.valid)
        value["evidence"]["claims"][0]["source_url"] = "https://unknown.example/x"
        variants.append(value)
        for article in variants:
            with self.subTest(article=article["evidence"]):
                with self.assertRaises(contract.ContentContractError):
                    self.validate(article)

    def test_missing_and_extra_article_keys_are_blocked(self) -> None:
        missing = copy.deepcopy(self.valid)
        del missing["summary"]
        extra = copy.deepcopy(self.valid)
        extra["remote_only"] = True
        for article in (missing, extra):
            with self.assertRaisesRegex(contract.ContentContractError, "keys mismatch"):
                self.validate(article)

    def test_invalid_source_schema_and_cardinality_are_blocked(self) -> None:
        missing_key = copy.deepcopy(self.valid)
        del missing_key["sources"][0]["title"]
        too_few = copy.deepcopy(self.valid)
        too_few["sources"] = too_few["sources"][:1]
        duplicate = copy.deepcopy(self.valid)
        duplicate["sources"][1]["url"] = duplicate["sources"][0]["url"]
        for article in (missing_key, too_few, duplicate):
            with self.assertRaises(contract.ContentContractError):
                self.validate(article)

    def test_wrong_week_and_duplicate_ids_are_blocked(self) -> None:
        wrong_week = copy.deepcopy(self.valid)
        wrong_week["date"] = "2026-08-27"
        with self.assertRaisesRegex(contract.ContentContractError, "outside 2026-W36"):
            self.validate(wrong_week)
        with self.assertRaisesRegex(contract.ContentContractError, "already exists"):
            self.validate(self.valid, forbidden={self.valid["id"]})
        with self.assertRaisesRegex(contract.ContentContractError, "already exists"):
            self.validate(self.valid, seen={self.valid["id"]})

    def test_transport_delta_is_content_transparent(self) -> None:
        base = {"editions": [{"id": "2026-W35"}], "articles": [{"id": "old"}]}
        candidate = {
            "editions": base["editions"] + [{"id": "2026-W36"}],
            "articles": base["articles"] + [copy.deepcopy(self.valid)],
        }
        delta = contract.transparent_delta(base, candidate)
        self.assertEqual(delta["articles"], [self.valid])
        self.assertEqual(delta["editions"], [{"id": "2026-W36"}])
        raw = json.dumps(delta, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(json.loads(raw)["articles"][0], self.valid)
        self.assertIn("evidence", json.loads(raw)["articles"][0])


class ValidatorIntegrationTests(unittest.TestCase):
    def make_package(self, root: Path, article: dict, *, ready: bool = False) -> tuple[Path, bytes]:
        inbox = root / "inbox"
        outbox = root / "outbox"
        inbox.mkdir()
        outbox.mkdir()
        package = outbox / "2026-W36--2026-09-04"
        package.mkdir()
        base = {
            "generated": "2026-08-28T04:08:59+00:00",
            "editions": [],
            "articles": [],
        }
        base_raw = json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode()
        (inbox / "current.json").write_bytes(base_raw)
        candidate = {
            **base,
            "editions": [{"id": "2026-W36"}],
            "articles": [article],
        }
        (package / "candidate.json").write_text(json.dumps(candidate), encoding="utf-8")
        (package / "handoff.json").write_text(
            json.dumps(
                {
                    "schema": "gneu-aihot-handoff-v2",
                    "producer": "adam",
                    "edition": "2026-W36",
                    "attempt": "2026-09-04",
                    "mode": "edition",
                    "base_sha256": hashlib.sha256(base_raw).hexdigest(),
                    "base_generated": base["generated"],
                }
            ),
            encoding="utf-8",
        )
        (package / "report.md").write_text("contract regression report " * 20)
        if ready:
            (package / "READY").write_text("PASS ready\n")
        return package, base_raw

    def call_handoff(self, root: Path) -> tuple[str, bool]:
        old_values = (
            handoff_validator.ROOT,
            handoff_validator.INBOX,
            handoff_validator.OUTBOX,
        )
        old_argv = sys.argv
        handoff_validator.ROOT = root
        handoff_validator.INBOX = root / "inbox"
        handoff_validator.OUTBOX = root / "outbox"
        sys.argv = ["validator", "2026-W36--2026-09-04"]
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                handoff_validator.main()
            return output.getvalue(), True
        except SystemExit as exc:
            return str(exc), False
        finally:
            sys.argv = old_argv
            (
                handoff_validator.ROOT,
                handoff_validator.INBOX,
                handoff_validator.OUTBOX,
            ) = old_values

    def test_missing_evidence_blocks_handoff_before_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, _ = self.make_package(
                root, fixture("invalid-missing-evidence.json")
            )
            output, passed = self.call_handoff(root)
            self.assertFalse(passed)
            self.assertIn("missing=['evidence']", output)
            self.assertFalse((package / "READY").exists())

    def test_valid_fixture_passes_handoff_and_trusted_local(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, base_raw = self.make_package(root, fixture("valid-article.json"))
            output, passed = self.call_handoff(root)
            self.assertTrue(passed, output)
            self.assertTrue((package / "READY").is_file())

            local_bin = root / "bin"
            local_bin.mkdir()
            source = (BIN / "validate-intake.py").read_text(encoding="utf-8")
            source = source.replace(
                'HANDOFF_ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff")',
                f"HANDOFF_ROOT = Path({str(root)!r})",
            ).replace(
                'LIVE_URL = "https://gneu.se/data/aihot.json"',
                f"LIVE_URL = {(root / 'inbox/current.json').as_uri()!r}",
            )
            (local_bin / "validate-intake.py").write_text(source)
            for name in (
                "aihot_package_identity.py",
                "aihot_content_contract.py",
                "aihot-content-schema.json",
            ):
                shutil.copy2(BIN / name, local_bin / name)
            cp = subprocess.run(
                [sys.executable, str(local_bin / "validate-intake.py"), package.name],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(cp.returncode, 0, cp.stdout)
            self.assertIn("PASS_INTAKE", cp.stdout)
            authoritative_simulation(fixture("valid-article.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
