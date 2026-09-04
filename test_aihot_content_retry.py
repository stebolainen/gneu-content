#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "runtime/aihot/bin"
GENERATION = ROOT / "runtime/aihot/generation"
FIXTURES = ROOT / "runtime/aihot/tests/fixtures"
sys.path.insert(0, str(BIN))

import aihot_content_retry as content_retry
import aihot_local_retry as local_retry
import aihot_ready_retry as ready_retry


NOW = dt.datetime(2026, 9, 4, 13, 30, tzinfo=dt.timezone.utc)
COMMIT = "f" * 40
ATTEMPT = "2026-09-04"
REV0 = "2026-W36--2026-09-04"
R1 = REV0 + "--r1"
R2 = REV0 + "--r2"
FAILURE_OUTPUT = """Traceback (most recent call last):
  File "/root/gneu-aihot-bridge/bin/validate-intake.py", line 151, in <module>
    article_date = date.fromisoformat(value) if isinstance(value, str) else None
                   ^^^^
NameError: name 'date' is not defined
"""


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load(
    "aihot_content_retry_gate_test",
    GENERATION / "gneu-aihot-daily-gate.py",
)
handoff_validator = load(
    "aihot_content_retry_handoff_test",
    GENERATION / "gneu-aihot-handoff-validate.py",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path: Path, value: object, *, canonical_state: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value) if canonical_state else (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()
    path.write_bytes(raw)
    path.chmod(0o600)


class ContentRetryFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.handoff_root = self.root / "handoff"
        self.outbox = self.handoff_root / "outbox"
        self.inbox = self.handoff_root / "inbox"
        self.bin = self.root / "bin"
        self.generation = self.root / "generation"
        self.proc = self.root / "proc"
        self.config = self.root / "scheduler.json"
        self.db = self.root / "executions.db"
        self.output = self.root / "output"
        for directory in (
            self.state / "failed",
            self.state / "processed",
            self.state / "intake",
            self.state / "generation" / "retry-authorized",
            self.state / "generation" / "retry-consumed",
            self.state / "ready-retry" / "authorized",
            self.state / "ready-retry" / "consumed",
            self.state / "ready-retry" / "failed",
            self.outbox,
            self.inbox,
            self.bin,
            self.generation,
            self.proc,
            self.output,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        (self.state / "process-ready.lock").touch(mode=0o600)
        write_json(
            self.config,
            {
                "schema": "gneu-aihot-hermes-scheduler-v1",
                "job_id": "fbd796dbb875",
                "name": "gneu-aihot-daily",
                "script": "gneu-aihot-daily-gate.py",
            },
        )
        self.base = {
            "generated": "2026-08-28T04:08:59+00:00",
            "editions": [],
            "articles": [],
        }
        write_json(self.inbox / "current.json", self.base)
        self._make_rev0_lineage()
        self._make_r1_package()
        self._make_runtime()
        self._make_ready_retry_lineage()
        self._bind_incident()
        self.paths = content_retry.ContentRetryPaths(
            self.state,
            self.outbox,
            self.config,
            self.db,
            self.output,
            self.provenance,
            self.runtime_paths,
            self.proc,
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def _make_rev0_lineage(self) -> None:
        package = self.outbox / REV0
        package.mkdir()
        write_json(package / "candidate.json", self.base)
        write_json(
            package / "handoff.json",
            {
                "schema": "gneu-aihot-handoff-v2",
                "producer": "adam",
                "edition": "2026-W36",
                "attempt": ATTEMPT,
                "mode": "edition",
                "base_sha256": "a" * 64,
                "base_generated": self.base["generated"],
            },
        )
        (package / "report.md").write_text("terminal local report " * 20)
        retry_paths = local_retry.RetryPaths(
            self.state, self.outbox, self.config, self.db, self.output
        )
        hashes = local_retry.source_hashes(retry_paths, REV0)
        authorization = {
            "schema": "gneu-aihot-generation-retry-authorization-v1",
            "edition": "2026-W36",
            "attempt": ATTEMPT,
            "source_package_id": REV0,
            "source_candidate_sha256": hashes["candidate"],
            "source_handoff_sha256": hashes["handoff"],
            "source_report_sha256": hashes["report"],
            "hermes_execution_id": "7" * 32,
            "validation_failure": local_retry.REASON,
            "target_package_id": R1,
            "revision": 1,
            "authorized_at": "2026-09-04T07:30:00+00:00",
        }
        self.local_auth_sha = local_retry.atomic_create(
            local_retry.authorization_path(retry_paths, ATTEMPT), authorization
        )
        self.local_consumed_sha = local_retry.atomic_create(
            local_retry.consumed_path(retry_paths, ATTEMPT),
            {
                **authorization,
                "schema": "gneu-aihot-generation-retry-consumed-v1",
                "authorization_sha256": self.local_auth_sha,
                "consumed_at": "2026-09-04T07:31:00+00:00",
            },
        )

    def _make_r1_package(self) -> None:
        package = self.outbox / R1
        package.mkdir()
        article = json.loads(
            (FIXTURES / "invalid-missing-evidence.json").read_text()
        )
        candidate = {
            **self.base,
            "editions": [{"id": "2026-W36"}],
            "articles": [article],
        }
        write_json(package / "candidate.json", candidate)
        write_json(
            package / "handoff.json",
            {
                "schema": "gneu-aihot-handoff-v2",
                "producer": "adam",
                "edition": "2026-W36",
                "attempt": ATTEMPT,
                "revision": 1,
                "mode": "edition",
                "base_sha256": hashlib.sha256(
                    (self.inbox / "current.json").read_bytes()
                ).hexdigest(),
                "base_generated": self.base["generated"],
            },
        )
        (package / "report.md").write_text("terminal trusted report " * 20)
        (package / "READY").write_text("PASS ready\n")
        self.original_failed = self.state / "failed" / f"{R1}.json"
        write_json(
            self.original_failed,
            {
                "schema": "gneu-aihot-ready-failure-v1",
                "edition": "2026-W36",
                "package_id": R1,
                "attempt": ATTEMPT,
                "revision": 1,
                "failed_at": "2026-09-04T09:03:02+00:00",
                "failed_stage": "validate",
                "stages": [
                    {"stage": "validate", "returncode": 1, "output": FAILURE_OUTPUT}
                ],
            },
        )

    def _make_runtime(self) -> None:
        path_sources = {
            "schema": BIN / "aihot-content-schema.json",
            "content_contract": BIN / "aihot_content_contract.py",
            "content_retry": BIN / "aihot_content_retry.py",
            "authorize_content_retry": BIN / "authorize-content-retry.py",
            "package_identity": BIN / "aihot_package_identity.py",
            "process_ready": BIN / "process-ready.py",
            "validate_intake": BIN / "validate-intake.py",
            "build_intake": BIN / "build-intake-payload.py",
            "dispatch_intake": BIN / "dispatch-trusted-intake.py",
            "daily_gate": GENERATION / "gneu-aihot-daily-gate.py",
            "handoff_validator": GENERATION / "gneu-aihot-handoff-validate.py",
            "adam_daily": GENERATION / "ADAM_DAILY.md",
            "generation_contract": GENERATION / "CONTRACT.md",
        }
        self.runtime_paths = {}
        for name, source in path_sources.items():
            destination = (self.generation if name in {
                "daily_gate", "handoff_validator", "adam_daily", "generation_contract"
            } else self.bin) / source.name
            shutil.copy2(source, destination)
            self.runtime_paths[name] = destination
        files = {}
        for relative, (name, mode) in content_retry.RUNTIME_FILES.items():
            path = self.runtime_paths[name]
            path.chmod(int(mode, 8))
            files[relative] = {
                "destination": str(path),
                "mode": mode,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        for relative, (filename, mode) in ready_retry.REQUIRED_RUNTIME.items():
            if relative in files:
                continue
            path = self.bin / filename
            source = BIN / filename
            shutil.copy2(source, path)
            path.chmod(int(mode, 8))
            files[relative] = {
                "destination": str(path),
                "mode": mode,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        self.provenance = self.root / "PROVENANCE.json"
        write_json(
            self.provenance,
            {
                "schema": "gneu-aihot-runtime-provenance-v1",
                "source_commit": COMMIT,
                "manifest_sha256": "e" * 64,
                "installed_at": "2026-09-04T13:00:00+00:00",
                "files": files,
            },
        )

    def _make_ready_retry_lineage(self) -> None:
        paths = ready_retry.ReadyRetryPaths(
            self.state, self.outbox, self.provenance, self.bin, self.proc
        )
        hashes = ready_retry.package_hashes(paths, R1)
        failed_sha = hashlib.sha256(self.original_failed.read_bytes()).hexdigest()
        authorization = {
            "schema": "gneu-aihot-ready-retry-authorization-v1",
            **ready_retry.authorization_values(R1, hashes, failed_sha, COMMIT),
            "authorized_at": "2026-09-04T10:30:00+00:00",
        }
        self.ready_auth_sha = ready_retry.create_receipt(
            ready_retry.authorization_path(paths, R1), authorization
        )
        consumed = {
            **authorization,
            "schema": "gneu-aihot-ready-retry-consumed-v1",
            "authorization_sha256": self.ready_auth_sha,
            "consumed_at": "2026-09-04T10:31:00+00:00",
        }
        self.ready_consumed_sha = ready_retry.create_receipt(
            ready_retry.consumed_path(paths, R1), consumed
        )
        article = json.loads(
            (FIXTURES / "invalid-missing-evidence.json").read_text()
        )
        payload = {
            "version": 1,
            "edition": "2026-W36",
            "mode": "edition",
            "base_main_sha": "a" * 40,
            "base_aihot_sha256": "b" * 64,
            "base_generated": self.base["generated"],
            "delta": {
                "editions": [{"id": "2026-W36"}],
                "articles": [article],
            },
            "report": "terminal trusted report " * 20,
        }
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        compressed = gzip.compress(raw, mtime=0)
        transport = {
            "edition": "2026-W36",
            "mode": "edition",
            "base_main_sha": "a" * 40,
            "payload_sha256": hashlib.sha256(compressed).hexdigest(),
            "payload_b64": base64.urlsafe_b64encode(compressed).rstrip(b"=").decode(),
        }
        self.transport = self.state / "intake" / f"{R1}.transport.json"
        write_json(self.transport, transport, canonical_state=True)
        stages = [
            {"stage": "validate", "returncode": 0, "output": "PASS\n"},
            {"stage": "build", "returncode": 0, "output": "PASS\n"},
            {
                "stage": "dispatch",
                "returncode": 1,
                "output": "INTAKE_DISPATCH: ACCEPTED\nrun_id: 33874811080\nconclusion: failure\n",
            },
        ]
        self.ready_failure_sha = ready_retry.record_retry_failure(
            paths,
            {
                "package_id": R1,
                "failed_receipt_sha256": failed_sha,
                "authorization_sha256": self.ready_auth_sha,
                "consumed_sha256": self.ready_consumed_sha,
            },
            "dispatch",
            "DISPATCH_FAILED",
            stages,
            NOW,
        )
        self.canonical_payload_sha = hashlib.sha256(raw).hexdigest()

    def _bind_incident(self) -> None:
        package = self.outbox / R1
        schema = self.runtime_paths["schema"]
        schema_value = json.loads(schema.read_text())
        content_retry.INCIDENT.update(
            {
                "edition": "2026-W36",
                "attempt": ATTEMPT,
                "source_package_id": R1,
                "target_package_id": R2,
                "source_candidate_sha256": hashlib.sha256(
                    (package / "candidate.json").read_bytes()
                ).hexdigest(),
                "source_handoff_sha256": hashlib.sha256(
                    (package / "handoff.json").read_bytes()
                ).hexdigest(),
                "source_report_sha256": hashlib.sha256(
                    (package / "report.md").read_bytes()
                ).hexdigest(),
                "source_ready_sha256": hashlib.sha256(
                    (package / "READY").read_bytes()
                ).hexdigest(),
                "original_failed_receipt_sha256": hashlib.sha256(
                    self.original_failed.read_bytes()
                ).hexdigest(),
                "local_retry_authorization_sha256": self.local_auth_sha,
                "local_retry_consumed_sha256": self.local_consumed_sha,
                "ready_retry_authorization_sha256": self.ready_auth_sha,
                "ready_retry_consumed_sha256": self.ready_consumed_sha,
                "ready_retry_failure_sha256": self.ready_failure_sha,
                "transport_sha256": hashlib.sha256(self.transport.read_bytes()).hexdigest(),
                "canonical_payload_sha256": self.canonical_payload_sha,
                "trusted_run_id": content_retry.EXPECTED_REMOTE_RUN_ID,
                "remote_head_sha": content_retry.EXPECTED_REMOTE_HEAD_SHA,
                "remote_validation_result": content_retry.EXPECTED_REMOTE_FAILURE,
                "remote_validate_conclusion": "failure",
                "remote_token_preparation": "skipped",
                "remote_scope_verification": "skipped",
                "remote_write_step": "skipped",
                "repository_writes": "none",
                "authoritative_contract_sha256": schema_value["provenance"]["sha256"],
                "content_schema_sha256": hashlib.sha256(schema.read_bytes()).hexdigest(),
                "content_contract_source_commit": content_retry.INCIDENT[
                    "content_contract_source_commit"
                ],
            }
        )

    def authorize(self):
        return content_retry.authorize(
            self.paths, ATTEMPT, COMMIT, content_retry.REASON, NOW
        )

    def configure_gate(self) -> None:
        gate.STATE = self.state
        gate.OUTBOX = self.outbox
        gate.CLAIMS = self.state / "generation"
        gate.BASE_META = self.root / "missing-meta.json"
        gate.SCHEDULER_CONFIG = self.config
        gate.EXECUTIONS_DB = self.db
        gate.CRON_OUTPUT = self.output
        gate.content_retry_paths = lambda: self.paths

    def admit_r2(self) -> None:
        self.authorize()
        result = gate.evaluate(NOW + dt.timedelta(minutes=1))
        if not result["wakeAgent"]:
            raise AssertionError(result)

    def write_r2(self, article: dict) -> Path:
        package = self.outbox / R2
        package.mkdir()
        write_json(
            package / "candidate.json",
            {
                **self.base,
                "editions": [{"id": "2026-W36"}],
                "articles": [article],
            },
        )
        write_json(
            package / "handoff.json",
            {
                "schema": "gneu-aihot-handoff-v2",
                "producer": "adam",
                "edition": "2026-W36",
                "attempt": ATTEMPT,
                "revision": 2,
                "mode": "edition",
                "base_sha256": hashlib.sha256(
                    (self.inbox / "current.json").read_bytes()
                ).hexdigest(),
                "base_generated": self.base["generated"],
            },
        )
        (package / "report.md").write_text("fresh r2 research report " * 20)
        handoff_validator.ROOT = self.handoff_root
        handoff_validator.INBOX = self.inbox
        handoff_validator.OUTBOX = self.outbox
        handoff_validator.RETRY_STATE = self.state
        handoff_validator.SCHEDULER_CONFIG = self.config
        handoff_validator.EXECUTIONS_DB = self.db
        handoff_validator.CRON_OUTPUT = self.output
        handoff_validator.content_retry_paths = lambda: self.paths
        return package

    def validate_r2(self) -> tuple[bool, str]:
        old_argv = sys.argv
        output = StringIO()
        sys.argv = ["validator", R2]
        try:
            with redirect_stdout(output):
                handoff_validator.main()
            return True, output.getvalue()
        except SystemExit as exc:
            return False, str(exc)
        finally:
            sys.argv = old_argv


class ContentRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_incident = copy.deepcopy(content_retry.INCIDENT)
        self.fixture = ContentRetryFixture()
        self.fixture.configure_gate()

    def tearDown(self) -> None:
        content_retry.INCIDENT.clear()
        content_retry.INCIDENT.update(self.original_incident)
        self.fixture.close()

    def test_r2_requires_authorization_and_wakes_exactly_once(self) -> None:
        blocked = gate.evaluate(NOW)
        self.assertFalse(blocked["wakeAgent"])
        self.assertEqual(blocked["context"]["reason"], "retry_already_consumed")
        authorization, auth_sha = self.fixture.authorize()
        self.assertEqual(authorization["target_package_id"], R2)
        self.assertEqual(authorization["revision"], 2)
        self.assertFalse(
            authorization["operator_attested_remote_evidence"]["verified_by_tool"]
        )
        auth_path = content_retry.authorization_path(self.fixture.paths)
        self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(content_retry.ContentRetryError):
            self.fixture.authorize()
        admitted = gate.evaluate(NOW + dt.timedelta(minutes=1))
        self.assertTrue(admitted["wakeAgent"])
        self.assertEqual(admitted["context"]["package_id"], R2)
        self.assertEqual(admitted["context"]["revision"], 2)
        self.assertEqual(
            admitted["context"]["reason"], "operator_content_contract_retry"
        )
        consumed, consumed_sha = content_retry.verify_consumed(
            self.fixture.paths, ATTEMPT, COMMIT
        )
        self.assertEqual(consumed["authorization_sha256"], auth_sha)
        self.assertEqual(
            consumed_sha,
            hashlib.sha256(
                content_retry.consumed_path(self.fixture.paths).read_bytes()
            ).hexdigest(),
        )
        duplicate = gate.evaluate(NOW + dt.timedelta(minutes=2))
        self.assertFalse(duplicate["wakeAgent"])
        self.assertEqual(
            duplicate["context"]["reason"], "content_retry_already_consumed"
        )

    def test_wrong_remote_proof_or_any_possible_write_blocks(self) -> None:
        for key, value in (
            ("trusted_run_id", 1),
            ("remote_validation_result", "BLOCKED: other"),
            ("remote_token_preparation", "success"),
            ("remote_scope_verification", "success"),
            ("remote_write_step", "success"),
            ("repository_writes", "unknown"),
        ):
            with self.subTest(key=key):
                original = content_retry.INCIDENT[key]
                content_retry.INCIDENT[key] = value
                with self.assertRaisesRegex(
                    content_retry.ContentRetryError,
                    "REMOTE_WRITE_BOUNDARY_NOT_PROVEN",
                ):
                    self.fixture.authorize()
                content_retry.INCIDENT[key] = original

    def test_changed_source_and_wrong_contract_provenance_block(self) -> None:
        (self.fixture.outbox / R1 / "report.md").write_text("changed\n")
        with self.assertRaisesRegex(
            content_retry.ContentRetryError, "SOURCE_PACKAGE_HASH_MISMATCH"
        ):
            self.fixture.authorize()
        self.tearDown()
        self.setUp()
        schema = self.fixture.runtime_paths["schema"]
        schema.write_text(schema.read_text() + "\n")
        with self.assertRaisesRegex(
            content_retry.ContentRetryError, "INVALID_RUNTIME_PROVENANCE"
        ):
            self.fixture.authorize()

    def test_non_missing_evidence_failure_and_target_state_block(self) -> None:
        original = content_retry.INCIDENT["remote_validation_result"]
        content_retry.INCIDENT["remote_validation_result"] = "BLOCKED: content"
        with self.assertRaises(content_retry.ContentRetryError):
            self.fixture.authorize()
        content_retry.INCIDENT["remote_validation_result"] = original
        (self.fixture.outbox / R2).mkdir()
        with self.assertRaisesRegex(content_retry.ContentRetryError, "TARGET_STATE_EXISTS"):
            self.fixture.authorize()

    def test_active_generation_and_wrong_runtime_commit_block(self) -> None:
        process = self.fixture.proc / "123"
        process.mkdir()
        (process / "cmdline").write_bytes(b"python\x00gneu-aihot-daily-gate.py\x00")
        with self.assertRaisesRegex(content_retry.ContentRetryError, "ACTIVE_GENERATION"):
            self.fixture.authorize()
        self.tearDown()
        self.setUp()
        with self.assertRaisesRegex(content_retry.ContentRetryError, "INVALID_RUNTIME"):
            content_retry.authorize(
                self.fixture.paths,
                ATTEMPT,
                "0" * 40,
                content_retry.REASON,
                NOW,
            )

    def test_tomorrow_normal_revision_zero_is_unaffected(self) -> None:
        self.fixture.authorize()
        self.assertTrue(gate.evaluate(NOW + dt.timedelta(minutes=1))["wakeAgent"])
        tomorrow = gate.evaluate(NOW + dt.timedelta(days=1))
        self.assertTrue(tomorrow["wakeAgent"])
        self.assertEqual(tomorrow["context"]["package_id"], "2026-W36--2026-09-05")
        self.assertNotIn("revision", tomorrow["context"])

    def test_r3_is_invalid_and_arbitrary_r2_is_not_authorizable(self) -> None:
        from aihot_package_identity import parse_package_id

        self.assertEqual(parse_package_id(R2), ("2026-W36", ATTEMPT, 2))
        with self.assertRaises(ValueError):
            parse_package_id(REV0 + "--r3")
        arbitrary = "2026-W36--2026-09-03--r2"
        self.assertEqual(parse_package_id(arbitrary), ("2026-W36", "2026-09-03", 2))
        with self.assertRaisesRegex(
            content_retry.ContentRetryError, "INVALID_CONTENT_RETRY_TARGET"
        ):
            content_retry.verify_target_consumed(self.fixture.paths, arbitrary)


class R2ContentValidationTests(unittest.TestCase):
    def test_adam_r2_contract_requires_fresh_evidence_and_forbids_r3(self) -> None:
        adam = (GENERATION / "ADAM_DAILY.md").read_text()
        contract = (GENERATION / "CONTRACT.md").read_text()
        for value in (adam, contract):
            self.assertIn("operator_content_contract_retry", value)
            self.assertIn("revision=2", value)
            self.assertIn("evidence", value)
            self.assertIn("r3", value.lower())
        self.assertIn("Never copy, edit, or enrich r1", adam)
        self.assertIn("fresh research", adam.lower())

    def test_r2_requires_evidence_and_rejects_future_date(self) -> None:
        from aihot_content_contract import ContentContractError, load_contract, validate_article

        invalid = json.loads((FIXTURES / "invalid-missing-evidence.json").read_text())
        with self.assertRaisesRegex(ContentContractError, "missing=.*evidence"):
            validate_article(
                invalid,
                "2026-W36",
                set(),
                set(),
                load_contract(),
                dt.date(2026, 9, 4),
            )
        valid = json.loads((FIXTURES / "valid-article.json").read_text())
        self.assertEqual(
            validate_article(
                valid,
                "2026-W36",
                set(),
                set(),
                load_contract(),
                dt.date(2026, 9, 4),
            ),
            valid["id"],
        )
        valid["date"] = "2026-09-05"
        with self.assertRaisesRegex(ContentContractError, "after attempt"):
            validate_article(
                valid,
                "2026-W36",
                set(),
                set(),
                load_contract(),
                dt.date(2026, 9, 4),
            )

    def test_handoff_blocks_missing_evidence_before_ready(self) -> None:
        original_incident = copy.deepcopy(content_retry.INCIDENT)
        fixture = ContentRetryFixture()
        try:
            fixture.configure_gate()
            fixture.admit_r2()
            package = fixture.write_r2(
                json.loads((FIXTURES / "invalid-missing-evidence.json").read_text())
            )
            passed, output = fixture.validate_r2()
            self.assertFalse(passed)
            self.assertIn("missing=['evidence']", output)
            self.assertFalse((package / "READY").exists())
        finally:
            content_retry.INCIDENT.clear()
            content_retry.INCIDENT.update(original_incident)
            fixture.close()

    def test_handoff_accepts_complete_evidence_for_r2(self) -> None:
        original_incident = copy.deepcopy(content_retry.INCIDENT)
        fixture = ContentRetryFixture()
        try:
            fixture.configure_gate()
            fixture.admit_r2()
            package = fixture.write_r2(
                json.loads((FIXTURES / "valid-article.json").read_text())
            )
            passed, output = fixture.validate_r2()
            self.assertTrue(passed, output)
            self.assertTrue((package / "READY").is_file())
        finally:
            content_retry.INCIDENT.clear()
            content_retry.INCIDENT.update(original_incident)
            fixture.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
