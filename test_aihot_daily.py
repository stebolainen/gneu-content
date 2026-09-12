#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from test_aihot_operator_disposition import SyntheticState, process_ready, rejection


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "runtime/aihot/tests/fixtures"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load(
    "aihot_daily_gate",
    ROOT / "runtime/aihot/generation/gneu-aihot-daily-gate.py",
)
freshness = load(
    "aihot_freshness",
    ROOT / "runtime/aihot/bin/aihot-freshness.py",
)
handoff_validator = load(
    "aihot_handoff_validator",
    ROOT / "runtime/aihot/generation/gneu-aihot-handoff-validate.py",
)
scheduler = load(
    "aihot_scheduler",
    ROOT / "runtime/aihot/bin/configure-generation-scheduler.py",
)
local_retry = load(
    "aihot_local_retry_daily",
    ROOT / "runtime/aihot/bin/aihot_local_retry.py",
)


class DailyAttemptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticState()
        self.fixture.reject()
        process_ready.STATE = self.fixture.state
        process_ready.OUTBOX = self.fixture.outbox
        process_ready.PROCESSED = self.fixture.state / "processed"
        process_ready.FAILED = self.fixture.state / "failed"
        process_ready.BIN = self.fixture.root / "bin"
        self.package_id = "2026-W36--2026-09-04"

    def tearDown(self) -> None:
        self.fixture.close()

    def make_attempt(self, *, replay: bool = False) -> None:
        package = self.fixture.outbox / self.package_id
        shutil.copytree(self.fixture.package, package)
        handoff = json.loads((package / "handoff.json").read_text())
        handoff["schema"] = "gneu-aihot-handoff-v2"
        handoff["attempt"] = "2026-09-04"
        (package / "handoff.json").write_text(
            json.dumps(handoff, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        if not replay:
            (package / "report.md").write_text(
                (package / "report.md").read_text() + "Independent daily attempt.\n"
            )
        payload = dict(self.fixture.payload)
        if not replay:
            payload["report"] += " Independent daily attempt."
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        compressed = gzip.compress(raw, mtime=0)
        transport = {
            "edition": self.fixture.edition,
            "mode": "edition",
            "base_main_sha": self.fixture.base_main_sha,
            "payload_sha256": hashlib.sha256(compressed).hexdigest(),
            "payload_b64": base64.urlsafe_b64encode(compressed).rstrip(b"=").decode(),
        }
        path = self.fixture.state / "intake" / f"{self.package_id}.transport.json"
        path.write_text(json.dumps(transport, separators=(",", ":")) + "\n")
        path.chmod(0o600)

    def run_attempt(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "PASS\n")

        original = process_ready.run
        process_ready.run = runner
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                result = process_ready.process_package(self.package_id)
        finally:
            process_ready.run = original
        return result, output.getvalue(), calls

    def authorize_r1(self) -> None:
        target = self.fixture.outbox / self.package_id
        source_id = "2026-W36--2026-09-04"
        source = self.fixture.outbox / source_id
        source.mkdir()
        for name in ("candidate.json", "handoff.json", "report.md"):
            shutil.copy2(target / name, source / name)
        paths = local_retry.RetryPaths(
            self.fixture.state,
            self.fixture.outbox,
            self.fixture.root / "scheduler.json",
            self.fixture.root / "executions.db",
            self.fixture.root / "output",
        )
        hashes = local_retry.source_hashes(paths, source_id)
        authorization = {
            "schema": "gneu-aihot-generation-retry-authorization-v1",
            "edition": "2026-W36",
            "attempt": "2026-09-04",
            "source_package_id": source_id,
            "source_candidate_sha256": hashes["candidate"],
            "source_handoff_sha256": hashes["handoff"],
            "source_report_sha256": hashes["report"],
            "hermes_execution_id": "a" * 32,
            "validation_failure": local_retry.REASON,
            "target_package_id": self.package_id,
            "revision": 1,
            "authorized_at": "2026-09-04T07:30:00+00:00",
        }
        authorization_sha = local_retry.atomic_create(
            local_retry.authorization_path(paths, "2026-09-04"), authorization
        )
        local_retry.atomic_create(
            local_retry.consumed_path(paths, "2026-09-04"),
            {
                **authorization,
                "schema": "gneu-aihot-generation-retry-consumed-v1",
                "authorization_sha256": authorization_sha,
                "consumed_at": "2026-09-04T07:31:00+00:00",
            },
        )

    def test_old_rejected_payload_remains_terminal(self) -> None:
        calls = []
        original = process_ready.run
        process_ready.run = lambda argv: calls.append(argv)
        try:
            self.assertTrue(process_ready.process_package(self.fixture.edition))
        finally:
            process_ready.run = original
        self.assertEqual(calls, [])

    def test_fresh_same_week_attempt_is_not_rejected_by_week(self) -> None:
        self.make_attempt()
        result, output, calls = self.run_attempt()
        self.assertTrue(result)
        self.assertIn(f"AIHOT_READY_PROCESSED {self.package_id}", output)
        self.assertEqual(len(calls), 3)
        self.assertTrue(
            (self.fixture.state / "processed" / f"{self.package_id}.json").is_file()
        )

    def test_exact_rejected_payload_replay_is_blocked_before_dispatch(self) -> None:
        self.make_attempt(replay=True)
        result, output, calls = self.run_attempt()
        self.assertFalse(result)
        self.assertIn("BLOCKED_REJECTED_PACKAGE_REPLAY", output)
        self.assertEqual(len(calls), 2)

    def test_attempt_must_belong_to_edition(self) -> None:
        with self.assertRaises(ValueError):
            process_ready.parse_package_id("2026-W36--2026-08-26")

    def test_r1_uses_normal_process_ready_and_records_revision(self) -> None:
        self.package_id = "2026-W36--2026-09-04--r1"
        self.make_attempt()
        self.authorize_r1()
        result, output, calls = self.run_attempt()
        self.assertTrue(result)
        self.assertIn(f"AIHOT_READY_PROCESSED {self.package_id}", output)
        self.assertEqual(len(calls), 3)
        receipt = json.loads(
            (self.fixture.state / "processed" / f"{self.package_id}.json").read_text()
        )
        self.assertEqual(receipt["revision"], 1)

    def test_r1_rejected_payload_replay_is_still_blocked(self) -> None:
        self.package_id = "2026-W36--2026-09-04--r1"
        self.make_attempt(replay=True)
        self.authorize_r1()
        result, output, calls = self.run_attempt()
        self.assertFalse(result)
        self.assertIn("BLOCKED_REJECTED_PACKAGE_REPLAY", output)
        self.assertEqual(len(calls), 2)

    def test_r1_process_ready_requires_consumed_authorization(self) -> None:
        self.package_id = "2026-W36--2026-09-04--r1"
        self.make_attempt()
        result, output, calls = self.run_attempt()
        self.assertFalse(result)
        self.assertIn("BLOCKED_INVALID_RETRY_AUTHORIZATION", output)
        self.assertEqual(calls, [])

    def with_r2_verifier(self, value):
        original = process_ready.verify_content_retry_consumed
        process_ready.verify_content_retry_consumed = value
        self.addCleanup(
            setattr,
            process_ready,
            "verify_content_retry_consumed",
            original,
        )

    def test_r2_uses_normal_process_ready_and_records_revision(self) -> None:
        self.package_id = "2026-W36--2026-09-04--r2"
        self.make_attempt()
        self.with_r2_verifier(lambda *args: ({}, "a" * 64))
        result, output, calls = self.run_attempt()
        self.assertTrue(result)
        self.assertIn(f"AIHOT_READY_PROCESSED {self.package_id}", output)
        self.assertEqual(len(calls), 3)
        receipt = json.loads(
            (self.fixture.state / "processed" / f"{self.package_id}.json").read_text()
        )
        self.assertEqual(receipt["revision"], 2)

    def test_r2_replay_guard_still_precedes_dispatch(self) -> None:
        self.package_id = "2026-W36--2026-09-04--r2"
        self.make_attempt(replay=True)
        self.with_r2_verifier(lambda *args: ({}, "a" * 64))
        result, output, calls = self.run_attempt()
        self.assertFalse(result)
        self.assertIn("BLOCKED_REJECTED_PACKAGE_REPLAY", output)
        self.assertEqual(len(calls), 2)

    def test_r2_process_ready_requires_consumed_authorization(self) -> None:
        from aihot_content_retry import ContentRetryError

        self.package_id = "2026-W36--2026-09-04--r2"
        self.make_attempt()

        def blocked(*args):
            raise ContentRetryError("not authorized")

        self.with_r2_verifier(blocked)
        result, output, calls = self.run_attempt()
        self.assertFalse(result)
        self.assertIn("BLOCKED_INVALID_CONTENT_RETRY_AUTHORIZATION", output)
        self.assertEqual(calls, [])

    def test_r3_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            process_ready.parse_package_id("2026-W36--2026-09-04--r3")


class DailyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        gate.STATE = root / "state"
        gate.OUTBOX = root / "outbox"
        gate.CLAIMS = gate.STATE / "generation"
        gate.BASE_META = root / "missing-meta.json"
        gate.SCHEDULER_CONFIG = root / "scheduler.json"
        gate.EXECUTIONS_DB = root / "executions.db"
        gate.CRON_OUTPUT = root / "output"
        gate.REQUEST_DUMPS = root / "sessions"
        gate.TRUSTED_UID = os.geteuid()
        self.original_load_claim = gate.load_claim
        self.original_load_canonical = gate.load_canonical
        self.original_load_job_id = gate.load_job_id
        self.original_create_immutable = gate.create_immutable

        def test_load_canonical(path, keys, schema, code):
            data = path.read_bytes()
            value = json.loads(data)
            if set(value) != keys or value.get("schema") != schema:
                raise gate.ResumeError(code)
            return value, data

        def test_load_claim(paths, attempt):
            return test_load_canonical(
                paths.claims / f"{attempt}.json",
                {"schema", "edition", "attempt", "package_id", "claimed_at"},
                "gneu-aihot-generation-claim-v1",
                "INVALID_CLAIM",
            )

        def test_create_immutable(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            path.chmod(0o600)
            return hashlib.sha256(path.read_bytes()).hexdigest()

        gate.load_claim = test_load_claim
        gate.load_canonical = test_load_canonical
        gate.load_job_id = lambda paths: "fbd796dbb875"
        gate.create_immutable = test_create_immutable
        gate.OUTBOX.mkdir(parents=True)
        gate.CRON_OUTPUT.mkdir()
        gate.REQUEST_DUMPS.mkdir(mode=0o700)
        contract = json.loads(
            (ROOT / "runtime/aihot/generation/hermes-scheduler.json").read_text()
        )
        gate.SCHEDULER_CONFIG.write_text(json.dumps(contract))
        with sqlite3.connect(gate.EXECUTIONS_DB) as connection:
            connection.execute(
                """CREATE TABLE executions (
                id TEXT PRIMARY KEY, job_id TEXT NOT NULL, source TEXT NOT NULL,
                process_id TEXT NOT NULL, pid INTEGER NOT NULL,
                process_started_at INTEGER, status TEXT NOT NULL,
                claimed_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                error TEXT)"""
            )

    def tearDown(self) -> None:
        gate.load_claim = self.original_load_claim
        gate.load_canonical = self.original_load_canonical
        gate.load_job_id = self.original_load_job_id
        gate.create_immutable = self.original_create_immutable
        self.temporary.cleanup()

    def execution(
        self,
        execution_id: str,
        status: str,
        when: dt.datetime,
        error: str | None = None,
        finished: dt.datetime | None = None,
        source: str = "builtin",
    ) -> None:
        timestamp = when.isoformat()
        finished_timestamp = (
            (finished or when).isoformat()
            if status in gate.TERMINAL_EXECUTION_STATUSES
            else None
        )
        with sqlite3.connect(gate.EXECUTIONS_DB) as connection:
            connection.execute(
                "INSERT INTO executions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    execution_id,
                    "fbd796dbb875",
                    source,
                    execution_id,
                    123,
                    None,
                    status,
                    timestamp,
                    timestamp,
                    finished_timestamp,
                    error,
                ),
            )

    def primary_429(self, now: dt.datetime) -> None:
        self.execution(
            "1" * 32,
            "failed",
            now - dt.timedelta(seconds=1),
            "RuntimeError: HTTP 429: The usage limit has been reached",
            now + dt.timedelta(seconds=1),
        )
        self.provider_failure(now)

    def provider_failure(self, now: dt.datetime, *, after_research: bool = False) -> None:
        inputs = [{"role": "user", "content": "daily prompt"}]
        if after_research:
            inputs.append({"type": "function_call_output", "output": "research"})
        value = {
            "timestamp": now.replace(tzinfo=None).isoformat(),
            "session_id": "cron_fbd796dbb875_20260904_050000",
            "reason": "max_retries_exhausted",
            "request": {"body": {"input": inputs}},
            "error": {"type": "usage_limit_reached", "status_code": 429},
        }
        path = gate.REQUEST_DUMPS / (
            "request_dump_cron_fbd796dbb875_20260904_050000_"
            "20260904_050000_000000.json"
        )
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        timestamp = now.timestamp()
        os.utime(path, (timestamp, timestamp))

    def fallback_execution(self, now: dt.datetime) -> None:
        self.execution("2" * 32, "running", now)

    def test_summer_and_winter_resolve_to_0700_stockholm(self) -> None:
        summer = gate.evaluate(dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc))
        self.assertTrue(summer["wakeAgent"])
        self.temporary.cleanup()
        self.setUp()
        winter = gate.evaluate(dt.datetime(2026, 12, 4, 6, 0, tzinfo=dt.timezone.utc))
        self.assertTrue(winter["wakeAgent"])

    def test_winter_primary_429_has_0700_utc_fallback(self) -> None:
        primary = dt.datetime(2026, 12, 4, 6, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(gate.evaluate(primary)["wakeAgent"])
        self.primary_429(primary)
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        result = gate.evaluate(fallback)
        self.assertTrue(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "FALLBACK_RETRY")

    def test_pre_window_is_blocked(self) -> None:
        result = gate.evaluate(dt.datetime(2026, 12, 4, 5, 59, tzinfo=dt.timezone.utc))
        self.assertFalse(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "before_daily_aihot_window")

    def test_same_day_duplicate_is_suppressed(self) -> None:
        now = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(gate.evaluate(now)["wakeAgent"])
        duplicate = gate.evaluate(now + dt.timedelta(hours=1))
        self.assertFalse(duplicate["wakeAgent"])
        self.assertEqual(duplicate["context"]["reason"], "daily_attempt_already_claimed")

    def test_primary_pre_research_429_admits_one_fallback(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        self.execution(
            "0" * 32,
            "failed",
            primary - dt.timedelta(days=1),
            "old direct failure",
            primary - dt.timedelta(days=1) + dt.timedelta(seconds=1),
            source="direct",
        )
        self.assertTrue(gate.evaluate(primary)["wakeAgent"])
        self.primary_429(primary)
        inspection = gate.inspect(primary + dt.timedelta(minutes=30))
        self.assertEqual(inspection["context"]["reason"], "PRIMARY_TRANSIENT_FAILURE")
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        result = gate.evaluate(fallback)
        self.assertTrue(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "FALLBACK_RETRY")
        receipt = gate.fallback_path("2026-09-04")
        self.assertTrue(receipt.is_file())
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

    def test_fallback_success_continues_normal_package_pipeline(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        first = gate.evaluate(primary)
        package_id = first["context"]["package_id"]
        self.primary_429(primary)
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        self.assertTrue(gate.evaluate(fallback)["wakeAgent"])
        package = gate.OUTBOX / package_id
        package.mkdir()
        (package / "READY").write_text("ready\n")
        terminal = gate.evaluate(fallback + dt.timedelta(hours=1))
        self.assertFalse(terminal["wakeAgent"])
        self.assertEqual(terminal["context"]["reason"], "daily_attempt_complete")

    def test_second_429_is_terminal_and_never_admits_third_attempt(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        gate.evaluate(primary)
        self.primary_429(primary)
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        self.assertTrue(gate.evaluate(fallback)["wakeAgent"])
        with sqlite3.connect(gate.EXECUTIONS_DB) as connection:
            connection.execute(
                "UPDATE executions SET status='failed', finished_at=?, error=? WHERE id=?",
                (
                    (fallback + dt.timedelta(seconds=10)).isoformat(),
                    "RuntimeError: HTTP 429: The usage limit has been reached",
                    "2" * 32,
                ),
            )
        third = fallback + dt.timedelta(hours=1)
        self.execution("3" * 32, "running", third)
        result = gate.evaluate(third)
        self.assertFalse(result["wakeAgent"])
        self.assertEqual(
            result["context"]["reason"],
            "FALLBACK_TRANSIENT_FAILURE_TERMINAL",
        )

    def test_package_or_publication_state_blocks_automatic_fallback(self) -> None:
        cases = (
            ("429_after_candidate", lambda package_id: self._package_files(package_id, "candidate.json")),
            (
                "validation_failure",
                lambda package_id: self._package_files(
                    package_id, "candidate.json", "handoff.json", "report.md"
                ),
            ),
            (
                "content_contract_failure",
                lambda package_id: self._package_files(
                    package_id, "candidate.json", "handoff.json", "report.md"
                ),
            ),
            ("ready_failure", lambda package_id: self._state_file("failed", package_id)),
            ("processed", lambda package_id: self._state_file("processed", package_id)),
            (
                "dispatch_failure",
                lambda package_id: self._state_file("intake", package_id, ".transport.json"),
            ),
            (
                "research_output",
                lambda package_id: (
                    gate.OUTBOX.parent / f"citations-{package_id}.json"
                ).write_text("{}\n"),
            ),
        )
        for stage, create_state in cases:
            with self.subTest(stage=stage):
                self.tearDown()
                self.setUp()
                primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
                first = gate.evaluate(primary)
                self.primary_429(primary)
                create_state(first["context"]["package_id"])
                reason, _, _ = gate.classify_claimed_attempt(
                    "2026-09-04", "2026-W36", first["context"]["package_id"],
                    primary + dt.timedelta(hours=1),
                )
                self.assertEqual(reason, "daily_attempt_requires_operator")
                self.assertFalse(gate.fallback_path("2026-09-04").exists())

    def _state_file(self, directory: str, package_id: str, suffix: str = ".json") -> None:
        target = gate.STATE / directory
        target.mkdir(parents=True)
        (target / f"{package_id}{suffix}").write_text("{}\n")

    def _package_files(self, package_id: str, *names: str) -> None:
        package = gate.OUTBOX / package_id
        package.mkdir()
        for name in names:
            (package / name).write_text("{}\n")

    def test_non_transient_provider_failure_is_terminal(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        gate.evaluate(primary)
        self.execution(
            "1" * 32,
            "failed",
            primary - dt.timedelta(seconds=1),
            "RuntimeError: provider authentication failed",
            primary + dt.timedelta(seconds=1),
        )
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        result = gate.evaluate(fallback)
        self.assertFalse(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "PRIMARY_FAILURE_TERMINAL")
        self.assertFalse(gate.fallback_path("2026-09-04").exists())

    def test_429_after_research_is_terminal(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        gate.evaluate(primary)
        self.execution(
            "1" * 32,
            "failed",
            primary - dt.timedelta(seconds=1),
            "RuntimeError: HTTP 429: The usage limit has been reached",
            primary + dt.timedelta(seconds=1),
        )
        self.provider_failure(primary, after_research=True)
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        result = gate.evaluate(fallback)
        self.assertFalse(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "PRIMARY_FAILURE_TERMINAL")

    def test_terminal_pre_research_state_stops_agent_without_third_attempt(self) -> None:
        original = gate.evaluate
        gate.evaluate = lambda: {
            "wakeAgent": False,
            "context": {"reason": "PRIMARY_TRANSIENT_FAILURE"},
        }
        try:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main([]), 0)
        finally:
            gate.evaluate = original

    def test_terminal_fallback_does_not_block_next_day(self) -> None:
        primary = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        gate.evaluate(primary)
        self.primary_429(primary)
        fallback = primary + dt.timedelta(hours=1)
        self.fallback_execution(fallback)
        gate.evaluate(fallback)
        with sqlite3.connect(gate.EXECUTIONS_DB) as connection:
            connection.execute(
                "UPDATE executions SET status='failed', finished_at=?, error=? WHERE id=?",
                (
                    (fallback + dt.timedelta(seconds=10)).isoformat(),
                    "RuntimeError: HTTP 429: The usage limit has been reached",
                    "2" * 32,
                ),
            )
        next_day = gate.evaluate(
            dt.datetime(2026, 9, 5, 5, 0, tzinfo=dt.timezone.utc)
        )
        self.assertTrue(next_day["wakeAgent"])
        self.assertEqual(next_day["context"]["package_id"], "2026-W36--2026-09-05")

    def test_missed_window_catches_up_once(self) -> None:
        late = dt.datetime(2026, 9, 4, 13, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(gate.evaluate(late)["wakeAgent"])
        self.assertFalse(gate.evaluate(late + dt.timedelta(minutes=1))["wakeAgent"])

    def test_next_day_is_independent(self) -> None:
        first = gate.evaluate(dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc))
        second = gate.evaluate(dt.datetime(2026, 9, 5, 5, 0, tzinfo=dt.timezone.utc))
        self.assertTrue(first["wakeAgent"])
        self.assertTrue(second["wakeAgent"])
        self.assertNotEqual(first["context"]["package_id"], second["context"]["package_id"])

    def test_pending_earlier_package_blocks_new_generation(self) -> None:
        pending = gate.OUTBOX / "2026-W36--2026-09-03"
        pending.mkdir()
        result = gate.evaluate(dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc))
        self.assertFalse(result["wakeAgent"])
        self.assertEqual(result["context"]["reason"], "earlier_daily_attempt_pending")

    def test_concurrent_generation_claim_allows_one_writer(self) -> None:
        now = dt.datetime(2026, 9, 4, 5, 0, tzinfo=dt.timezone.utc)
        barrier = threading.Barrier(2)
        results = []

        def call():
            barrier.wait()
            results.append(gate.evaluate(now)["wakeAgent"])

        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [False, True])


class FreshnessTests(unittest.TestCase):
    class Response:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return self.payload

    def opener(self, generated: str):
        raw = json.dumps(
            {"generated": generated, "editions": [{"id": "2026-W36"}], "articles": []}
        ).encode()
        return lambda request, timeout: self.Response(raw)

    def test_fresh_under_26_hours(self) -> None:
        now = dt.datetime(2026, 9, 4, 12, tzinfo=dt.timezone.utc)
        result = freshness.probe(now, self.opener("2026-09-03T11:00:01+00:00"))
        self.assertEqual(result["state"], "FRESH")

    def test_stale_at_26_hours_is_visible(self) -> None:
        now = dt.datetime(2026, 9, 4, 12, tzinfo=dt.timezone.utc)
        result = freshness.probe(now, self.opener("2026-09-03T10:00:00+00:00"))
        self.assertEqual(result["state"], "STALE")


class SchedulerContractTests(unittest.TestCase):
    def test_scheduler_contract_has_dst_safe_fallback(self) -> None:
        value = json.loads(
            (ROOT / "runtime/aihot/generation/hermes-scheduler.json").read_text()
        )
        self.assertEqual(value["schedule"], "0 5,6,7 * * *")
        self.assertEqual(value["scheduler_timezone"], "Etc/UTC")
        self.assertEqual(value["operator_timezone"], "Europe/Stockholm")
        self.assertEqual(value["local_time"], "07:00")

    def test_reconciler_uses_documented_hermes_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            contract = json.loads(
                (ROOT / "runtime/aihot/generation/hermes-scheduler.json").read_text()
            )
            config = temp / "scheduler.json"
            jobs = temp / "jobs.json"
            config.write_text(json.dumps(contract))
            jobs.write_text(
                json.dumps(
                    [
                        {
                            "id": contract["job_id"],
                            "name": contract["name"],
                            "enabled": True,
                            "state": "scheduled",
                            "schedule": {"kind": "cron", "expr": contract["schedule"]},
                            "script": contract["script"],
                            "workdir": contract["workdir"],
                            "prompt": contract["prompt"],
                        }
                    ]
                )
            )
            old_config, old_jobs, old_gate, old_run, old_euid = (
                scheduler.CONFIG,
                scheduler.JOBS,
                scheduler.GATE,
                scheduler.subprocess.run,
                scheduler.os.geteuid,
            )
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                if argv[0] == "timedatectl":
                    return subprocess.CompletedProcess(argv, 0, "Etc/UTC\n", "")
                if argv[0] == scheduler.sys.executable:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        json.dumps(
                            {
                                "status": "AIHOT_DAILY_GATE_INSPECT",
                                "context": {"reason": "daily_attempt_unclaimed"},
                            }
                        ),
                        "",
                    )
                self.assertEqual(argv[:4], [scheduler.HERMES, "cron", "edit", contract["job_id"]])
                return subprocess.CompletedProcess(argv, 0, "", "")

            scheduler.CONFIG, scheduler.JOBS, scheduler.GATE = config, jobs, temp / "gate.py"
            scheduler.subprocess.run = fake_run
            scheduler.os.geteuid = lambda: 0
            try:
                scheduler.check()
                scheduler.install()
            finally:
                scheduler.CONFIG, scheduler.JOBS, scheduler.GATE, scheduler.subprocess.run, scheduler.os.geteuid = (
                    old_config,
                    old_jobs,
                    old_gate,
                    old_run,
                    old_euid,
                )
            hermes_calls = [call for call in calls if call[0] == scheduler.HERMES]
            self.assertEqual(len(hermes_calls), 1)
            self.assertIn(contract["schedule"], hermes_calls[0])

    def test_reconciler_does_not_mask_primary_failure_with_raw_ok(self) -> None:
        old_run = scheduler.subprocess.run

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv,
                0,
                "Etc/UTC\n" if argv[0] == "timedatectl" else json.dumps(
                    {
                        "status": "AIHOT_DAILY_GATE_INSPECT",
                        "context": {"reason": "PRIMARY_TRANSIENT_FAILURE"},
                    }
                ),
                "",
            )

        scheduler.subprocess.run = fake_run
        old_config, old_jobs = scheduler.CONFIG, scheduler.JOBS
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                contract = json.loads(
                    (ROOT / "runtime/aihot/generation/hermes-scheduler.json").read_text()
                )
                scheduler.CONFIG = root / "scheduler.json"
                scheduler.CONFIG.write_text(json.dumps(contract))
                scheduler.JOBS = root / "jobs.json"
                scheduler.JOBS.write_text(
                    json.dumps(
                        [{
                            "id": contract["job_id"],
                            "name": contract["name"],
                            "enabled": True,
                            "state": "scheduled",
                            "last_status": "ok",
                            "schedule": {"kind": "cron", "expr": contract["schedule"]},
                            "script": contract["script"],
                            "workdir": contract["workdir"],
                            "prompt": contract["prompt"],
                        }]
                    )
                )
                with self.assertRaisesRegex(
                    scheduler.SchedulerError, "PRIMARY_TRANSIENT_FAILURE"
                ):
                    scheduler.check()
        finally:
            scheduler.CONFIG, scheduler.JOBS = old_config, old_jobs
            scheduler.subprocess.run = old_run


class HandoffValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        handoff_validator.ROOT = root
        handoff_validator.INBOX = root / "inbox"
        handoff_validator.OUTBOX = root / "outbox"
        handoff_validator.RETRY_STATE = root / "state"
        handoff_validator.SCHEDULER_CONFIG = root / "scheduler.json"
        handoff_validator.EXECUTIONS_DB = root / "executions.db"
        handoff_validator.CRON_OUTPUT = root / "output"
        handoff_validator.INBOX.mkdir()
        handoff_validator.OUTBOX.mkdir()
        self.package_id = "2026-W36--2026-09-04"
        self.package = handoff_validator.OUTBOX / self.package_id
        self.package.mkdir()
        self.base = {
            "generated": "2026-08-28T04:08:59+00:00",
            "editions": [],
            "articles": [],
        }
        raw = json.dumps(self.base, ensure_ascii=False, separators=(",", ":")).encode()
        (handoff_validator.INBOX / "current.json").write_bytes(raw)
        article = json.loads((FIXTURES / "valid-article.json").read_text())
        article.update(
            {
                "id": "invalid-date",
                "date": "2026-08-26",
            }
        )
        candidate = {
            **self.base,
            "editions": [{"id": "2026-W36"}],
            "articles": [article],
        }
        (self.package / "candidate.json").write_text(json.dumps(candidate))
        (self.package / "handoff.json").write_text(
            json.dumps(
                {
                    "schema": "gneu-aihot-handoff-v2",
                    "producer": "adam",
                    "edition": "2026-W36",
                    "attempt": "2026-09-04",
                    "mode": "edition",
                    "base_sha256": hashlib.sha256(raw).hexdigest(),
                    "base_generated": self.base["generated"],
                }
            )
        )
        (self.package / "report.md").write_text("deterministic report " * 20)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def call_validator(self):
        import sys

        old = sys.argv
        sys.argv = ["validator", self.package_id]
        try:
            return handoff_validator.main()
        finally:
            sys.argv = old

    def authorize_handoff_r1(self, target_id: str) -> None:
        paths = local_retry.RetryPaths(
            handoff_validator.RETRY_STATE,
            handoff_validator.OUTBOX,
            handoff_validator.SCHEDULER_CONFIG,
            handoff_validator.EXECUTIONS_DB,
            handoff_validator.CRON_OUTPUT,
        )
        hashes = local_retry.source_hashes(paths, "2026-W36--2026-09-04")
        authorization = {
            "schema": "gneu-aihot-generation-retry-authorization-v1",
            "edition": "2026-W36",
            "attempt": "2026-09-04",
            "source_package_id": "2026-W36--2026-09-04",
            "source_candidate_sha256": hashes["candidate"],
            "source_handoff_sha256": hashes["handoff"],
            "source_report_sha256": hashes["report"],
            "hermes_execution_id": "b" * 32,
            "validation_failure": local_retry.REASON,
            "target_package_id": target_id,
            "revision": 1,
            "authorized_at": "2026-09-04T07:30:00+00:00",
        }
        auth_sha = local_retry.atomic_create(
            local_retry.authorization_path(paths, "2026-09-04"), authorization
        )
        local_retry.atomic_create(
            local_retry.consumed_path(paths, "2026-09-04"),
            {
                **authorization,
                "schema": "gneu-aihot-generation-retry-consumed-v1",
                "authorization_sha256": auth_sha,
                "consumed_at": "2026-09-04T07:31:00+00:00",
            },
        )

    def test_article_date_outside_edition_never_creates_ready(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.call_validator()
        self.assertIn("article invalid-date.date is outside 2026-W36", str(caught.exception))
        self.assertFalse((self.package / "READY").exists())

    def test_existing_ready_is_never_deleted_or_overwritten(self) -> None:
        ready = self.package / "READY"
        ready.write_text("immutable old marker\n")
        before = ready.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            self.call_validator()
        self.assertEqual(ready.read_bytes(), before)
        self.assertIn("ALREADY_READY", output.getvalue())

    def test_r1_requires_revision_binding_and_accepts_in_week_article(self) -> None:
        target = handoff_validator.OUTBOX / (self.package_id + "--r1")
        shutil.copytree(self.package, target)
        source = handoff_validator.OUTBOX / self.package_id
        self.package = target
        candidate = json.loads((target / "candidate.json").read_text())
        candidate["articles"][0]["date"] = "2026-09-02"
        (target / "candidate.json").write_text(json.dumps(candidate))
        handoff = json.loads((target / "handoff.json").read_text())
        handoff["revision"] = 1
        (target / "handoff.json").write_text(json.dumps(handoff))
        self.package_id += "--r1"
        self.authorize_handoff_r1(self.package_id)
        self.call_validator()
        self.assertTrue((target / "READY").is_file())
        self.assertFalse((source / "READY").exists())

    def test_r1_without_revision_binding_is_blocked(self) -> None:
        target = handoff_validator.OUTBOX / (self.package_id + "--r1")
        shutil.copytree(self.package, target)
        self.package = target
        self.package_id += "--r1"
        self.authorize_handoff_r1(self.package_id)
        with self.assertRaises(SystemExit) as caught:
            self.call_validator()
        self.assertIn("handoff revision mismatch", str(caught.exception))


class GeneratorContractTests(unittest.TestCase):
    def test_research_window_is_not_candidate_eligibility(self) -> None:
        contract = (ROOT / "runtime/aihot/generation/CONTRACT.md").read_text()
        instructions = (ROOT / "runtime/aihot/generation/ADAM_DAILY.md").read_text()
        for value in (contract, instructions):
            self.assertIn("date.fromisoformat(article_date).isocalendar()", value)
            self.assertIn("research window", value.lower())
            self.assertIn("supplied edition", value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
