#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


resume = load(
    "aihot_claim_resume",
    ROOT / "runtime/aihot/bin/aihot_claim_resume.py",
)
gate = load(
    "aihot_daily_gate_resume",
    ROOT / "runtime/aihot/generation/gneu-aihot-daily-gate.py",
)


NOW = dt.datetime(2026, 9, 4, 7, 30, tzinfo=dt.timezone.utc)
ATTEMPT = "2026-09-04"
PACKAGE_ID = "2026-W36--2026-09-04"


class ClaimResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.state = root / "state"
        self.outbox = root / "outbox"
        self.config = root / "scheduler.json"
        self.db = root / "executions.db"
        self.output = root / "output"
        self.outbox.mkdir()
        self.output.mkdir()
        self.config.write_text(
            json.dumps(
                {
                    "schema": "gneu-aihot-hermes-scheduler-v1",
                    "job_id": "fbd796dbb875",
                    "name": "gneu-aihot-daily",
                    "script": "gneu-aihot-daily-gate.py",
                }
            )
        )
        self.config.chmod(0o600)
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                """CREATE TABLE executions (
                id TEXT PRIMARY KEY, job_id TEXT NOT NULL, source TEXT NOT NULL,
                process_id TEXT NOT NULL, pid INTEGER NOT NULL,
                process_started_at INTEGER, status TEXT NOT NULL,
                claimed_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                error TEXT)"""
            )
        self.paths = resume.ResumePaths(
            self.state, self.outbox, self.config, self.db, self.output
        )
        gate.STATE = self.state
        gate.OUTBOX = self.outbox
        gate.CLAIMS = self.state / "generation"
        gate.BASE_META = root / "missing-meta.json"
        gate.SCHEDULER_CONFIG = self.config
        gate.EXECUTIONS_DB = self.db
        gate.CRON_OUTPUT = self.output

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def snapshot(self) -> list[tuple[str, int, bytes]]:
        if not self.state.exists():
            return []
        result = []
        for path in sorted(self.state.rglob("*")):
            relative = str(path.relative_to(self.state))
            mode = path.lstat().st_mode
            result.append((relative, mode, path.read_bytes() if path.is_file() else b""))
        return result

    def initial_claim(self) -> tuple[dict, str]:
        result = gate.evaluate(NOW)
        self.assertTrue(result["wakeAgent"])
        claim = gate.CLAIMS / f"{ATTEMPT}.json"
        return result, hashlib.sha256(claim.read_bytes()).hexdigest()

    def authorize(self, claim_sha: str, now: dt.datetime = NOW):
        return resume.authorize(
            self.paths,
            ATTEMPT,
            claim_sha,
            resume.REASON,
            now,
        )

    def insert_execution(self, status: str, claimed_at: str) -> None:
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "INSERT INTO executions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "execution-id",
                    "fbd796dbb875",
                    "manual",
                    "process-id",
                    123,
                    None,
                    status,
                    claimed_at,
                    claimed_at,
                    claimed_at if status in {"completed", "failed"} else None,
                    None,
                ),
            )

    def test_help_and_inspection_are_side_effect_free(self) -> None:
        before = self.snapshot()
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                gate.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(self.snapshot(), before)

        for command in ("help", "inspect", "check"):
            before = self.snapshot()
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.main([command]), 0)
            self.assertEqual(self.snapshot(), before)
            if command != "help":
                value = json.loads(output.getvalue())
                self.assertEqual(value["status"], "AIHOT_DAILY_GATE_INSPECT")
                self.assertNotIn("wakeAgent", value)

    def test_missing_claim_authorization_has_no_state_side_effect(self) -> None:
        before = self.snapshot()
        with self.assertRaises(resume.ResumeError):
            self.authorize("0" * 64)
        self.assertEqual(self.snapshot(), before)

    def test_normal_duplicate_and_authorized_resume_are_exactly_once(self) -> None:
        first, claim_sha = self.initial_claim()
        self.assertEqual(first["context"]["reason"], "daily_aihot_window")
        duplicate = gate.evaluate(NOW + dt.timedelta(minutes=1))
        self.assertFalse(duplicate["wakeAgent"])
        self.assertEqual(duplicate["context"]["reason"], "daily_attempt_already_claimed")

        authorization, _ = self.authorize(claim_sha)
        authorization_path = self.paths.authorizations / f"{ATTEMPT}.json"
        self.assertEqual(authorization["package_id"], PACKAGE_ID)
        self.assertEqual(authorization_path.stat().st_mode & 0o777, 0o600)

        resumed = gate.evaluate(NOW + dt.timedelta(minutes=2))
        self.assertTrue(resumed["wakeAgent"])
        self.assertEqual(resumed["context"]["reason"], "operator_resume_claim")
        self.assertEqual(resumed["context"]["package_id"], PACKAGE_ID)
        consumed = self.paths.consumed / f"{ATTEMPT}.json"
        self.assertTrue(consumed.is_file())
        self.assertEqual(consumed.stat().st_mode & 0o777, 0o600)
        resume.verify_consumed(self.paths, ATTEMPT, claim_sha)

        final = gate.evaluate(NOW + dt.timedelta(minutes=3))
        self.assertFalse(final["wakeAgent"])
        self.assertEqual(final["context"]["reason"], "resume_already_consumed")

    def test_concurrent_resume_admits_exactly_one_agent(self) -> None:
        _, claim_sha = self.initial_claim()
        self.authorize(claim_sha)
        barrier = threading.Barrier(2)
        results = []

        def call() -> None:
            barrier.wait()
            results.append(gate.evaluate(NOW + dt.timedelta(minutes=2)))

        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(value["wakeAgent"] for value in results), [False, True])
        self.assertEqual(
            sorted(value["context"]["reason"] for value in results),
            ["operator_resume_claim", "resume_already_consumed"],
        )

    def test_active_or_completed_execution_after_claim_blocks_authorization(self) -> None:
        for status in ("claimed", "running", "completed"):
            with self.subTest(status=status):
                self.tearDown()
                self.setUp()
                _, claim_sha = self.initial_claim()
                self.insert_execution(status, "2026-09-04T07:31:00+00:00")
                with self.assertRaises(resume.ResumeError):
                    self.authorize(claim_sha)

    def test_package_processed_and_failed_state_each_block_authorization(self) -> None:
        cases = (
            lambda: (self.outbox / PACKAGE_ID).mkdir(),
            lambda: self._state_file("processed"),
            lambda: self._state_file("failed"),
            self._transport_file,
        )
        for create_conflict in cases:
            with self.subTest(create_conflict=create_conflict):
                self.tearDown()
                self.setUp()
                _, claim_sha = self.initial_claim()
                create_conflict()
                with self.assertRaises(resume.ResumeError):
                    self.authorize(claim_sha)

    def _state_file(self, directory: str) -> None:
        path = self.state / directory
        path.mkdir(parents=True)
        (path / f"{PACKAGE_ID}.json").write_text("{}\n")

    def _transport_file(self) -> None:
        path = self.state / "intake"
        path.mkdir(parents=True)
        (path / f"{PACKAGE_ID}.transport.json").write_text("{}\n")

    def test_scheduler_output_at_or_after_claim_blocks_authorization(self) -> None:
        _, claim_sha = self.initial_claim()
        directory = self.output / "fbd796dbb875"
        directory.mkdir()
        evidence = directory / "2026-09-04_07-31-00.md"
        evidence.write_text("completed generation\n")
        timestamp = dt.datetime(2026, 9, 4, 7, 31, tzinfo=dt.timezone.utc).timestamp()
        os.utime(evidence, (timestamp, timestamp))
        with self.assertRaises(resume.ResumeError):
            self.authorize(claim_sha)

    def test_wrong_claim_hash_and_wrong_package_identity_are_blocked(self) -> None:
        _, claim_sha = self.initial_claim()
        with self.assertRaises(resume.ResumeError):
            self.authorize("0" * 64)

        claim_path = gate.CLAIMS / f"{ATTEMPT}.json"
        value = json.loads(claim_path.read_text())
        value["package_id"] = "2026-W36--2026-09-05"
        claim_path.write_bytes(resume.canonical_bytes(value))
        invalid_sha = hashlib.sha256(claim_path.read_bytes()).hexdigest()
        with self.assertRaises(resume.ResumeError):
            self.authorize(invalid_sha)
        self.assertFalse((self.paths.authorizations / f"{ATTEMPT}.json").exists())

    def test_previous_and_future_local_dates_are_blocked(self) -> None:
        _, claim_sha = self.initial_claim()
        for now in (
            dt.datetime(2026, 9, 3, 12, tzinfo=dt.timezone.utc),
            dt.datetime(2026, 9, 5, 12, tzinfo=dt.timezone.utc),
        ):
            with self.subTest(now=now):
                with self.assertRaises(resume.ResumeError):
                    self.authorize(claim_sha, now)

    def test_authorization_is_append_only_and_cannot_be_overwritten(self) -> None:
        _, claim_sha = self.initial_claim()
        _, first_sha = self.authorize(claim_sha)
        path = self.paths.authorizations / f"{ATTEMPT}.json"
        before = path.read_bytes()
        with self.assertRaises(resume.ResumeError):
            self.authorize(claim_sha, NOW + dt.timedelta(minutes=1))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(hashlib.sha256(before).hexdigest(), first_sha)


if __name__ == "__main__":
    unittest.main(verbosity=2)
