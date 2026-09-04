#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "runtime/aihot/bin"))
NOW = dt.datetime(2026, 9, 4, 7, 30, tzinfo=dt.timezone.utc)
ATTEMPT = "2026-09-04"
SOURCE = "2026-W36--2026-09-04"
TARGET = SOURCE + "--r1"
EXECUTION = "7085ac11c6aa40b4a8ff53bc2e7cc299"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retry = load(
    "aihot_local_retry_test",
    ROOT / "runtime/aihot/bin/aihot_local_retry.py",
)
gate = load(
    "aihot_daily_gate_local_retry_test",
    ROOT / "runtime/aihot/generation/gneu-aihot-daily-gate.py",
)
identity = load(
    "aihot_package_identity_test",
    ROOT / "runtime/aihot/bin/aihot_package_identity.py",
)


class PackageIdentityTests(unittest.TestCase):
    def test_legacy_revision_zero_and_r1_are_distinct(self) -> None:
        self.assertEqual(identity.parse_package_id("2026-W36"), ("2026-W36", None, None))
        self.assertEqual(
            identity.parse_package_id(SOURCE), ("2026-W36", ATTEMPT, 0)
        )
        self.assertEqual(
            identity.parse_package_id(TARGET), ("2026-W36", ATTEMPT, 1)
        )

    def test_later_revision_and_wrong_iso_week_are_blocked(self) -> None:
        for package_id in (SOURCE + "--r2", "2026-W36--2026-08-27--r1"):
            with self.subTest(package_id=package_id):
                with self.assertRaises(ValueError):
                    identity.parse_package_id(package_id)


class LocalRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.state = root / "state"
        self.handoff_root = root / "handoff"
        self.outbox = self.handoff_root / "outbox"
        self.inbox = self.handoff_root / "inbox"
        self.config = root / "scheduler.json"
        self.db = root / "executions.db"
        self.output = root / "output"
        self.outbox.mkdir(parents=True)
        self.inbox.mkdir()
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
            connection.execute(
                "INSERT INTO executions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    EXECUTION,
                    "fbd796dbb875",
                    "direct",
                    "process-id",
                    123,
                    None,
                    "completed",
                    "2026-09-04T07:00:00+00:00",
                    "2026-09-04T07:00:00+00:00",
                    "2026-09-04T07:20:00+00:00",
                    None,
                ),
            )
        base = {"generated": "2026-08-28T04:08:59+00:00", "editions": [], "articles": []}
        base_raw = json.dumps(base, separators=(",", ":")).encode()
        (self.inbox / "current.json").write_bytes(base_raw)
        package = self.outbox / SOURCE
        package.mkdir()
        candidate = {
            **base,
            "editions": [{"id": "2026-W36"}],
            "articles": [
                {
                    "id": "outside-week",
                    "edition": "2026-W36",
                    "date": "2026-08-26",
                    "sources": [{}, {}],
                }
            ],
        }
        (package / "candidate.json").write_text(json.dumps(candidate))
        (package / "handoff.json").write_text(
            json.dumps(
                {
                    "schema": "gneu-aihot-handoff-v2",
                    "producer": "adam",
                    "edition": "2026-W36",
                    "attempt": ATTEMPT,
                    "mode": "edition",
                    "base_sha256": hashlib.sha256(base_raw).hexdigest(),
                    "base_generated": base["generated"],
                }
            )
        )
        (package / "report.md").write_text("reproducible local failure " * 20)
        output_dir = self.output / "fbd796dbb875"
        output_dir.mkdir()
        (output_dir / "run.md").write_text(
            f"AIHOT_HANDOFF_FAILED {SOURCE} article date outside edition\n"
        )
        self.paths = retry.RetryPaths(
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

    def hashes(self) -> dict[str, str]:
        return retry.source_hashes(self.paths, SOURCE)

    def authorize(self):
        return retry.authorize(
            self.paths, ATTEMPT, self.hashes(), EXECUTION, retry.REASON, NOW
        )

    def state_file(self, directory: str, package_id: str, suffix: str = ".json") -> Path:
        path = self.state / directory
        path.mkdir(parents=True, exist_ok=True)
        result = path / f"{package_id}{suffix}"
        result.write_text("{}\n")
        return result

    def test_r1_requires_authorization_and_is_consumed_once(self) -> None:
        source_before = {
            name: (self.outbox / SOURCE / name).read_bytes()
            for name in ("candidate.json", "handoff.json", "report.md")
        }
        blocked = gate.evaluate(NOW)
        self.assertFalse(blocked["wakeAgent"])
        self.assertEqual(blocked["context"]["reason"], "daily_attempt_requires_operator")
        authorization, _ = self.authorize()
        self.assertEqual(authorization["target_package_id"], TARGET)
        self.assertEqual(authorization["revision"], 1)
        auth_path = retry.authorization_path(self.paths, ATTEMPT)
        self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((auth_path.stat().st_uid, auth_path.stat().st_gid), (0, 0))
        admitted = gate.evaluate(NOW + dt.timedelta(minutes=1))
        self.assertTrue(admitted["wakeAgent"])
        self.assertEqual(admitted["context"]["package_id"], TARGET)
        self.assertEqual(admitted["context"]["reason"], "operator_local_retry")
        self.assertEqual(admitted["context"]["revision"], 1)
        consumed_path = retry.consumed_path(self.paths, ATTEMPT)
        self.assertEqual(consumed_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            (consumed_path.stat().st_uid, consumed_path.stat().st_gid), (0, 0)
        )
        duplicate = gate.evaluate(NOW + dt.timedelta(minutes=2))
        self.assertFalse(duplicate["wakeAgent"])
        self.assertEqual(duplicate["context"]["reason"], "retry_already_consumed")
        self.assertEqual(
            source_before,
            {
                name: (self.outbox / SOURCE / name).read_bytes()
                for name in source_before
            },
        )

    def test_source_is_immutable_and_authorization_is_append_only(self) -> None:
        hashes = self.hashes()
        _, first_sha = self.authorize()
        with self.assertRaises(retry.RetryError):
            retry.authorize(
                self.paths, ATTEMPT, hashes, EXECUTION, retry.REASON, NOW
            )
        receipt = retry.authorization_path(self.paths, ATTEMPT)
        self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(), first_sha)
        (self.outbox / SOURCE / "report.md").write_text("modified " * 30)
        unsafe = gate.evaluate(NOW + dt.timedelta(minutes=1))
        self.assertFalse(unsafe["wakeAgent"])
        self.assertEqual(unsafe["context"]["reason"], "unsafe_retry_state")

    def test_source_and_target_conflicts_block_authorization(self) -> None:
        conflicts = (
            lambda: (self.outbox / SOURCE / "READY").write_text("PASS\n"),
            lambda: self.state_file("processed", SOURCE),
            lambda: self.state_file("failed", SOURCE),
            lambda: self.state_file("intake", SOURCE, ".transport.json"),
            lambda: (self.outbox / TARGET).mkdir(),
            lambda: self.state_file("processed", TARGET),
            lambda: self.state_file("failed", TARGET),
            lambda: self.state_file("intake", TARGET, ".transport.json"),
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                self.tearDown()
                self.setUp()
                conflict()
                with self.assertRaises(retry.RetryError):
                    self.authorize()

    def test_active_generation_and_wrong_hashes_are_blocked(self) -> None:
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "UPDATE executions SET status='running' WHERE id=?", (EXECUTION,)
            )
        with self.assertRaises(retry.RetryError):
            self.authorize()
        self.tearDown()
        self.setUp()
        hashes = self.hashes()
        hashes["candidate"] = "0" * 64
        with self.assertRaises(retry.RetryError):
            retry.authorize(
                self.paths, ATTEMPT, hashes, EXECUTION, retry.REASON, NOW
            )

    def test_only_same_day_r1_is_supported(self) -> None:
        with self.assertRaises(retry.RetryError):
            retry.authorize(
                self.paths,
                ATTEMPT,
                self.hashes(),
                EXECUTION,
                retry.REASON,
                NOW + dt.timedelta(days=1),
            )
        for value in (SOURCE + "--r2", SOURCE + "--r10"):
            self.assertIsNone(gate.DAILY_PACKAGE_RE.fullmatch(value))

    def test_tomorrow_normal_revision_zero_is_unaffected_after_terminal_r1(self) -> None:
        self.authorize()
        admitted = gate.evaluate(NOW + dt.timedelta(minutes=1))
        self.assertTrue(admitted["wakeAgent"])
        self.state_file("processed", TARGET)
        tomorrow = gate.evaluate(NOW + dt.timedelta(days=1))
        self.assertTrue(tomorrow["wakeAgent"])
        self.assertEqual(tomorrow["context"]["package_id"], "2026-W36--2026-09-05")
        self.assertNotIn("revision", tomorrow["context"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
