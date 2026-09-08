#!/usr/bin/env python3
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "runtime/aihot/bin"
sys.path.insert(0, str(BIN))

import aihot_historical_disposition as historical

PROCESS_SPEC = importlib.util.spec_from_file_location(
    "aihot_process_ready_historical", BIN / "process-ready.py"
)
assert PROCESS_SPEC is not None and PROCESS_SPEC.loader is not None
process_ready = importlib.util.module_from_spec(PROCESS_SPEC)
PROCESS_SPEC.loader.exec_module(process_ready)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)


def write_json(path: Path, value: object) -> None:
    write(path, canonical(value))


class HistoricalFixture:
    approval = "Human approved the exact historical terminal lineage"
    reason = "Verified historical blocker is closed without retry"

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.outbox = self.root / "outbox"
        self.state.mkdir(mode=0o700)
        self.outbox.mkdir(mode=0o700)
        (self.state / "process-ready.lock").touch(mode=0o600)
        for package_id in historical.HISTORICAL_CASES:
            self.make_case(package_id)

    def close(self) -> None:
        self.temporary.cleanup()

    def make_package(self, package_id: str) -> None:
        package = self.outbox / package_id
        package.mkdir(mode=0o700)
        write(package / "READY", f"PASS {package_id}\n".encode())
        write_json(package / "handoff.json", {"package_id": package_id})
        write_json(package / "candidate.json", {"package_id": package_id})
        write(package / "report.md", f"Report for {package_id}\n".encode())

    def make_case(self, package_id: str) -> None:
        self.make_package(package_id)
        case = historical.HISTORICAL_CASES[package_id]
        failed = {
            "schema": "gneu-aihot-ready-failure-v1",
            "package_id": package_id,
            "failed_stage": "dispatch",
            "stages": [],
        }
        if case.failure_stage == "build":
            failed.update(
                {
                    "failed_stage": "build",
                    "stages": [
                        {
                            "stage": "build",
                            "returncode": 1,
                            "output": "BLOCKED: " + case.failure_detail + "\n",
                        }
                    ],
                }
            )
        write_json(self.state / "failed" / f"{package_id}.json", failed)
        if package_id.endswith("--r1"):
            attempt = "2026-09-04"
            write_json(
                self.state / "generation/retry-authorized" / f"{attempt}-r1.json",
                {"target_package_id": package_id},
            )
            write_json(
                self.state / "generation/retry-consumed" / f"{attempt}-r1.json",
                {"target_package_id": package_id},
            )
            ready = {
                "package_id": package_id,
                "runtime_source_commit": "a" * 40,
            }
            write_json(
                self.state / "ready-retry/authorized" / f"{package_id}.json", ready
            )
            write_json(
                self.state / "ready-retry/consumed" / f"{package_id}.json", ready
            )
            write_json(
                self.state / "ready-retry/failed" / f"{package_id}.json",
                {
                    "schema": "gneu-aihot-ready-retry-failure-v1",
                    "package_id": package_id,
                    "failure_code": "DISPATCH_FAILED",
                },
            )
        elif package_id.endswith("--r2"):
            attempt = "2026-09-04"
            content = {
                "target_package_id": package_id,
                "runtime_source_commit": "b" * 40,
                "reason": "TRUSTED_CONTENT_CONTRACT_MISSING_EVIDENCE",
            }
            write_json(
                self.state / "generation/retry-authorized" / f"{attempt}-r2.json",
                content,
            )
            write_json(
                self.state / "generation/retry-consumed" / f"{attempt}-r2.json",
                content,
            )

    def evidence(self, package_id: str) -> dict[str, str]:
        return historical.recompute_evidence(
            historical.HISTORICAL_CASES[package_id], self.state, self.outbox
        )

    def append(self, package_id: str, **changes: object) -> str:
        case = historical.HISTORICAL_CASES[package_id]
        arguments = {
            "package_id": package_id,
            "failure_code": case.failure_code,
            "evidence_sha256": self.evidence(package_id),
            "human_approval": self.approval,
            "operator_reason": self.reason,
        }
        arguments.update(changes)
        return historical.append_disposition(
            **arguments,
            state_root=self.state,
            outbox_root=self.outbox,
            now=lambda: dt.datetime(2026, 9, 8, 12, 0, tzinfo=dt.timezone.utc),
        )


class HistoricalDispositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HistoricalFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def assert_blocked(self, callback) -> None:
        with self.assertRaises(historical.HistoricalDispositionError):
            callback()

    def configure_processor(self) -> None:
        process_ready.STATE = self.fixture.state
        process_ready.OUTBOX = self.fixture.outbox
        process_ready.PROCESSED = self.fixture.state / "processed"
        process_ready.FAILED = self.fixture.state / "failed"
        process_ready.BIN = self.fixture.root / "bin"
        process_ready.LOCK = self.fixture.state / "process-ready.lock"

    def test_r1_exact_disposition_is_non_actionable(self) -> None:
        package = "2026-W36--2026-09-04--r1"
        evidence_paths = historical.evidence_paths(
            self.fixture.state,
            self.fixture.outbox,
            historical.HISTORICAL_CASES[package],
        )
        protected = {path: path.read_bytes() for path in evidence_paths.values()}
        state_before = {path for path in self.fixture.state.rglob("*") if path.is_file()}
        self.assertEqual(self.fixture.append(package), "HISTORICAL_TERMINAL_DISPOSED")
        self.assertEqual({path: path.read_bytes() for path in protected}, protected)
        state_after = {path for path in self.fixture.state.rglob("*") if path.is_file()}
        self.assertEqual(
            state_after - state_before,
            {historical.disposition_path(self.fixture.state, package)},
        )
        self.configure_processor()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(process_ready.process_package(package))
        self.assertIn("HISTORICAL_TERMINAL_NON_ACTIONABLE", output.getvalue())

    def test_r2_exact_disposition_and_r3_forbidden(self) -> None:
        package = "2026-W36--2026-09-04--r2"
        self.fixture.append(package)
        self.configure_processor()
        self.assertTrue(process_ready.process_package(package))
        self.assert_blocked(
            lambda: historical.append_disposition(
                "2026-W36--2026-09-04--r3",
                "INVALID_RUNTIME_PROVENANCE",
                {},
                self.fixture.approval,
                self.fixture.reason,
                state_root=self.fixture.state,
                outbox_root=self.fixture.outbox,
            )
        )

    def test_w37_build_failure_exact_disposition_is_non_actionable(self) -> None:
        package = "2026-W37--2026-09-07"
        self.fixture.append(package)
        self.configure_processor()
        self.assertTrue(process_ready.process_package(package))

    def test_wrong_package_and_wildcard_are_blocked(self) -> None:
        for package in ("2026-W38--2026-09-14", "2026-W37--*"):
            self.assert_blocked(
                lambda package=package: historical.append_disposition(
                    package,
                    "CANDIDATE_EDITION_PREFIX_DIFFERS_FROM_ORIGIN_MAIN",
                    {},
                    self.fixture.approval,
                    self.fixture.reason,
                    state_root=self.fixture.state,
                    outbox_root=self.fixture.outbox,
                )
            )

    def test_wrong_evidence_hash_is_blocked(self) -> None:
        package = "2026-W37--2026-09-07"
        evidence = self.fixture.evidence(package)
        evidence["failed_sha256"] = "0" * 64
        self.assert_blocked(
            lambda: self.fixture.append(package, evidence_sha256=evidence)
        )

    def test_wrong_failure_code_is_blocked(self) -> None:
        self.assert_blocked(
            lambda: self.fixture.append(
                "2026-W37--2026-09-07", failure_code="BUILD_FAILED"
            )
        )

    def test_changed_failure_detail_is_blocked(self) -> None:
        package = "2026-W37--2026-09-07"
        failed = self.fixture.state / "failed" / f"{package}.json"
        value = json.loads(failed.read_text())
        value["stages"][-1]["output"] = "different build failure\n"
        write_json(failed, value)
        self.assert_blocked(lambda: self.fixture.append(package))

    def test_duplicate_identical_is_noop(self) -> None:
        package = "2026-W37--2026-09-07"
        self.fixture.append(package)
        path = historical.disposition_path(self.fixture.state, package)
        before = path.read_bytes()
        self.assertEqual(self.fixture.append(package), "ALREADY_HISTORICAL_TERMINAL")
        self.assertEqual(path.read_bytes(), before)

    def test_conflicting_disposition_is_blocked(self) -> None:
        package = "2026-W37--2026-09-07"
        self.fixture.append(package)
        self.assert_blocked(
            lambda: self.fixture.append(
                package,
                operator_reason="A conflicting historical disposition reason",
            )
        )

    def test_future_failure_without_disposition_remains_blocking(self) -> None:
        package = "2026-W38--2026-09-14"
        self.fixture.make_package(package)
        write_json(
            self.fixture.state / "failed" / f"{package}.json",
            {
                "schema": "gneu-aihot-ready-failure-v1",
                "package_id": package,
                "failed_stage": "build",
                "stages": [],
            },
        )
        self.configure_processor()
        original = process_ready.consume_publication_retry
        process_ready.consume_publication_retry = lambda paths, identity: None
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                self.assertFalse(process_ready.process_package(package))
        finally:
            process_ready.consume_publication_retry = original
        self.assertIn("FAILED_REQUIRES_OPERATOR", output.getvalue())

    def test_invalid_receipt_hash_binding_blocks_processor(self) -> None:
        package = "2026-W37--2026-09-07"
        self.fixture.append(package)
        write(self.fixture.outbox / package / "report.md", b"changed immutable report\n")
        self.configure_processor()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertFalse(process_ready.process_package(package))
        self.assertIn("BLOCKED_INVALID_HISTORICAL_DISPOSITION", output.getvalue())

    def test_disposed_history_allows_today_no_change_to_pass(self) -> None:
        for package in historical.HISTORICAL_CASES:
            self.fixture.append(package)
        today = "2026-W37--2026-09-08"
        self.fixture.make_package(today)
        payload_raw = canonical({"package_id": today, "mode": "no-change"})[:-1]
        compressed = gzip.compress(payload_raw, mtime=0)
        write_json(
            self.fixture.state / "intake" / f"{today}.transport.json",
            {
                "payload_b64": base64.urlsafe_b64encode(compressed)
                .rstrip(b"=")
                .decode(),
                "payload_sha256": hashlib.sha256(compressed).hexdigest(),
                "base_main_sha": "c" * 40,
                "mode": "no-change",
            },
        )
        self.configure_processor()
        calls: list[list[str]] = []
        original_run = process_ready.run
        process_ready.run = lambda argv: (
            calls.append(argv) or subprocess.CompletedProcess(argv, 0, "PASS\n")
        )
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                self.assertEqual(process_ready.main(), 0)
        finally:
            process_ready.run = original_run
        text = output.getvalue()
        for package in historical.HISTORICAL_CASES:
            self.assertIn(f"HISTORICAL_TERMINAL_NON_ACTIONABLE {package}", text)
        self.assertIn(f"AIHOT_READY_PROCESSED {today}", text)
        self.assertEqual(len(calls), 3)
        self.assertTrue((self.fixture.state / "processed" / f"{today}.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
