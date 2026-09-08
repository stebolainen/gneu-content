#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout

from test_aihot_historical_disposition import (
    HistoricalFixture,
    canonical,
    process_ready,
    write,
    write_json,
)


HISTORICAL = (
    "2026-W36--2026-09-04--r1",
    "2026-W36--2026-09-04--r2",
    "2026-W37--2026-09-07",
)


class ReleaseLivenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = HistoricalFixture()
        process_ready.STATE = self.fixture.state
        process_ready.OUTBOX = self.fixture.outbox
        process_ready.PROCESSED = self.fixture.state / "processed"
        process_ready.FAILED = self.fixture.state / "failed"
        process_ready.BIN = self.fixture.root / "bin"
        process_ready.LOCK = self.fixture.state / "process-ready.lock"

    def tearDown(self) -> None:
        self.fixture.close()

    def add_current(self, package_id: str, mode: str) -> None:
        self.fixture.make_package(package_id)
        write_json(
            self.fixture.outbox / package_id / "handoff.json",
            {
                "package_id": package_id,
                "mode": mode,
                "base_sha256": "d" * 64,
            },
        )
        if mode == "no-change":
            return
        payload_raw = canonical({"package_id": package_id, "mode": mode})[:-1]
        compressed = gzip.compress(payload_raw, mtime=0)
        write_json(
            self.fixture.state / "intake" / f"{package_id}.transport.json",
            {
                "payload_b64": base64.urlsafe_b64encode(compressed)
                .rstrip(b"=")
                .decode(),
                "payload_sha256": hashlib.sha256(compressed).hexdigest(),
                "base_main_sha": "c" * 40,
                "mode": mode,
            },
        )

    def snapshot_immutable(self) -> dict:
        roots = (
            self.fixture.state / "failed",
            self.fixture.state / "ready-retry",
            self.fixture.state / "generation/retry-authorized",
            self.fixture.state / "generation/retry-consumed",
        )
        return {
            path: path.read_bytes()
            for root in roots
            if root.exists()
            for path in root.rglob("*")
            if path.is_file()
        }

    def run_queue(self) -> tuple[int, str, list[list[str]]]:
        calls: list[list[str]] = []
        original = process_ready.run
        process_ready.run = lambda argv: (
            calls.append(argv) or subprocess.CompletedProcess(argv, 0, "PASS\n")
        )
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                result = process_ready.main()
        finally:
            process_ready.run = original
        return result, output.getvalue(), calls

    def test_old_terminal_failures_skip_and_later_no_change_exits_zero(self) -> None:
        today = "2026-W37--2026-09-08"
        self.add_current(today, "no-change")
        immutable_before = self.snapshot_immutable()
        state_files_before = {
            path for path in self.fixture.state.rglob("*") if path.is_file()
        }
        result, output, calls = self.run_queue()
        self.assertEqual(result, 0)
        for package_id in HISTORICAL:
            self.assertIn(f"HISTORICAL_TERMINAL_SKIPPED {package_id}", output)
        self.assertIn(f"AIHOT_READY_NO_CHANGE_PROCESSED {today}", output)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][-1] == today)
        self.assertNotIn("dispatch-trusted-intake.py", " ".join(calls[0]))
        self.assertEqual(self.snapshot_immutable(), immutable_before)
        self.assertFalse(
            (self.fixture.state / "historical-terminal-dispositions").exists()
        )
        self.assertFalse(
            (self.fixture.state / "intake" / f"{today}.transport.json").exists()
        )
        state_files_after = {
            path for path in self.fixture.state.rglob("*") if path.is_file()
        }
        self.assertEqual(
            state_files_after - state_files_before,
            {self.fixture.state / "processed" / f"{today}.json"},
        )

    def test_later_valid_content_reaches_dispatch_path(self) -> None:
        current = "2026-W38--2026-09-14"
        self.add_current(current, "edition")
        result, output, calls = self.run_queue()
        self.assertEqual(result, 0)
        self.assertIn(f"AIHOT_READY_PROCESSED {current}", output)
        self.assertTrue(
            any("dispatch-trusted-intake.py" in " ".join(call) for call in calls)
        )
        for package_id in HISTORICAL:
            self.assertIn(f"HISTORICAL_TERMINAL_SKIPPED {package_id}", output)

    def test_current_unresolved_failure_still_blocks(self) -> None:
        result, output, _ = self.run_queue()
        self.assertEqual(result, 1)
        self.assertIn("FAILED_REQUIRES_OPERATOR 2026-W37--2026-09-07", output)
        self.assertNotIn(
            "HISTORICAL_TERMINAL_SKIPPED 2026-W37--2026-09-07", output
        )

    def test_invalid_historical_failed_latch_still_blocks(self) -> None:
        current = "2026-W38--2026-09-14"
        self.add_current(current, "edition")
        failed = self.fixture.state / "failed/2026-W37--2026-09-07.json"
        value = json.loads(failed.read_text())
        value["schema"] = "tampered"
        write_json(failed, value)
        result, output, _ = self.run_queue()
        self.assertEqual(result, 1)
        self.assertIn("BLOCKED_INVALID_HISTORICAL_FAILURE", output)

    def test_future_package_identity_does_not_reactivate_history(self) -> None:
        future = "2026-W39--2026-09-21"
        self.add_current(future, "no-change")
        result, output, calls = self.run_queue()
        self.assertEqual(result, 0)
        self.assertIn(f"AIHOT_READY_NO_CHANGE_PROCESSED {future}", output)
        self.assertEqual(len(calls), 1)

    def test_no_change_handoff_race_fails_closed(self) -> None:
        current = "2026-W38--2026-09-14"
        self.add_current(current, "no-change")
        original = process_ready.run

        def mutate(argv: list[str]) -> subprocess.CompletedProcess:
            write(self.fixture.outbox / current / "handoff.json", b"{}\n")
            return subprocess.CompletedProcess(argv, 0, "PASS\n")

        process_ready.run = mutate
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                result = process_ready.main()
        finally:
            process_ready.run = original
        self.assertEqual(result, 1)
        self.assertIn("AIHOT_READY_FAILED", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
