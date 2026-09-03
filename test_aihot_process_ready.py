#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from test_aihot_operator_disposition import SyntheticState, process_ready, write_json


class ProcessReadyRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticState()
        process_ready.STATE = self.fixture.state
        process_ready.OUTBOX = self.fixture.outbox
        process_ready.PROCESSED = self.fixture.state / "processed"
        process_ready.FAILED = self.fixture.state / "failed"
        process_ready.BIN = self.fixture.root / "bin"

    def tearDown(self) -> None:
        self.fixture.close()

    def run_week(self) -> tuple[bool, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            result = process_ready.process_week(self.fixture.edition)
        return result, output.getvalue()

    def test_failed_without_rejection_keeps_existing_latch_behavior(self) -> None:
        result, output = self.run_week()
        self.assertFalse(result)
        self.assertIn("FAILED_REQUIRES_OPERATOR 2026-W36", output)

    def test_valid_rejection_is_terminal_without_subprocess(self) -> None:
        self.fixture.reject()
        calls = []
        original = process_ready.run
        process_ready.run = lambda argv: calls.append(argv)  # type: ignore[assignment]
        try:
            result, output = self.run_week()
        finally:
            process_ready.run = original
        self.assertTrue(result)
        self.assertIn("ALREADY_REJECTED 2026-W36", output)
        self.assertEqual(calls, [])

    def test_processed_and_rejected_conflict_fails_closed(self) -> None:
        self.fixture.reject()
        write_json(
            self.fixture.state / "processed" / f"{self.fixture.edition}.json",
            {"schema": "synthetic", "result": "success"},
        )
        result, output = self.run_week()
        self.assertFalse(result)
        self.assertIn("BLOCKED_STATE_CONFLICT 2026-W36", output)

    def test_tampered_rejection_fails_closed(self) -> None:
        self.fixture.reject()
        receipt = json.loads(self.fixture.receipt_path.read_text())
        receipt["payload_sha256"] = "0" * 64
        self.fixture.receipt_path.write_bytes(
            __import__("aihot_rejection").canonical_json(receipt)
        )
        result, output = self.run_week()
        self.assertFalse(result)
        self.assertIn("BLOCKED_INVALID_REJECTION 2026-W36", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
