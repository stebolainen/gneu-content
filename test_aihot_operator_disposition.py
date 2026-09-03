#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "runtime/aihot/bin"
sys.path.insert(0, str(BIN))

import aihot_rejection as rejection

PROCESS_SPEC = importlib.util.spec_from_file_location(
    "aihot_process_ready", BIN / "process-ready.py"
)
assert PROCESS_SPEC is not None and PROCESS_SPEC.loader is not None
process_ready = importlib.util.module_from_spec(PROCESS_SPEC)
PROCESS_SPEC.loader.exec_module(process_ready)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
    path.chmod(0o600)


class SyntheticState:
    edition = "2026-W36"
    failing_article = "outside-article"
    run_id = "33475420413"
    base_main_sha = "a" * 40
    reason = "The immutable article date is outside the declared edition"
    remote_proof = "Operator verified no matching publication side effect or pending PR"

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.outbox = self.root / "outbox"
        for directory in (
            self.state,
            self.state / "failed",
            self.state / "intake",
            self.state / "processed",
            self.outbox,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        self.lock = self.state / "process-ready.lock"
        self.lock.touch(mode=0o600)
        self.package = self.outbox / self.edition
        self.package.mkdir()
        self.package.chmod(0o755)
        self.payload = {
            "version": 1,
            "edition": self.edition,
            "mode": "edition",
            "base_main_sha": self.base_main_sha,
            "base_aihot_sha256": "c" * 64,
            "base_generated": "2026-08-28T04:08:59+00:00",
            "delta": {
                "editions": [{"id": self.edition, "title": "Week 36"}],
                "articles": [
                    {
                        "id": self.failing_article,
                        "edition": self.edition,
                        "date": "2026-08-26",
                        "title": "Outside",
                    },
                    {
                        "id": "valid-article",
                        "edition": self.edition,
                        "date": "2026-09-01",
                        "title": "Inside",
                    },
                ],
            },
            "report": (
                "A deterministic synthetic report used only by isolated tests. " * 4
            ).strip(),
        }
        self._write_bound_state()

    def close(self) -> None:
        self.temporary.cleanup()

    @property
    def failed_path(self) -> Path:
        return self.state / "failed" / f"{self.edition}.json"

    @property
    def transport_path(self) -> Path:
        return self.state / "intake" / f"{self.edition}.transport.json"

    @property
    def receipt_path(self) -> Path:
        return self.state / "rejected" / f"{self.edition}.json"

    def _write_bound_state(self) -> None:
        articles = self.payload["delta"]["articles"]
        candidate = {
            "generated": self.payload["base_generated"],
            "editions": [{"id": "2026-W35"}] + self.payload["delta"]["editions"],
            "articles": [{"id": "existing"}] + articles,
        }
        handoff = {
            "schema": "gneu-aihot-handoff-v1",
            "producer": "adam",
            "edition": self.edition,
            "mode": "edition",
            "base_sha256": "c" * 64,
            "base_generated": self.payload["base_generated"],
            "created_at": "2026-09-01T05:49:13Z",
            "research_window_days": 7,
        }
        (self.package / "READY").write_text(
            f"PASS {self.edition} mode=edition base={handoff['base_sha256']}\n"
        )
        (self.package / "READY").chmod(0o600)
        write_json(self.package / "handoff.json", handoff)
        write_json(self.package / "candidate.json", candidate)
        (self.package / "report.md").write_text(self.payload["report"] + "\n")
        (self.package / "report.md").chmod(0o600)

        payload_raw = json.dumps(
            self.payload, ensure_ascii=False, separators=(",", ":")
        ).encode()
        compressed = gzip.compress(payload_raw, mtime=0)
        compressed_sha = hashlib.sha256(compressed).hexdigest()
        transport = {
            "edition": self.edition,
            "mode": "edition",
            "base_main_sha": self.base_main_sha,
            "payload_sha256": compressed_sha,
            "payload_b64": base64.urlsafe_b64encode(compressed).rstrip(b"=").decode(),
        }
        write_json(self.transport_path, transport)
        failed = {
            "schema": "gneu-aihot-ready-failure-v1",
            "edition": self.edition,
            "failed_at": "2026-09-01T06:00:00+00:00",
            "failed_stage": "dispatch",
            "stages": [
                {
                    "stage": "validate",
                    "returncode": 0,
                    "output": f"PASS_INTAKE {self.edition} mode=edition articles=2\n",
                },
                {
                    "stage": "build",
                    "returncode": 0,
                    "output": (
                        "AIHOT_PAYLOAD_BUILD: PASS\n"
                        f"edition: {self.edition}\n"
                        f"base_main: {self.base_main_sha}\n"
                        f"payload_sha256: {compressed_sha}\n"
                    ),
                },
                {
                    "stage": "dispatch",
                    "returncode": 1,
                    "output": (
                        "INTAKE_DISPATCH: ACCEPTED\n"
                        f"edition: {self.edition}\n"
                        f"expected_main: {self.base_main_sha}\n"
                        f"payload_sha256: {compressed_sha}\n"
                        f"run_id: {self.run_id}\n"
                        "status: completed\n"
                        "conclusion: failure\n"
                        "BLOCKED: intake validation workflow failed\n"
                    ),
                },
            ],
        }
        write_json(self.failed_path, failed)
        self.refresh_args(payload_raw)

    def refresh_args(self, payload_raw: bytes | None = None) -> None:
        if payload_raw is None:
            transport = json.loads(self.transport_path.read_text())
            encoded = transport["payload_b64"]
            compressed = base64.urlsafe_b64decode(
                encoded + "=" * ((4 - len(encoded) % 4) % 4)
            )
            payload_raw = gzip.decompress(compressed)
        self.args = {
            "failing_article": self.failing_article,
            "run_id": self.run_id,
            "failure_sha256": digest(self.failed_path),
            "ready_sha256": digest(self.package / "READY"),
            "handoff_sha256": digest(self.package / "handoff.json"),
            "candidate_sha256": digest(self.package / "candidate.json"),
            "report_sha256": digest(self.package / "report.md"),
            "transport_sha256": digest(self.transport_path),
            "payload_sha256": hashlib.sha256(payload_raw).hexdigest(),
            "base_main_sha": self.base_main_sha,
            "reason": self.reason,
            "remote_proof": self.remote_proof,
        }

    def rebuild(self) -> None:
        self._write_bound_state()

    def reject(self, **changes: str) -> str:
        arguments = dict(self.args)
        arguments.update(changes)
        return rejection.reject(
            self.edition,
            state_root=self.state,
            outbox_root=self.outbox,
            **arguments,
        )

    def verify(self) -> dict:
        return rejection.verify_receipt(
            self.edition, state_root=self.state, outbox_root=self.outbox
        )


class OperatorDispositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SyntheticState()

    def tearDown(self) -> None:
        self.fixture.close()

    def assertBlocked(self, callback) -> None:  # noqa: N802
        with self.assertRaises(rejection.RejectionError):
            callback()

    def test_01_reject_exact_failed_package(self) -> None:
        protected = {
            path: path.read_bytes()
            for path in (
                self.fixture.failed_path,
                self.fixture.transport_path,
                self.fixture.package / "READY",
                self.fixture.package / "handoff.json",
                self.fixture.package / "candidate.json",
                self.fixture.package / "report.md",
            )
        }
        self.assertEqual(self.fixture.reject(), "REJECTED")
        self.assertEqual(self.fixture.verify()["disposition"], "rejected")
        self.assertEqual({path: path.read_bytes() for path in protected}, protected)

    def test_02_reject_twice_is_idempotent(self) -> None:
        self.fixture.reject()
        original = self.fixture.receipt_path.read_bytes()
        self.assertEqual(self.fixture.reject(), "ALREADY_REJECTED")
        self.assertEqual(self.fixture.receipt_path.read_bytes(), original)

    def test_03_wrong_edition_fails_closed(self) -> None:
        self.assertBlocked(
            lambda: rejection.reject(
                "2026-W35",
                state_root=self.fixture.state,
                outbox_root=self.fixture.outbox,
                **self.fixture.args,
            )
        )

    def test_04_wrong_article_fails_closed(self) -> None:
        self.assertBlocked(lambda: self.fixture.reject(failing_article="other"))

    def test_05_wrong_run_id_fails_closed(self) -> None:
        self.assertBlocked(lambda: self.fixture.reject(run_id="999"))

    def test_06_changed_failed_state_fails_closed(self) -> None:
        self.fixture.failed_path.write_text(self.fixture.failed_path.read_text() + " ")
        self.assertBlocked(self.fixture.reject)

    def test_07_changed_ready_fails_closed(self) -> None:
        (self.fixture.package / "READY").write_text("changed\n")
        self.assertBlocked(self.fixture.reject)

    def test_08_changed_handoff_fails_closed(self) -> None:
        (self.fixture.package / "handoff.json").write_text("{}\n")
        self.assertBlocked(self.fixture.reject)

    def test_09_changed_candidate_fails_closed(self) -> None:
        (self.fixture.package / "candidate.json").write_text("{}\n")
        self.assertBlocked(self.fixture.reject)

    def test_10_changed_report_fails_closed(self) -> None:
        (self.fixture.package / "report.md").write_text("changed\n")
        self.assertBlocked(self.fixture.reject)

    def test_11_changed_transport_fails_closed(self) -> None:
        self.fixture.transport_path.write_text("{}\n")
        self.assertBlocked(self.fixture.reject)

    def test_12_changed_decoded_payload_fails_closed(self) -> None:
        old_payload_hash = self.fixture.args["payload_sha256"]
        self.fixture.payload["report"] += " changed"
        self.fixture.rebuild()
        self.fixture.args["payload_sha256"] = old_payload_hash
        self.assertBlocked(self.fixture.reject)

    def test_13_wrong_base_main_fails_closed(self) -> None:
        self.assertBlocked(lambda: self.fixture.reject(base_main_sha="d" * 40))

    def test_14_missing_failed_latch_fails_closed(self) -> None:
        self.fixture.failed_path.unlink()
        self.assertBlocked(self.fixture.reject)

    def test_15_ready_without_failed_latch_cannot_be_rejected(self) -> None:
        self.fixture.failed_path.unlink()
        self.assertTrue((self.fixture.package / "READY").is_file())
        self.assertBlocked(self.fixture.reject)

    def test_16_failure_not_in_allowlist_fails_closed(self) -> None:
        original = rejection.FAILURE_REASON_ALLOWLIST
        rejection.FAILURE_REASON_ALLOWLIST = frozenset()
        try:
            self.assertBlocked(self.fixture.reject)
        finally:
            rejection.FAILURE_REASON_ALLOWLIST = original

    def test_17_matching_article_date_fails_closed(self) -> None:
        self.fixture.payload["delta"]["articles"][0]["date"] = "2026-09-02"
        self.fixture.rebuild()
        self.assertBlocked(self.fixture.reject)

    def test_18_processed_and_rejected_conflict(self) -> None:
        self.fixture.reject()
        write_json(
            self.fixture.state / "processed" / f"{self.fixture.edition}.json",
            {"result": "success"},
        )
        self.assertBlocked(self.fixture.verify)

    def _configure_process(self) -> None:
        process_ready.STATE = self.fixture.state
        process_ready.OUTBOX = self.fixture.outbox
        process_ready.PROCESSED = self.fixture.state / "processed"
        process_ready.FAILED = self.fixture.state / "failed"
        process_ready.BIN = self.fixture.root / "bin"

    def test_19_process_ready_accepts_valid_rejected(self) -> None:
        self.fixture.reject()
        self._configure_process()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(process_ready.process_week(self.fixture.edition))
        self.assertIn("ALREADY_REJECTED", output.getvalue())

    def test_20_manipulated_receipt_fails_closed(self) -> None:
        self.fixture.reject()
        receipt = json.loads(self.fixture.receipt_path.read_text())
        receipt["github_run_id"] += 1
        self.fixture.receipt_path.write_bytes(rejection.canonical_json(receipt))
        self.assertBlocked(self.fixture.verify)

    def test_21_rejected_package_never_dispatches(self) -> None:
        self.fixture.reject()
        self._configure_process()
        calls = []
        original = process_ready.run
        process_ready.run = lambda argv: calls.append(argv)  # type: ignore[assignment]
        try:
            self.assertTrue(process_ready.process_week(self.fixture.edition))
        finally:
            process_ready.run = original
        self.assertEqual(calls, [])

    def test_22_unrelated_later_edition_processes_normally(self) -> None:
        self.fixture.reject()
        later = "2026-W37"
        later_package = self.fixture.outbox / later
        shutil.copytree(self.fixture.package, later_package)
        shutil.copyfile(
            self.fixture.transport_path,
            self.fixture.state / "intake" / f"{later}.transport.json",
        )
        self._configure_process()
        original = process_ready.run
        process_ready.run = lambda argv: subprocess.CompletedProcess(argv, 0, "PASS\n")
        try:
            self.assertTrue(process_ready.process_week(later))
        finally:
            process_ready.run = original
        self.assertTrue((self.fixture.state / "processed" / f"{later}.json").is_file())

    def test_23_same_edition_different_identity_is_isolated(self) -> None:
        self.fixture.reject()
        other = SyntheticState()
        try:
            other.payload["report"] += " distinct"
            other.rebuild()
            (other.state / "rejected").mkdir(mode=0o700)
            shutil.copyfile(self.fixture.receipt_path, other.receipt_path)
            self.assertBlocked(other.verify)
        finally:
            other.close()

    def test_24_symlink_failed_path_fails_closed(self) -> None:
        target = self.fixture.root / "failed-target"
        self.fixture.failed_path.rename(target)
        self.fixture.failed_path.symlink_to(target)
        self.assertBlocked(self.fixture.reject)

    def test_25_symlink_package_path_fails_closed(self) -> None:
        target = self.fixture.root / "package-target"
        self.fixture.package.rename(target)
        self.fixture.package.symlink_to(target, target_is_directory=True)
        self.assertBlocked(self.fixture.reject)

    def test_26_symlink_rejected_path_fails_closed(self) -> None:
        target = self.fixture.root / "rejected-target"
        target.mkdir(mode=0o700)
        (self.fixture.state / "rejected").symlink_to(target, target_is_directory=True)
        self.assertBlocked(self.fixture.reject)

    def test_27_crash_before_commit_has_no_terminal_receipt(self) -> None:
        def crash(stage: str, path: Path) -> None:
            if stage == "before_commit":
                raise RuntimeError("simulated crash")

        with self.assertRaises(RuntimeError):
            rejection.reject(
                self.fixture.edition,
                state_root=self.fixture.state,
                outbox_root=self.fixture.outbox,
                test_hook=crash,
                **self.fixture.args,
            )
        self.assertFalse(self.fixture.receipt_path.exists())

    def test_28_crash_after_commit_leaves_complete_receipt(self) -> None:
        def crash(stage: str, path: Path) -> None:
            if stage == "after_commit":
                raise RuntimeError("simulated crash")

        with self.assertRaises(RuntimeError):
            rejection.reject(
                self.fixture.edition,
                state_root=self.fixture.state,
                outbox_root=self.fixture.outbox,
                test_hook=crash,
                **self.fixture.args,
            )
        self.assertEqual(self.fixture.verify()["disposition"], "rejected")

    def test_29_changed_operator_reason_does_not_overwrite(self) -> None:
        self.fixture.reject()
        original = self.fixture.receipt_path.read_bytes()
        self.assertBlocked(
            lambda: self.fixture.reject(reason="A different operator disposition reason")
        )
        self.assertEqual(self.fixture.receipt_path.read_bytes(), original)

    def test_30_receipt_contains_no_credentials_or_tokens(self) -> None:
        self.fixture.reject()
        raw = self.fixture.receipt_path.read_text()
        for forbidden in ("credentials", "github_pat_", "ghp_", "Bearer ", "PRIVATE KEY"):
            self.assertNotIn(forbidden, raw)

    def test_31_process_ready_blocks_processed_rejected_conflict(self) -> None:
        self.fixture.reject()
        write_json(
            self.fixture.state / "processed" / f"{self.fixture.edition}.json",
            {"result": "success"},
        )
        self._configure_process()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertFalse(process_ready.process_week(self.fixture.edition))
        self.assertIn("BLOCKED_STATE_CONFLICT", output.getvalue())

    def test_32_wrong_failure_stage_fails_closed(self) -> None:
        failed = json.loads(self.fixture.failed_path.read_text())
        failed["failed_stage"] = "receipt"
        write_json(self.fixture.failed_path, failed)
        self.fixture.args["failure_sha256"] = digest(self.fixture.failed_path)
        self.assertBlocked(self.fixture.reject)

    def test_33_path_traversal_edition_fails_closed(self) -> None:
        self.assertBlocked(
            lambda: rejection.reject(
                "../2026-W36",
                state_root=self.fixture.state,
                outbox_root=self.fixture.outbox,
                **self.fixture.args,
            )
        )

    def test_34_operator_tool_has_no_github_or_network_dependency(self) -> None:
        raw = (BIN / "operator-disposition.py").read_text()
        shared = (BIN / "aihot_rejection.py").read_text()
        for forbidden in ("github_auth", "mint_token", "urllib", "requests"):
            self.assertNotIn(forbidden, raw)
            self.assertNotIn(forbidden, shared)


if __name__ == "__main__":
    unittest.main(verbosity=2)
