#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "runtime/aihot/bin"
sys.path.insert(0, str(BIN))

import aihot_publication_retry as publication_retry


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


process_ready = load("publication_retry_process_ready", BIN / "process-ready.py")
PACKAGE = "2026-W36--2026-09-05"
COMMIT = "f" * 40


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


class Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.outbox = self.root / "outbox"
        self.bin = self.root / "bin"
        self.package = self.outbox / PACKAGE
        self.package.mkdir(parents=True)
        self.bin.mkdir()
        for name, raw in {
            "candidate.json": b'{"generated":"x","editions":[],"articles":[]}\n',
            "handoff.json": b'{"edition":"2026-W36"}\n',
            "report.md": b"trusted report\n",
            "READY": b"PASS\n",
        }.items():
            (self.package / name).write_bytes(raw)
        payload = {"version": 1, "edition": "2026-W36", "delta": {}}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        compressed = gzip.compress(raw, mtime=0)
        transport = {
            "edition": "2026-W36", "mode": "edition", "base_main_sha": "a" * 40,
            "payload_sha256": hashlib.sha256(compressed).hexdigest(),
            "payload_b64": base64.urlsafe_b64encode(compressed).rstrip(b"=").decode(),
        }
        write_json(self.state / "intake" / f"{PACKAGE}.transport.json", transport)
        dispatch_output = "\n".join([
            "INTAKE_DISPATCH: ACCEPTED", "edition: 2026-W36", "package_id: " + PACKAGE,
            "expected_main: " + "b" * 40, "run_id: 33946469430",
            "status: completed", "conclusion: failure",
        ])
        write_json(self.state / "failed" / f"{PACKAGE}.json", {
            "schema": "gneu-aihot-ready-failure-v1", "edition": "2026-W36",
            "package_id": PACKAGE, "attempt": "2026-09-05", "failed_stage": "dispatch",
            "stages": [
                {"stage": "validate", "returncode": 0, "output": "PASS"},
                {"stage": "build", "returncode": 0, "output": "PASS"},
                {"stage": "dispatch", "returncode": 1, "output": dispatch_output},
            ],
        })
        files = {}
        required = {
            "runtime/aihot/bin/process-ready.py": "process-ready.py",
            "runtime/aihot/bin/build-intake-payload.py": "build-intake-payload.py",
            "runtime/aihot/bin/dispatch-trusted-intake.py": "dispatch-trusted-intake.py",
            "runtime/aihot/bin/aihot_publication_retry.py": "aihot_publication_retry.py",
            "runtime/aihot/bin/authorize-publication-retry.py": "authorize-publication-retry.py",
        }
        for relative, name in required.items():
            shutil.copy2(BIN / name, self.bin / name)
            files[relative] = {
                "destination": str(self.bin / name), "mode": "0700",
                "sha256": hashlib.sha256((self.bin / name).read_bytes()).hexdigest(),
            }
        self.provenance = self.root / "PROVENANCE.json"
        write_json(self.provenance, {"source_commit": COMMIT, "files": files})
        self.paths = publication_retry.PublicationRetryPaths(
            self.state, self.outbox, self.provenance, self.bin
        )

    def close(self) -> None:
        self.temp.cleanup()

    def authorize(self):
        original = publication_retry.remote_no_write
        publication_retry.remote_no_write = lambda *args: {
            "trusted_run_id": 33946469430, "remote_head_sha": "b" * 40,
            "conflicting_pr": 21, "conflicting_ref": "aihot/2026-W36",
            "failure_fingerprint": "target AI-hot branch already exists",
            "executor_blob_sha": "c" * 40,
            "write_boundary": "branch_guard_before_first_blob_write",
        }
        try:
            return publication_retry.authorize(
                self.paths, PACKAGE, COMMIT, publication_retry.REASON, 21,
                "2026-09-06T10:00:00+00:00",
            )
        finally:
            publication_retry.remote_no_write = original


class PublicationRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = Fixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_authorization_is_append_only_and_consumes_once(self) -> None:
        original_failed = (self.fx.state / "failed" / f"{PACKAGE}.json").read_bytes()
        original_transport = (self.fx.state / "intake" / f"{PACKAGE}.transport.json").read_bytes()
        _, auth_sha = self.fx.authorize()
        self.assertEqual(len(auth_sha), 64)
        with self.assertRaises(publication_retry.PublicationRetryError):
            self.fx.authorize()
        consumed = publication_retry.consume_for_processing(self.fx.paths, PACKAGE)
        self.assertEqual(consumed["recovery_type"], "publication")
        with self.assertRaisesRegex(publication_retry.PublicationRetryError, "ALREADY_CONSUMED"):
            publication_retry.consume_for_processing(self.fx.paths, PACKAGE)
        self.assertEqual((self.fx.state / "failed" / f"{PACKAGE}.json").read_bytes(), original_failed)
        self.assertEqual((self.fx.state / "intake" / f"{PACKAGE}.transport.json").read_bytes(), original_transport)

    def test_changed_evidence_and_remote_write_boundary_block(self) -> None:
        self.fx.authorize()
        (self.fx.package / "READY").write_text("changed\n")
        with self.assertRaises(publication_retry.PublicationRetryError):
            publication_retry.verify_authorization(self.fx.paths, PACKAGE, COMMIT)
        steps = {
            "Validate transported intake": "success",
            "Run trusted AI-hot validators": "success",
            "Create short-lived PR Writer token": "success",
            "Verify writer repository scope": "success",
            "Execute constrained PR write": "success",
        }
        original = publication_retry.remote_read
        publication_retry.remote_read = lambda args, allow_absent=False: (
            {"status": "completed", "conclusion": "failure", "head_sha": "b" * 40}
            if args[0] == "workflow-run" else
            {"jobs": [{"steps": [{"name": k, "conclusion": v} for k, v in steps.items()]}]}
        )
        try:
            with self.assertRaises(publication_retry.PublicationRetryError):
                publication_retry.remote_no_write(PACKAGE, {"trusted_run_id": 1, "remote_head_sha": "b" * 40}, 21)
        finally:
            publication_retry.remote_read = original

    def test_process_ready_revalidates_verifies_build_then_dispatches(self) -> None:
        self.fx.authorize()
        process_ready.STATE = self.fx.state
        process_ready.OUTBOX = self.fx.outbox
        process_ready.PROCESSED = self.fx.state / "processed"
        process_ready.FAILED = self.fx.state / "failed"
        process_ready.BIN = self.fx.bin
        process_ready.PROVENANCE = self.fx.provenance
        process_ready.publication_retry_paths = lambda: self.fx.paths
        process_ready.verified_rejections = lambda: []
        calls = []
        original_run = process_ready.run
        def runner(argv):
            calls.append([Path(argv[1]).name, *argv[2:]])
            return subprocess.CompletedProcess(argv, 0, "PASS\n")
        process_ready.run = runner
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                result = process_ready.process_package(PACKAGE)
            self.assertTrue(result, output.getvalue())
            self.assertEqual(calls, [
                ["validate-intake.py", PACKAGE],
                ["build-intake-payload.py", "--verify-existing", PACKAGE],
                ["dispatch-trusted-intake.py", PACKAGE],
            ])
            processed = json.loads((self.fx.state / "processed" / f"{PACKAGE}.json").read_text())
            publication_retry.verify_processed_lineage(self.fx.paths, PACKAGE, processed)
        finally:
            process_ready.run = original_run

    def test_failed_package_without_authorization_remains_latched(self) -> None:
        process_ready.STATE = self.fx.state
        process_ready.OUTBOX = self.fx.outbox
        process_ready.PROCESSED = self.fx.state / "processed"
        process_ready.FAILED = self.fx.state / "failed"
        process_ready.BIN = self.fx.bin
        process_ready.PROVENANCE = self.fx.provenance
        process_ready.publication_retry_paths = lambda: self.fx.paths
        calls = []
        original_run = process_ready.run
        process_ready.run = lambda argv: calls.append(argv)
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                result = process_ready.process_package(PACKAGE)
            self.assertFalse(result)
            self.assertIn("FAILED_REQUIRES_OPERATOR", output.getvalue())
            self.assertEqual(calls, [])
        finally:
            process_ready.run = original_run

    def test_rejected_payload_replay_blocks_before_dispatch(self) -> None:
        self.fx.authorize()
        process_ready.STATE = self.fx.state
        process_ready.OUTBOX = self.fx.outbox
        process_ready.PROCESSED = self.fx.state / "processed"
        process_ready.FAILED = self.fx.state / "failed"
        process_ready.BIN = self.fx.bin
        process_ready.PROVENANCE = self.fx.provenance
        process_ready.publication_retry_paths = lambda: self.fx.paths
        canonical = publication_retry.package_evidence(self.fx.paths, PACKAGE)[
            "canonical_payload_sha256"
        ]
        process_ready.verified_rejections = lambda: [{"payload_sha256": canonical}]
        calls = []
        original_run = process_ready.run
        def runner(argv):
            calls.append(Path(argv[1]).name)
            return subprocess.CompletedProcess(argv, 0, "PASS\n")
        process_ready.run = runner
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                result = process_ready.process_package(PACKAGE)
            self.assertFalse(result)
            self.assertIn("BLOCKED_REJECTED_PACKAGE_REPLAY", output.getvalue())
            self.assertEqual(calls, ["validate-intake.py", "build-intake-payload.py"])
            self.assertTrue(publication_retry.retry_failure_path(self.fx.paths, PACKAGE).is_file())
        finally:
            process_ready.run = original_run


if __name__ == "__main__":
    unittest.main(verbosity=2)
