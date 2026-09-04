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
FIXTURES = ROOT / "runtime/aihot/tests/fixtures"
sys.path.insert(0, str(BIN))

import aihot_ready_retry as ready_retry


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


process_ready = load("aihot_process_ready_recovery", BIN / "process-ready.py")

PACKAGE_ID = "2026-W36--2026-09-04--r1"
COMMIT = "f" * 40
FAILURE_OUTPUT = """Traceback (most recent call last):
  File "/root/gneu-aihot-bridge/bin/validate-intake.py", line 151, in <module>
    article_date = date.fromisoformat(value) if isinstance(value, str) else None
                   ^^^^
NameError: name 'date' is not defined
"""


def write_json(path: Path, value: object, *, canonical: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if canonical:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    else:
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(0o600)


class ReadyRetryFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.outbox = self.root / "outbox"
        self.bin = self.root / "bin"
        self.proc = self.root / "proc"
        for directory in (
            self.state / "failed",
            self.state / "processed",
            self.state / "intake",
            self.outbox,
            self.bin,
            self.proc,
        ):
            directory.mkdir(parents=True)
        (self.state / "process-ready.lock").touch(mode=0o600)
        self.package = self.outbox / PACKAGE_ID
        self.package.mkdir()
        candidate = {
            "generated": "2026-08-28T04:08:59+00:00",
            "editions": [{"id": "2026-W36"}],
            "articles": [
                {
                    "id": "inside-week",
                    "edition": "2026-W36",
                    "date": "2026-09-01",
                    "sources": [{}, {}, {}],
                }
            ],
        }
        handoff = {
            "schema": "gneu-aihot-handoff-v2",
            "producer": "adam",
            "edition": "2026-W36",
            "attempt": "2026-09-04",
            "revision": 1,
            "mode": "edition",
            "base_sha256": "a" * 64,
            "base_generated": candidate["generated"],
        }
        (self.package / "candidate.json").write_text(json.dumps(candidate))
        (self.package / "handoff.json").write_text(json.dumps(handoff))
        (self.package / "report.md").write_text("bounded report " * 30)
        (self.package / "READY").write_text("PASS ready\n")
        self.failed = self.state / "failed" / f"{PACKAGE_ID}.json"
        write_json(
            self.failed,
            {
                "schema": "gneu-aihot-ready-failure-v1",
                "edition": "2026-W36",
                "package_id": PACKAGE_ID,
                "attempt": "2026-09-04",
                "revision": 1,
                "failed_at": "2026-09-04T09:03:02+00:00",
                "failed_stage": "validate",
                "stages": [
                    {
                        "stage": "validate",
                        "returncode": 1,
                        "output": FAILURE_OUTPUT,
                    }
                ],
            },
        )
        self.provenance = self.root / "PROVENANCE.json"
        files = {}
        for relative, (filename, mode) in ready_retry.REQUIRED_RUNTIME.items():
            runtime = self.bin / filename
            if filename in {
                "validate-intake.py",
                "aihot_content_contract.py",
                "aihot-content-schema.json",
            }:
                shutil.copy2(BIN / filename, runtime)
            else:
                runtime.write_text(f"# synthetic {filename}\n")
            files[relative] = {
                "destination": str(runtime),
                "mode": mode,
                "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            }
        write_json(
            self.provenance,
            {
                "schema": "gneu-aihot-runtime-provenance-v1",
                "source_commit": COMMIT,
                "manifest_sha256": "e" * 64,
                "installed_at": "2026-09-04T10:00:00+00:00",
                "files": files,
            },
        )
        self.paths = ready_retry.ReadyRetryPaths(
            self.state, self.outbox, self.provenance, self.bin, self.proc
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def hashes(self) -> dict[str, str]:
        return ready_retry.package_hashes(self.paths, PACKAGE_ID)

    def failed_sha(self) -> str:
        return hashlib.sha256(self.failed.read_bytes()).hexdigest()

    def authorize(self):
        return ready_retry.authorize(
            self.paths,
            self.failed_sha(),
            self.hashes(),
            COMMIT,
            ready_retry.REASON,
        )

    def configure_process_ready(self) -> None:
        process_ready.STATE = self.state
        process_ready.OUTBOX = self.outbox
        process_ready.PROCESSED = self.state / "processed"
        process_ready.FAILED = self.state / "failed"
        process_ready.BIN = self.bin
        process_ready.PROVENANCE = self.provenance

    def write_transport(self, payload: dict | None = None) -> str:
        payload = payload or {"version": 1, "edition": "2026-W36", "delta": {}}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        compressed = gzip.compress(raw, mtime=0)
        transport = {
            "edition": "2026-W36",
            "mode": "edition",
            "base_main_sha": "a" * 40,
            "payload_sha256": hashlib.sha256(compressed).hexdigest(),
            "payload_b64": base64.urlsafe_b64encode(compressed).rstrip(b"=").decode(),
        }
        write_json(
            self.state / "intake" / f"{PACKAGE_ID}.transport.json",
            transport,
        )
        return hashlib.sha256(raw).hexdigest()


class ValidateIntakeRegressionTests(unittest.TestCase):
    def test_article_date_path_passes_and_blocks_as_content_not_nameerror(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handoff_root = root / "handoff"
            package = handoff_root / "outbox" / PACKAGE_ID
            package.mkdir(parents=True)
            base = {
                "generated": "2026-08-28T04:08:59+00:00",
                "editions": [{"id": "2026-W35"}],
                "articles": [{"id": "existing"}],
            }
            base_path = root / "base.json"
            base_raw = json.dumps(base, separators=(",", ":")).encode()
            base_path.write_bytes(base_raw)
            article = json.loads((FIXTURES / "valid-article.json").read_text())
            article["id"] = "inside-week"
            candidate = {
                **base,
                "editions": base["editions"] + [{"id": "2026-W36"}],
                "articles": base["articles"] + [article],
            }
            write_json(package / "candidate.json", candidate)
            write_json(
                package / "handoff.json",
                {
                    "schema": "gneu-aihot-handoff-v2",
                    "producer": "adam",
                    "edition": "2026-W36",
                    "attempt": "2026-09-04",
                    "revision": 1,
                    "mode": "edition",
                    "base_sha256": hashlib.sha256(base_raw).hexdigest(),
                    "base_generated": base["generated"],
                },
            )
            (package / "report.md").write_text("validator regression report " * 20)
            (package / "READY").write_text("PASS ready\n")
            local_bin = root / "bin"
            local_bin.mkdir()
            script = local_bin / "validate-intake.py"
            source = (BIN / "validate-intake.py").read_text()
            source = source.replace(
                'HANDOFF_ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff")',
                f"HANDOFF_ROOT = Path({str(handoff_root)!r})",
            ).replace(
                'LIVE_URL = "https://gneu.se/data/aihot.json"',
                f"LIVE_URL = {base_path.as_uri()!r}",
            )
            script.write_text(source)
            shutil.copy2(BIN / "aihot_package_identity.py", local_bin)
            shutil.copy2(BIN / "aihot_content_contract.py", local_bin)
            shutil.copy2(BIN / "aihot-content-schema.json", local_bin)
            valid = subprocess.run(
                [sys.executable, str(script), PACKAGE_ID],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(valid.returncode, 0, valid.stdout)
            self.assertIn("PASS_INTAKE", valid.stdout)
            candidate["articles"][-1]["date"] = "2026-08-27"
            write_json(package / "candidate.json", candidate)
            invalid = subprocess.run(
                [sys.executable, str(script), PACKAGE_ID],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("article inside-week.date is outside 2026-W36", invalid.stdout)
            self.assertNotIn("NameError", invalid.stdout)


class ReadyRetryAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ReadyRetryFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_authorize_consume_verify_is_append_only_and_exactly_once(self) -> None:
        original_failed = self.fixture.failed.read_bytes()
        authorization, auth_sha = self.fixture.authorize()
        self.assertEqual(authorization["package_id"], PACKAGE_ID)
        auth_path = ready_retry.authorization_path(self.fixture.paths, PACKAGE_ID)
        self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)
        auth_before = auth_path.read_bytes()
        with self.assertRaises(ready_retry.ReadyRetryError):
            self.fixture.authorize()
        self.assertEqual(auth_path.read_bytes(), auth_before)
        consumed = ready_retry.consume_for_processing(self.fixture.paths, PACKAGE_ID)
        self.assertIsNotNone(consumed)
        verified, consumed_sha = ready_retry.verify_consumed(
            self.fixture.paths,
            self.fixture.failed_sha(),
            self.fixture.hashes(),
            COMMIT,
        )
        self.assertEqual(verified["authorization_sha256"], auth_sha)
        self.assertEqual(consumed_sha, consumed["consumed_sha256"])
        consumed_path = ready_retry.consumed_path(self.fixture.paths, PACKAGE_ID)
        self.assertEqual(consumed_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(
            ready_retry.ReadyRetryError, "READY_RETRY_ALREADY_CONSUMED"
        ):
            ready_retry.consume_for_processing(self.fixture.paths, PACKAGE_ID)
        self.assertEqual(self.fixture.failed.read_bytes(), original_failed)

    def test_changed_package_after_authorization_blocks_consumption(self) -> None:
        self.fixture.authorize()
        (self.fixture.package / "READY").write_text("changed after authorization\n")
        with self.assertRaises(ready_retry.ReadyRetryError):
            ready_retry.consume_for_processing(self.fixture.paths, PACKAGE_ID)

    def test_runtime_commit_and_installed_hash_must_match_provenance(self) -> None:
        with self.assertRaises(ready_retry.ReadyRetryError):
            ready_retry.authorize(
                self.fixture.paths,
                self.fixture.failed_sha(),
                self.fixture.hashes(),
                "0" * 40,
                ready_retry.REASON,
            )
        (self.fixture.bin / "aihot_local_retry.py").write_text("changed\n")
        with self.assertRaises(ready_retry.ReadyRetryError):
            self.fixture.authorize()

    def test_wrong_failure_hash_stage_and_content_failure_are_blocked(self) -> None:
        with self.assertRaises(ready_retry.ReadyRetryError):
            ready_retry.authorize(
                self.fixture.paths,
                "0" * 64,
                self.fixture.hashes(),
                COMMIT,
                ready_retry.REASON,
            )
        for stage, output in (
            ("build", FAILURE_OUTPUT),
            ("validate", "BLOCKED: article date is outside 2026-W36\n"),
        ):
            self.tearDown()
            self.setUp()
            value = json.loads(self.fixture.failed.read_text())
            value["failed_stage"] = stage
            value["stages"][0]["stage"] = stage
            value["stages"][0]["output"] = output
            write_json(self.fixture.failed, value)
            with self.assertRaises(ready_retry.ReadyRetryError):
                self.fixture.authorize()

    def test_package_provenance_active_process_and_downstream_conflicts_block(self) -> None:
        conflicts = (
            lambda f: (f.package / "READY").write_text("changed\n"),
            lambda f: write_json(
                f.state / "processed" / f"{PACKAGE_ID}.json", {"result": "success"}
            ),
            lambda f: write_json(
                f.state / "intake" / f"{PACKAGE_ID}.transport.json", {"x": 1}
            ),
            lambda f: (
                (f.proc / "123").mkdir(),
                (f.proc / "123" / "cmdline").write_bytes(b"python\x00process-ready.py\x00"),
            ),
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                self.tearDown()
                self.setUp()
                hashes = self.fixture.hashes()
                conflict(self.fixture)
                with self.assertRaises(ready_retry.ReadyRetryError):
                    ready_retry.authorize(
                        self.fixture.paths,
                        self.fixture.failed_sha(),
                        hashes,
                        COMMIT,
                        ready_retry.REASON,
                    )


class ProcessReadyRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ReadyRetryFixture()
        self.fixture.configure_process_ready()
        self.original_run = process_ready.run
        self.original_verify_target = process_ready.verify_target_consumed
        self.original_rejections = process_ready.verified_rejections
        process_ready.verify_target_consumed = lambda *args, **kwargs: ({}, "a" * 64)
        process_ready.verified_rejections = lambda: []

    def tearDown(self) -> None:
        process_ready.run = self.original_run
        process_ready.verify_target_consumed = self.original_verify_target
        process_ready.verified_rejections = self.original_rejections
        self.fixture.close()

    def run_package(self) -> tuple[bool, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            result = process_ready.process_package(PACKAGE_ID)
        return result, output.getvalue()

    def successful_runner(self, calls: list[str]):
        def runner(argv):
            stage = Path(argv[1]).name
            calls.append(stage)
            if stage == "build-intake-payload.py":
                self.fixture.write_transport()
            return subprocess.CompletedProcess(argv, 0, f"PASS {stage}\n")

        return runner

    def test_failed_without_authorization_remains_latched(self) -> None:
        calls: list[str] = []
        process_ready.run = self.successful_runner(calls)
        result, output = self.run_package()
        self.assertFalse(result)
        self.assertIn("FAILED_REQUIRES_OPERATOR", output)
        self.assertEqual(calls, [])

    def test_success_revalidates_builds_replay_checks_then_dispatches_once(self) -> None:
        original_failed = self.fixture.failed.read_bytes()
        self.fixture.authorize()
        calls: list[str] = []
        process_ready.run = self.successful_runner(calls)
        result, output = self.run_package()
        self.assertTrue(result)
        self.assertIn("PROCESS_READY_RECOVERY", output)
        self.assertEqual(
            calls,
            ["validate-intake.py", "build-intake-payload.py", "dispatch-trusted-intake.py"],
        )
        processed_path = self.fixture.state / "processed" / f"{PACKAGE_ID}.json"
        processed = json.loads(processed_path.read_text())
        ready_retry.verify_processed_lineage(
            self.fixture.paths, PACKAGE_ID, processed
        )
        self.assertEqual(self.fixture.failed.read_bytes(), original_failed)
        calls.clear()
        result, output = self.run_package()
        self.assertTrue(result)
        self.assertIn("ALREADY_PROCESSED", output)
        self.assertEqual(calls, [])

    def test_failed_and_processed_without_lineage_is_conflict(self) -> None:
        write_json(
            self.fixture.state / "processed" / f"{PACKAGE_ID}.json",
            {"schema": "gneu-aihot-ready-processed-v1", "result": "success"},
        )
        result, output = self.run_package()
        self.assertFalse(result)
        self.assertIn("BLOCKED_STATE_CONFLICT", output)

    def test_retry_failure_is_separate_and_never_runs_twice(self) -> None:
        original_failed = self.fixture.failed.read_bytes()
        self.fixture.authorize()
        calls: list[str] = []

        def runner(argv):
            stage = Path(argv[1]).name
            calls.append(stage)
            return subprocess.CompletedProcess(argv, 1, "BLOCKED trusted stage\n")

        process_ready.run = runner
        result, output = self.run_package()
        self.assertFalse(result)
        self.assertIn("stage=validate", output)
        retry_failure = ready_retry.retry_failure_path(
            self.fixture.paths, PACKAGE_ID
        )
        self.assertTrue(retry_failure.is_file())
        self.assertEqual(retry_failure.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.fixture.failed.read_bytes(), original_failed)
        calls.clear()
        result, output = self.run_package()
        self.assertFalse(result)
        self.assertIn("READY_RETRY_FAILED_REQUIRES_OPERATOR", output)
        self.assertEqual(calls, [])

    def test_rejected_payload_replay_still_blocks_before_dispatch(self) -> None:
        self.fixture.authorize()
        calls: list[str] = []
        payload = {"version": 1, "edition": "2026-W36", "delta": {"replay": True}}
        payload_raw = json.dumps(payload, separators=(",", ":")).encode()
        payload_sha = hashlib.sha256(payload_raw).hexdigest()

        def runner(argv):
            stage = Path(argv[1]).name
            calls.append(stage)
            if stage == "build-intake-payload.py":
                self.fixture.write_transport(payload)
            return subprocess.CompletedProcess(argv, 0, f"PASS {stage}\n")

        process_ready.run = runner
        process_ready.verified_rejections = lambda: [{"payload_sha256": payload_sha}]
        result, output = self.run_package()
        self.assertFalse(result)
        self.assertIn("BLOCKED_REJECTED_PACKAGE_REPLAY", output)
        self.assertEqual(calls, ["validate-intake.py", "build-intake-payload.py"])
        retry_failure = json.loads(
            ready_retry.retry_failure_path(self.fixture.paths, PACKAGE_ID).read_text()
        )
        self.assertEqual(retry_failure["failed_stage"], "replay-guard")


if __name__ == "__main__":
    unittest.main(verbosity=2)
