#!/usr/bin/env python3
"""Exercise real remote_no_write(), mocking only sanitized GitHub responses."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "runtime/aihot/bin"))
import aihot_publication_retry as recovery

FIXTURES = ROOT / "runtime/aihot/tests/fixtures"
SOURCE_PATH = FIXTURES / "gneu-se-executor-4bb9ba39.py.txt"
PROVENANCE_PATH = FIXTURES / "gneu-se-executor-4bb9ba39.provenance.json"


class ExecutorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.raw = SOURCE_PATH.read_bytes()
        self.source = self.raw.decode("utf-8")
        self.provenance = json.loads(PROVENANCE_PATH.read_text())
        self.head = self.provenance["ref"]
        self.calls = []

    def remote_proof(self, source=None, *, overrides=None):
        raw = (self.source if source is None else source).encode("utf-8")
        names = {
            "Validate transported intake": "success",
            "Run trusted AI-hot validators": "success",
            "Create short-lived PR Writer token": "success",
            "Verify writer repository scope": "success",
            "Execute constrained PR write": "failure",
        }
        responses = {
            "workflow-run": {"status": "completed", "conclusion": "failure", "head_sha": self.head},
            "workflow-jobs": {"jobs": [{"steps": [
                {"name": name, "conclusion": status} for name, status in names.items()
            ]}]},
            "pr-view": {"state": "closed", "merged_at": None, "head": {"ref": "aihot/2026-W36"}},
            "branch": None,
            "pr-list": [],
            "contents": {
                "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                "content": base64.b64encode(raw).decode(),
            },
        }
        responses.update(overrides or {})

        def read(args, allow_absent=False):
            self.calls.append((args, allow_absent))
            return responses[args[0]]

        with patch.object(recovery, "remote_read", side_effect=read):
            return recovery.remote_no_write(
                "2026-W36--2026-09-05",
                {"trusted_run_id": 33946469430, "remote_head_sha": self.head}, 21,
            )

    def assert_blocked(self, source):
        with self.assertRaisesRegex(recovery.PublicationRetryError, "boundary not proven"):
            self.remote_proof(source)

    def test_actual_main_shape_regresses_pr80_bug_via_real_remote_proof(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.provenance["source_sha256"])
        self.assertEqual(
            hashlib.sha1(b"blob " + str(len(self.raw)).encode() + b"\0" + self.raw).hexdigest(),
            self.provenance["blob_sha"],
        )
        # PR #80 cannot pass this actual source: there is no def execute.
        self.assertEqual(self.source.find("def execute("), -1)
        result = self.remote_proof()
        self.assertEqual(result["executor_blob_sha"], self.provenance["blob_sha"])
        self.assertEqual(result["executor_source_sha256"], self.provenance["source_sha256"])
        self.assertEqual(result["executor_ast_sha256"], recovery.EXECUTOR_AST_SHA256)
        self.assertEqual(result["remote_head_sha"], self.head)
        self.assertEqual(result["failure_fingerprint"], recovery.COLLISION_FINGERPRINT)
        proof = recovery.prove_executor_boundary(self.source)
        self.assertEqual(proof["function"], "main")
        self.assertEqual(proof["guard_line"], 519)
        self.assertEqual(proof["first_write_line"], 550)
        self.assertIn((["contents", "scripts/aihot_pr_execute.py", "--ref", self.head], False), self.calls)

    def test_entry_function_name_is_not_part_of_proof(self):
        tree = ast.parse(self.source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                node.name = "run_publication"
            if isinstance(node, ast.Name) and node.id == "main":
                node.id = "run_publication"
        self.remote_proof(ast.unparse(tree))

    def test_comments_and_formatting_do_not_define_proof(self):
        self.remote_proof("# def execute(): fake comment\n" + ast.unparse(ast.parse(self.source)))

    def test_missing_guard_and_comment_decoys_block(self):
        original = '    if branch(token, head_ref) is not None:\n        fail("target AI-hot branch already exists")'
        self.assertIn(original, self.source)
        self.assert_blocked(self.source.replace(original, '    # ' + original.replace('\n', '\n    # ')))

    def test_changed_failure_fingerprint_blocks(self):
        self.assert_blocked(self.source.replace(recovery.COLLISION_FINGERPRINT, "a different failure"))

    def test_wrong_branch_arguments_and_comparison_block(self):
        for condition in ['branch(token, base_sha)', 'branch(other_token, head_ref)',
                          'branch(token, "main")']:
            with self.subTest(condition=condition):
                self.assert_blocked(self.source.replace('branch(token, head_ref)', condition, 1))
        self.assert_blocked(self.source.replace('if branch(token, head_ref) is not None:',
                                              'if branch(token, head_ref) is None:', 1))

    def test_repository_writes_before_guard_block(self):
        guard = '    if branch(token, head_ref) is not None:'
        for statement in ['create_blob(token, candidate_raw)',
                          'api("POST", "/repos/stebolainen/gneu-se/git/refs", token, {})',
                          'api("POST", "/repos/stebolainen/gneu-se/pulls", token, {})']:
            with self.subTest(statement=statement):
                self.assert_blocked(self.source.replace(guard, '    ' + statement + '\n' + guard, 1))

    def test_guard_in_unrelated_function_blocks(self):
        tree = ast.parse(self.source)
        entry = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        guard = next(n for n in entry.body if isinstance(n, ast.If) and any(
            isinstance(c, ast.Constant) and c.value == recovery.COLLISION_FINGERPRINT for c in ast.walk(n)))
        entry.body.remove(guard)
        unrelated = ast.parse('def unrelated():\n    pass\n').body[0]
        unrelated.body = [guard]
        tree.body.insert(-1, unrelated)
        self.assert_blocked(ast.unparse(tree))

    def test_ambiguous_duplicate_dead_and_nested_guards_block(self):
        guard = '    if branch(token, head_ref) is not None:\n        fail("target AI-hot branch already exists")'
        self.assert_blocked(self.source.replace(guard, guard + '\n' + guard, 1))
        self.assert_blocked(self.source.replace(guard, '    if False:\n' + '\n'.join('    ' + l for l in guard.splitlines()), 1))
        self.assert_blocked(self.source.replace(guard, '    def hidden():\n' + '\n'.join('    ' + l for l in guard.splitlines()), 1))

    def test_malformed_python_and_missing_entry_launch_block(self):
        self.assert_blocked('def invalid(:\n')
        self.assert_blocked(self.source.replace('    main()\n', '    pass\n'))

    def test_transitive_helper_write_or_nonterminal_failure_blocks(self):
        self.assert_blocked(self.source.replace('    data = branch(\n',
                                              '    create_blob(token, b"hidden write")\n    data = branch(\n', 1))
        self.assert_blocked(self.source.replace('    raise SystemExit("BLOCKED: " + msg)', '    return'))

    def test_target_binding_and_unknown_semantic_drift_block(self):
        self.assert_blocked(self.source.replace('expected_head = f"aihot/{edition}"', 'expected_head = "other"'))
        self.assert_blocked(self.source.replace('    if plan["head_ref"] != expected_head:', '    if False:'))
        self.assert_blocked(self.source.replace('head_ref = plan["head_ref"]', 'head_ref = "other"'))
        self.assert_blocked(self.source.replace('        "POST",\n', '        "PATCH",\n', 1))

    def test_existing_remote_disposition_and_head_checks_remain(self):
        for overrides in [
            {"branch": {"name": "aihot/2026-W36"}},
            {"pr-view": {"state": "open", "merged_at": None, "head": {"ref": "aihot/2026-W36"}}},
            {"pr-view": {"state": "closed", "merged_at": "2026-09-06T00:00:00Z", "head": {"ref": "aihot/2026-W36"}}},
            {"pr-list": [{"head": {"ref": "aihot/2026-W36"}}]},
            {"workflow-run": {"status": "completed", "conclusion": "failure", "head_sha": "0" * 40}},
            {"contents": {"sha": "0" * 40, "content": base64.b64encode(self.raw).decode()}},
        ]:
            with self.subTest(overrides=overrides), self.assertRaises(recovery.PublicationRetryError):
                self.remote_proof(overrides=overrides)


if __name__ == "__main__":
    unittest.main(verbosity=2)
