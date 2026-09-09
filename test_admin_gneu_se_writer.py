import ast
import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parent / "runtime/admin/gneu-github-app"
loader = importlib.machinery.SourceFileLoader("technical_broker", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
b = importlib.util.module_from_spec(spec)
loader.exec_module(b)
BASE, OLD_TREE, NEW_TREE, COMMIT = [c * 40 for c in "abcd"]
TOKEN = "synthetic-private-token-never-output"
ROOT = "/repos/stebolainen/gneu-se"


def request(workflow=False):
    return {"expected_main_sha": BASE, "branch": "admin/technical-test", "title": "Technical test",
            "message": "Technical test", "files": [{"path": ".github/workflows/test.yml" if workflow else "scripts/test.py", "content": "print(1)\n"}]}


class API:
    def __init__(self, req):
        self.req = req
        self.calls = []
        self.permissions = None
        self.stale = False
        self.exists = False
        self.created = False
        self.bad_permissions = False
        self.bad_scope = False
        self.extra_tree = False
        self.old_mode = None
        self.old_type = "blob"
        self.move_after = None

    def __call__(self, method, path, bearer, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path.endswith("/access_tokens"):
            self.permissions = body["permissions"]
            perms = dict(self.permissions)
            if self.bad_permissions:
                perms.pop("workflows", None)
                perms["actions"] = "write"
            return {"token": TOKEN, "permissions": perms}
        if path == "/installation/token":
            return None
        if path == "/installation/repositories":
            return {"total_count": 1, "repositories": [{"full_name": "stebolainen/other" if self.bad_scope else "stebolainen/gneu-se"}]}
        assert path.startswith(ROOT), path
        suffix = path[len(ROOT):]
        if suffix == "/git/ref/heads/main":
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "f" * 40 if self.stale else BASE}}
        if suffix.startswith("/git/matching-refs/"):
            return [{}] if self.exists or self.created else []
        if suffix.startswith("/pulls?state=all"):
            return []
        if method == "GET" and suffix.startswith("/git/commits/"):
            if suffix.endswith(BASE):
                return {"sha": BASE, "tree": {"sha": OLD_TREE}}
            return {"sha": COMMIT, "tree": {"sha": NEW_TREE}, "parents": [{"sha": BASE}]}
        if suffix == "/git/trees/" + OLD_TREE + "?recursive=1":
            rows = [] if self.old_mode is None else [{"path": self.req["files"][0]["path"], "mode": self.old_mode, "type": self.old_type, "sha": "e" * 40}]
            return {"truncated": False, "tree": rows}
        if suffix == "/git/trees/" + NEW_TREE + "?recursive=1":
            rows = []
            for item in self.req["files"]:
                raw = item["content"].encode()
                sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                rows.append({"path": item["path"], "mode": self.old_mode or "100644", "type": "blob", "sha": sha})
            if self.extra_tree:
                rows.append({"path": "data/aihot.json", "mode": "100644", "type": "blob", "sha": "f" * 40})
            return {"truncated": False, "tree": rows}
        if method == "POST":
            if self.move_after == suffix:
                self.stale = True
            if suffix == "/git/trees": return {"sha": NEW_TREE}
            if suffix == "/git/commits": return {"sha": COMMIT}
            if suffix == "/git/refs":
                self.created = True
                return {"ref": "refs/heads/" + self.req["branch"], "object": {"sha": COMMIT}}
            if suffix == "/pulls": return {"number": 9}
        if suffix.startswith("/git/ref/heads/admin/"):
            return {"object": {"sha": COMMIT}}
        if suffix == "/pulls/9":
            return {"number": 9, "state": "open", "head": {"ref": self.req["branch"], "sha": COMMIT},
                    "base": {"ref": "main", "sha": BASE}, "temp_clone_token": TOKEN}
        raise AssertionError((method, suffix))


class WriterTests(unittest.TestCase):
    def execute(self, req, api=None):
        api = api or API(req)
        with patch.object(b, "installation", return_value={"id": 155274448}), patch.object(b, "make_jwt", return_value="synthetic-jwt"), patch.object(b, "github_request", side_effect=api):
            result = b.create_gneu_se_technical_pr("gneu-admin", req)
        return result, api

    def test_complete_create_only_lifecycle_and_output(self):
        result, api = self.execute(request())
        self.assertEqual(result["commit_sha"], COMMIT)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(api.permissions, {"contents": "write", "pull_requests": "write"})
        writes = [(m, p, body) for m, p, body in api.calls if m == "POST" and p.startswith(ROOT)]
        self.assertEqual([p[len(ROOT):] for _, p, _ in writes], ["/git/trees", "/git/commits", "/git/refs", "/pulls"])
        self.assertEqual(writes[1][2]["parents"], [BASE])
        self.assertEqual(writes[2][2], {"ref": "refs/heads/admin/technical-test", "sha": COMMIT})
        self.assertEqual(writes[3][2]["base"], "main")
        mint = next(x for x in api.calls if x[1].endswith("/access_tokens"))
        self.assertEqual(mint[2]["repositories"], ["gneu-se"])
        self.assertEqual(api.calls[-1][:2], ("DELETE", "/installation/token"))

    def test_workflow_scoping_and_missing_permission(self):
        _, api = self.execute(request(True))
        self.assertEqual(api.permissions, {"contents": "write", "pull_requests": "write", "workflows": "write"})
        api = API(request(True)); api.bad_permissions = True
        with self.assertRaises(b.TechnicalPRError): self.execute(request(True), api)
        self.assertFalse(any(m == "POST" and p.startswith(ROOT) for m, p, _ in api.calls))
        self.assertEqual(api.calls[-1][:2], ("DELETE", "/installation/token"))

    def test_arbitrary_arguments_repo_base_force_permissions_block_before_mint(self):
        for key, value in [("repo", "other/repo"), ("base", "published"), ("force", True), ("delete", True), ("permissions", {"actions": "write"}), ("url", "https://example.org")]:
            req = request(); req[key] = value
            with self.subTest(key=key), patch.object(b, "mint_gneu_se_technical") as mint:
                with self.assertRaises(b.TechnicalPRError): b.create_gneu_se_technical_pr("gneu-admin", req)
                mint.assert_not_called()

    def test_branches_fail_closed(self):
        for branch in ["main", "aihot/x", "adam/x", "forvaltare/x", "release/x", "refs/heads/admin/x", "admin/", "admin/x..y", "admin/x.lock", "admin/x/y", "admin/x%2fy"]:
            req = request(); req["branch"] = branch
            with self.subTest(branch=branch), self.assertRaises(b.TechnicalPRError): b.technical_request(req)

    def test_content_and_path_escapes_block(self):
        for path in ["data/aihot.json", "data/aihot.xml", "aihot/drafts/2026-W36.report.md", "sitemap.xml", "ai-hot.html", "scripts/config.php", "scripts/../data/aihot.json", "/scripts/a.py", "scripts/a.py/../../data/aihot.json", ".git/config", "scripts/secrets/a.json", ".github/workflows/x.yml/evil"]:
            req = request(); req["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(b.TechnicalPRError): b.technical_request(req)

    def test_stale_existing_scope_block_before_repo_write(self):
        for flag in ["stale", "exists", "bad_scope"]:
            req = request(); api = API(req); setattr(api, flag, True)
            with self.subTest(flag=flag), self.assertRaises(Exception): self.execute(req, api)
            self.assertFalse(any(m == "POST" and p.startswith(ROOT) for m, p, _ in api.calls))
            self.assertEqual(api.calls[-1][:2], ("DELETE", "/installation/token"))

    def test_main_move_after_tree_stops_before_commit_ref_pr(self):
        req = request(); api = API(req); api.move_after = "/git/trees"
        with self.assertRaisesRegex(b.TechnicalPRError, "STALE_BASE"): self.execute(req, api)
        self.assertFalse(any(m == "POST" and p.endswith(("/git/commits", "/git/refs", "/pulls")) for m, p, _ in api.calls))

    def test_main_rechecked_after_each_write_and_no_force_delete(self):
        stages = ["/git/trees", "/git/commits", "/git/refs", "/pulls"]
        for stage in stages:
            req = request(); api = API(req); api.move_after = stage
            with self.subTest(stage=stage), self.assertRaisesRegex(b.TechnicalPRError, "STALE_BASE"):
                self.execute(req, api)
            writes = [p[len(ROOT):] for m,p,_ in api.calls if m == "POST" and p.startswith(ROOT)]
            self.assertEqual(writes, stages[:stages.index(stage)+1])
            self.assertFalse(any(m in {"PUT","PATCH","DELETE"} and p.startswith(ROOT) for m,p,_ in api.calls))

    def test_credentials_signed_urls_bounds_and_extra_file_keys_block(self):
        for content in ["ghp_" + "x"*36, "https://example.org/file?X-Amz-Signature=synthetic", "-----BEGIN " + "PRIVATE KEY-----", "x"*200001, "bad\0data"]:
            req=request(); req["files"][0]["content"]=content
            with self.subTest(content_length=len(content)), self.assertRaises(b.TechnicalPRError): b.technical_request(req)
        for key,value in [("mode","120000"),("sha",None),("delete",True)]:
            req=request(); req["files"][0][key]=value
            with self.assertRaises(b.TechnicalPRError): b.technical_request(req)
        req=request(); req["files"] *= 2
        with self.assertRaises(b.TechnicalPRError): b.technical_request(req)

    def test_other_profile_cannot_mint_and_runtime_exception_is_sanitized(self):
        with patch.object(b,"make_jwt") as jwt:
            with self.assertRaises(b.TechnicalPRError): b.create_gneu_se_technical_pr("gneu-forvaltare",request())
            jwt.assert_not_called()
        req=request(); api=API(req)
        def failing(method,path,bearer,body=None):
            if path==ROOT+"/git/trees" and method=="POST": raise RuntimeError(TOKEN)
            return api(method,path,bearer,body)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"request.json";path.write_text(json.dumps(req))
            with patch.object(b,"installation",return_value={"id":155274448}), patch.object(b,"make_jwt",return_value="synthetic-jwt"), patch.object(b,"github_request",side_effect=failing), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(b.technical_pr_cli("gneu-admin",["create","--request",str(path)]),1)
            self.assertNotIn(TOKEN,out.getvalue()+err.getvalue())
            self.assertNotIn("synthetic-jwt",out.getvalue()+err.getvalue())
            self.assertEqual(api.calls[-1][:2],("DELETE","/installation/token"))

    def test_existing_regular_blob_modes_are_preserved(self):
        for mode in ["100644", "100755"]:
            req = request(); api = API(req); api.old_mode = mode
            with self.subTest(mode=mode):
                _, api = self.execute(req, api)
                tree_write = next(body for method, path, body in api.calls if method == "POST" and path == ROOT + "/git/trees")
                self.assertEqual(tree_write["tree"][0]["mode"], mode)

    def test_special_or_unknown_existing_objects_block(self):
        for mode, kind in [("120000", "blob"), ("160000", "commit"), ("040000", "tree"), ("100640", "blob")]:
            req = request(); api = API(req); api.old_mode = mode
            api.old_type = kind
            with self.subTest(mode=mode, kind=kind), self.assertRaises(b.TechnicalPRError): self.execute(req, api)
            self.assertFalse(any(m == "POST" and p.startswith(ROOT) for m, p, _ in api.calls))
        req = request(); api = API(req); api.extra_tree = True
        with self.assertRaises(b.TechnicalPRError): self.execute(req, api)
        self.assertFalse(any(m == "POST" and p.endswith("/git/refs") for m, p, _ in api.calls))

    def test_all_other_operations_block_without_network(self):
        for op in ["api", "push", "merge", "close", "approve", "dispatch", "rerun", "cancel", "settings", "secrets", "variables", "environments", "delete", "release", "tag"]:
            with self.subTest(op=op), patch.object(b, "github_request") as api, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(b.technical_pr_cli("gneu-admin", [op, "--request", "unused"]), 1)
                api.assert_not_called()

    def test_cli_errors_never_echo_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"request.json"; path.write_text(json.dumps(request()))
            with patch.object(b, "create_gneu_se_technical_pr", side_effect=RuntimeError(TOKEN)), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(b.technical_pr_cli("gneu-admin", ["create", "--request", str(path)]), 1)
            self.assertNotIn(TOKEN, out.getvalue()+err.getvalue())
            self.assertEqual(err.getvalue().strip(), "BLOCKED_TECHNICAL_PR")

    def test_local_check_no_network_and_duplicate_json_symlink_block(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"request.json"; path.write_text(json.dumps(request()))
            with patch.object(b, "github_request") as api, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.technical_pr_cli("gneu-admin", ["check", "--request", str(path)]), 0)
                api.assert_not_called()
            link=Path(directory)/"link"; link.symlink_to(path)
            with self.assertRaises(OSError): b.load_technical_request(str(link))
            path.write_text('{"branch":"x","branch":"y"}')
            with self.assertRaises(b.TechnicalPRError): b.load_technical_request(str(path))

    def test_existing_read_and_content_behavior_source_unchanged(self):
        baseline = subprocess.check_output(["git", "show", "e157a499494003ddc4a792d7a01dc5bcc2f35d0a:runtime/admin/gneu-github-app"], text=True)
        old = {n.name: ast.dump(n) for n in ast.parse(baseline).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        new = {n.name: ast.dump(n) for n in ast.parse(SOURCE.read_text()).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        for name, value in old.items():
            if name != "main": self.assertEqual(new[name], value, name)
        self.assertEqual(b.GNEU_SE_TOKEN_PERMISSIONS, {"actions":"read","contents":"read","pull_requests":"read"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
