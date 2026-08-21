#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import os
import unittest
from pathlib import Path
from contextlib import redirect_stderr
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("adapter", ROOT / "hermes_adam_github.py")
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)

REPO = "stebolainen/gneu-content"
URL = "https://github.com/stebolainen/gneu-content.git"
GIT = "/usr/bin/git"
GH = "/usr/bin/gh"
BRANCH = "adam/gen12-cisa-kev"


class PolicyTests(unittest.TestCase):
    def assert_allowed(self, argv: list[str], expected: list[str] | None = None) -> None:
        actual = adapter.build_command(argv)
        normalized = list(argv)
        normalized[0] = GIT if argv[0] == "git" else GH
        self.assertEqual(actual, expected or normalized)

    def assert_blocked(self, argv: list[str]) -> None:
        with self.assertRaises(adapter.PolicyError, msg="unexpected allow: " + repr(argv)):
            adapter.build_command(argv)

    def test_allows_read_only_git_operations_for_locked_repository(self) -> None:
        self.assert_allowed(["git", "fetch", "origin"], [GIT, "fetch", URL])
        self.assert_allowed(["git", "ls-remote", "origin"], [GIT, "ls-remote", URL])
        self.assert_allowed(["git", "ls-remote", "--heads", "origin"], [GIT, "ls-remote", "--heads", URL])

    def test_allows_push_only_to_canonical_adam_generation_branch(self) -> None:
        self.assert_allowed(
            ["git", "push", "--set-upstream", "origin", f"HEAD:refs/heads/{BRANCH}"],
            [GIT, "push", "--set-upstream", URL, f"HEAD:refs/heads/{BRANCH}"],
        )
        self.assert_allowed(
            ["git", "push", "origin", f"HEAD:refs/heads/{BRANCH}"],
            [GIT, "push", URL, f"HEAD:refs/heads/{BRANCH}"],
        )

    def test_blocks_protected_and_non_adam_push_targets(self) -> None:
        for target in ("main", "published", "feature/x", "adam/other", "refs/heads/main"):
            self.assert_blocked(["git", "push", "origin", target])

    def test_blocks_force_broad_tag_mirror_and_deletion_pushes(self) -> None:
        commands = [
            ["git", "push", "--force", "origin", BRANCH],
            ["git", "push", "--force-with-lease", "origin", BRANCH],
            ["git", "push", "--mirror", "origin"],
            ["git", "push", "--all", "origin"],
            ["git", "push", "--tags", "origin"],
            ["git", "push", "origin", ":refs/heads/" + BRANCH],
            ["git", "push", "origin", "+HEAD:refs/heads/" + BRANCH],
            ["git", "push", "origin", BRANCH],
            ["git", "push", "origin", BRANCH, "adam/gen13-extra"],
            ["git", "push", "origin"],
        ]
        for command in commands:
            self.assert_blocked(command)

    def test_blocks_malformed_or_noncanonical_generation_refs(self) -> None:
        refs = (
            "adam/gen0-zero",
            "adam/gen01-leading-zero",
            "adam/gen1-",
            "adam/gen1-UPPER",
            "adam/gen1-two..dots",
            "adam/gen1-two/slash",
            "HEAD:adam/gen1-short-target",
            "HEAD:refs/heads/published",
            "refs/heads/adam/gen1-x:refs/heads/adam/gen1-x",
        )
        for ref in refs:
            self.assert_blocked(["git", "push", "origin", ref])

    def test_allows_pr_create_only_for_exact_repo_base_and_head(self) -> None:
        command = [
            "gh", "pr", "create", "--repo", REPO, "--base", "published",
            "--head", BRANCH, "--title", "New event", "--body", "Source-bound summary",
        ]
        self.assert_allowed(command)

    def test_blocks_pr_create_with_wrong_or_missing_routing(self) -> None:
        valid = [
            "gh", "pr", "create", "--repo", REPO, "--base", "published",
            "--head", BRANCH, "--title", "Title", "--body", "Body",
        ]
        variants = [
            ["main" if value == "published" else value for value in valid],
            ["feature/x" if value == BRANCH else value for value in valid],
            ["other/repo" if value == REPO else value for value in valid],
            valid[:-2],
            [value for index, value in enumerate(valid) if index not in (4, 5)],
            valid + ["--base", "published"],
            valid + ["--web"],
        ]
        for command in variants:
            self.assert_blocked(command)

    def test_allows_required_pr_read_operations(self) -> None:
        self.assert_allowed(["gh", "pr", "list", "--repo", REPO])
        self.assert_allowed([
            "gh", "pr", "list", "--repo", REPO, "--head", BRANCH,
            "--base", "published", "--state", "open", "--limit", "20",
            "--json", "number,url,state,headRefName,headRefOid,baseRefName",
        ])
        self.assert_allowed(["gh", "pr", "view", "42", "--repo", REPO, "--json", "number,url,state,headRefOid"])
        self.assert_allowed(["gh", "pr", "checks", "42", "--repo", REPO])
        self.assert_allowed(["gh", "pr", "status", "--repo", REPO])

    def test_blocks_pr_mutations_api_and_unknown_programs(self) -> None:
        commands = [
            ["gh", "pr", "merge", "42", "--repo", REPO],
            ["gh", "pr", "close", "42", "--repo", REPO],
            ["gh", "pr", "edit", "42", "--repo", REPO],
            ["gh", "api", "repos/" + REPO],
            ["gh", "workflow", "run", "publisher.yml"],
            ["gh", "secret", "list", "--repo", REPO],
            ["bash", "-c", "git push origin main"],
            ["curl", "https://api.github.com"],
            ["git", "status"],
        ]
        for command in commands:
            self.assert_blocked(command)

    def test_blocks_argparse_and_option_smuggling(self) -> None:
        commands = [
            ["git", "-c", "credential.helper=store", "fetch", "origin"],
            ["git", "fetch", "--upload-pack=/tmp/evil", "origin"],
            ["git", "push", "--", "origin", BRANCH],
            ["gh", "--repo", REPO, "pr", "list"],
            ["gh", "pr", "list", "--repo=" + REPO],
            ["gh", "pr", "view", "--repo", REPO, "42"],
            ["gh", "pr", "checks", "not-a-number", "--repo", REPO],
            ["gh", "pr", "list", "--repo", REPO, "--json", "number,evilField"],
        ]
        for command in commands:
            self.assert_blocked(command)


class ExecutionTests(unittest.TestCase):
    def test_cli_fails_closed_without_python_isolated_mode(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(adapter, "_isolated_runtime", return_value=False):
            with redirect_stderr(stderr):
                result = adapter.main(["--", "git", "fetch", "origin"])
        self.assertEqual(result, 70)
        self.assertEqual(stderr.getvalue(), "ADAPTER_ERROR: isolated Python runtime required\n")

    def test_mints_executes_without_shell_or_persistent_auth_and_always_cleans(self) -> None:
        fake_auth = mock.Mock()
        mint_environment: dict[str, str | None] = {}

        def fake_mint_token():
            mint_environment.update({
                "PATH": os.environ.get("PATH"),
                "HTTPS_PROXY": os.environ.get("HTTPS_PROXY"),
                "OPENSSL_CONF": os.environ.get("OPENSSL_CONF"),
                "HERMES_HOME": os.environ.get("HERMES_HOME"),
                "SECRET_OVERRIDE": os.environ.get("GNEU_ADAM_APP_SECRET_DIR"),
            })
            return "never-print-this-token", {"owner_repo": REPO}

        fake_auth._mint_token.side_effect = fake_mint_token
        fake_auth._request.return_value = (204, None)
        fake_auth._cleanup.return_value = (True, "not_present")
        runner = mock.Mock(return_value=mock.Mock(returncode=7))
        preflight = mock.Mock(return_value=mock.Mock(returncode=0, stdout="core.filemode\nremote.origin.url\n"))

        with mock.patch.dict(os.environ, {
            "GH_TOKEN": "wrong-token",
            "GITHUB_TOKEN": "wrong-token",
            "GIT_ASKPASS": "/tmp/unsafe",
            "GIT_EXEC_PATH": "/tmp/unsafe-git-exec",
            "GIT_SSL_NO_VERIFY": "1",
            "GH_HOST": "attacker.invalid",
            "HTTPS_PROXY": "https://attacker.invalid",
            "OPENSSL_CONF": "/tmp/unsafe-openssl.cnf",
            "PATH": "/tmp/unsafe-bin",
            "GH_PAGER": "/tmp/exfil",
            "GH_DEBUG": "api",
            "HERMES_HOME": "/tmp/other-profile",
            "GNEU_ADAM_APP_SECRET_DIR": "/tmp/other-app",
        }, clear=False):
            result = adapter.execute(
                ["git", "fetch", "origin"], fake_auth, runner,
                preflight_runner=preflight,
            )

        self.assertEqual(result, 7)
        fake_auth._mint_token.assert_called_once_with()
        fake_auth._request.assert_called_once_with("DELETE", "/installation/token", "never-print-this-token")
        self.assertEqual(mint_environment, {
            "PATH": "/usr/bin:/bin",
            "HTTPS_PROXY": None,
            "OPENSSL_CONF": None,
            "HERMES_HOME": None,
            "SECRET_OVERRIDE": None,
        })
        self.assertEqual(fake_auth._cleanup.call_count, 2)
        args, kwargs = runner.call_args
        self.assertEqual(args[0], [GIT, "fetch", URL])
        self.assertFalse(kwargs.get("shell", False))
        env = kwargs["env"]
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("GH_TOKEN", env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_ASKPASS"], "/bin/false")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GH_HOST"], "github.com")
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertEqual(env["GH_PAGER"], "/bin/cat")
        for unsafe in ("GIT_EXEC_PATH", "GIT_SSL_NO_VERIFY", "HTTPS_PROXY", "GH_DEBUG"):
            self.assertNotIn(unsafe, env)
        config_values = [env[key] for key in env if key.startswith("GIT_CONFIG_VALUE_")]
        self.assertFalse(any("wrong-token" in value for value in config_values))
        self.assertFalse(any("never-print-this-token" in value for value in config_values))
        self.assertTrue(any(value.startswith("AUTHORIZATION: basic ") for value in config_values))
        self.assertTrue(any("core.hooksPath" == env[key] for key in env if key.startswith("GIT_CONFIG_KEY_")))

    def test_dangerous_local_git_config_is_denied_before_mint(self) -> None:
        for key in ("push.followtags", "url.https://attacker.invalid/.insteadof"):
            with self.subTest(key=key):
                fake_auth = mock.Mock()
                runner = mock.Mock()
                preflight = mock.Mock(return_value=mock.Mock(
                    returncode=0,
                    stdout=key + "\n",
                ))

                with self.assertRaises(adapter.PolicyError):
                    adapter.execute(
                        ["git", "fetch", "origin"], fake_auth, runner,
                        preflight_runner=preflight,
                    )

                fake_auth._mint_token.assert_not_called()
                runner.assert_not_called()

    def test_gh_receives_only_ephemeral_token_and_cleanup_runs_on_runner_error(self) -> None:
        fake_auth = mock.Mock()
        fake_auth._mint_token.return_value = ("ephemeral", {"owner_repo": REPO})
        fake_auth._request.return_value = (204, None)
        fake_auth._cleanup.return_value = (True, "not_present")
        runner = mock.Mock(side_effect=OSError("exec failed"))
        command = ["gh", "pr", "status", "--repo", REPO]

        with self.assertRaises(adapter.AdapterError):
            adapter.execute(command, fake_auth, runner)

        self.assertEqual(fake_auth._cleanup.call_count, 2)
        fake_auth._request.assert_called_once_with("DELETE", "/installation/token", "ephemeral")
        env = runner.call_args.kwargs["env"]
        self.assertEqual(env["GH_TOKEN"], "ephemeral")
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_auth_failure_executes_nothing_and_attempts_cleanup(self) -> None:
        fake_auth = mock.Mock()
        fake_auth._mint_token.side_effect = RuntimeError("missing credentials")
        runner = mock.Mock()

        with self.assertRaises(adapter.AuthRequired):
            adapter.execute(["git", "ls-remote", "origin"], fake_auth, runner)

        runner.assert_not_called()
        self.assertEqual(fake_auth._cleanup.call_count, 2)

    def test_policy_denial_happens_before_auth_mint(self) -> None:
        fake_auth = mock.Mock()
        runner = mock.Mock()
        with self.assertRaises(adapter.PolicyError):
            adapter.execute(["gh", "pr", "merge", "42", "--repo", REPO], fake_auth, runner)
        fake_auth._mint_token.assert_not_called()
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
