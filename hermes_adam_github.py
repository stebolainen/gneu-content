#!/usr/bin/python3 -I
"""Policy-enforced ephemeral GitHub adapter for the GNEU Adam identity.

The adapter accepts only a small Git/gh allowlist for stebolainen/gneu-content.
It mints through the sibling hermes_adam_auth.py implementation, supplies the
credential only in the child process environment, and always attempts cleanup.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterator, Sequence

OWNER_REPO = "stebolainen/gneu-content"
REPOSITORY_URL = "https://github.com/stebolainen/gneu-content.git"
GIT_EXECUTABLE = "/usr/bin/git"
GH_EXECUTABLE = "/usr/bin/gh"
BRANCH_RE = re.compile(r"adam/gen[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
JSON_FIELDS = frozenset({
    "baseRefName",
    "headRefName",
    "headRefOid",
    "isDraft",
    "number",
    "state",
    "statusCheckRollup",
    "url",
})


class AdapterError(RuntimeError):
    """Base class for safe, non-secret adapter failures."""


class PolicyError(AdapterError):
    """The requested operation is outside Adam's allowlist."""


class AuthRequired(AdapterError):
    """Ephemeral Adam authentication could not be prepared."""


def _valid_branch(value: str) -> bool:
    return bool(BRANCH_RE.fullmatch(value))


def _validate_json_fields(value: str) -> None:
    fields = value.split(",")
    if not fields or any(not field or field not in JSON_FIELDS for field in fields):
        raise PolicyError("unsupported --json field")
    if len(fields) != len(set(fields)):
        raise PolicyError("duplicate --json field")


def _parse_flags(tokens: Sequence[str], allowed: frozenset[str]) -> dict[str, str]:
    if len(tokens) % 2:
        raise PolicyError("every option must have one explicit value")
    parsed: dict[str, str] = {}
    for index in range(0, len(tokens), 2):
        option, value = tokens[index], tokens[index + 1]
        if option not in allowed or option in parsed:
            raise PolicyError("unsupported or duplicate option")
        if not value or "\x00" in value:
            raise PolicyError("empty or malformed option value")
        parsed[option] = value
    return parsed


def _validate_repo(options: dict[str, str]) -> None:
    if options.get("--repo") != OWNER_REPO:
        raise PolicyError("--repo must name the locked repository")


def _build_git(argv: Sequence[str]) -> list[str]:
    if list(argv) == ["git", "fetch", "origin"]:
        return [GIT_EXECUTABLE, "fetch", REPOSITORY_URL]
    if list(argv) == ["git", "ls-remote", "origin"]:
        return [GIT_EXECUTABLE, "ls-remote", REPOSITORY_URL]
    if list(argv) == ["git", "ls-remote", "--heads", "origin"]:
        return [GIT_EXECUTABLE, "ls-remote", "--heads", REPOSITORY_URL]

    if len(argv) not in (4, 5) or argv[:2] != ["git", "push"]:
        raise PolicyError("Git operation is not allowlisted")

    offset = 2
    option: str | None = None
    if len(argv) == 5:
        option = argv[offset]
        if option not in ("-u", "--set-upstream"):
            raise PolicyError("push option is not allowlisted")
        offset += 1
    if argv[offset] != "origin":
        raise PolicyError("push remote must be origin")

    refspec = argv[offset + 1]
    explicit = refspec.startswith("HEAD:refs/heads/") and _valid_branch(refspec.removeprefix("HEAD:refs/heads/"))
    if not explicit:
        raise PolicyError("push refspec must target one canonical Adam generation branch")

    result = [GIT_EXECUTABLE, "push"]
    if option is not None:
        result.append(option)
    result.extend((REPOSITORY_URL, refspec))
    return result


def _build_pr_create(argv: Sequence[str]) -> list[str]:
    options = _parse_flags(
        argv[3:],
        frozenset({"--repo", "--base", "--head", "--title", "--body"}),
    )
    _validate_repo(options)
    if options.get("--base") != "published":
        raise PolicyError("PR base must be published")
    if not _valid_branch(options.get("--head", "")):
        raise PolicyError("PR head must be a canonical Adam generation branch")
    if not options.get("--title", "").strip() or not options.get("--body", "").strip():
        raise PolicyError("PR title and body are required")
    return list(argv)


def _build_pr_list(argv: Sequence[str]) -> list[str]:
    options = _parse_flags(
        argv[3:],
        frozenset({"--repo", "--head", "--base", "--state", "--limit", "--json"}),
    )
    _validate_repo(options)
    if "--head" in options and not _valid_branch(options["--head"]):
        raise PolicyError("PR head filter is malformed")
    if "--base" in options and options["--base"] != "published":
        raise PolicyError("PR base filter must be published")
    if "--state" in options and options["--state"] not in {"open", "closed", "merged", "all"}:
        raise PolicyError("unsupported PR state")
    if "--limit" in options:
        value = options["--limit"]
        if not value.isdigit() or str(int(value)) != value or not 1 <= int(value) <= 100:
            raise PolicyError("PR list limit must be a canonical integer from 1 to 100")
    if "--json" in options:
        _validate_json_fields(options["--json"])
    return list(argv)


def _build_pr_number_read(argv: Sequence[str], action: str) -> list[str]:
    if len(argv) < 6 or argv[2] != action:
        raise PolicyError("malformed PR read operation")
    number = argv[3]
    if not number.isdigit() or str(int(number)) != number or int(number) < 1:
        raise PolicyError("PR number must be a positive canonical integer")
    allowed = frozenset({"--repo", "--json"}) if action == "view" else frozenset({"--repo"})
    options = _parse_flags(argv[4:], allowed)
    _validate_repo(options)
    if "--json" in options:
        _validate_json_fields(options["--json"])
    return list(argv)


def _build_gh(argv: Sequence[str]) -> list[str]:
    if len(argv) < 4 or argv[:2] != ["gh", "pr"]:
        raise PolicyError("GitHub CLI operation is not allowlisted")
    action = argv[2]
    if action == "create":
        result = _build_pr_create(argv)
    elif action == "list":
        result = _build_pr_list(argv)
    elif action in {"view", "checks"}:
        result = _build_pr_number_read(argv, action)
    elif action == "status":
        options = _parse_flags(argv[3:], frozenset({"--repo"}))
        _validate_repo(options)
        result = list(argv)
    else:
        raise PolicyError("GitHub CLI operation is not allowlisted")
    result[0] = GH_EXECUTABLE
    return result


def build_command(argv: Sequence[str]) -> list[str]:
    """Validate an Adam operation and return its locked executable argv."""
    if not argv or any(not isinstance(value, str) or "\x00" in value for value in argv):
        raise PolicyError("missing or malformed command")
    if argv[0] == "git":
        return _build_git(argv)
    if argv[0] == "gh":
        return _build_gh(argv)
    raise PolicyError("program is not allowlisted")


def _load_auth_module() -> ModuleType:
    here = Path(__file__).resolve().parent
    for name in ("gneu-content-adam-auth.py", "hermes_adam_auth.py"):
        path = here / name
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("gneu_content_adam_auth", path)
        if spec is None or spec.loader is None:
            break
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if getattr(module, "OWNER", None) != "stebolainen" or getattr(module, "REPO", None) != "gneu-content":
            raise AuthRequired("auth helper repository scope mismatch")
        return module
    raise AuthRequired("trusted sibling auth helper is missing")


def _clean_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(("GIT_", "GH_", "GITHUB_")) or key in {
            "ALL_PROXY", "BROWSER", "CURL_CA_BUNDLE", "EDITOR", "HTTP_PROXY",
            "HTTPS_PROXY", "LD_LIBRARY_PATH", "LD_PRELOAD", "LESS", "LV",
            "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES", "PAGER",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE", "SSLKEYLOGFILE",
            "SSH_ASKPASS", "VISUAL", "all_proxy", "http_proxy", "https_proxy",
        }:
            env.pop(key, None)
    env.update({
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GH_HOST": "github.com",
        "GH_PAGER": "/bin/cat",
        "GH_PROMPT_DISABLED": "1",
        "PAGER": "/bin/cat",
        "PATH": "/usr/bin:/bin",
    })
    return env


@contextmanager
def _sanitized_auth_environment(hermes_home: Path | None = None) -> Iterator[None]:
    """Protect auth-helper network and openssl subprocesses from env injection."""
    unsafe = {
        "ALL_PROXY", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "GIT_SSL_NO_VERIFY",
        "HTTP_PROXY", "HTTPS_PROXY", "LD_LIBRARY_PATH", "LD_PRELOAD",
        "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES",
        "REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE", "SSLKEYLOGFILE",
        "all_proxy", "http_proxy", "https_proxy",
    }
    controlled = unsafe | {
        "GNEU_ADAM_APP_SECRET_DIR", "GNEU_GITHUB_TOKEN_FILE", "HERMES_HOME", "PATH",
    }
    saved = {key: os.environ[key] for key in controlled if key in os.environ}
    for key in controlled:
        os.environ.pop(key, None)
    os.environ["PATH"] = "/usr/bin:/bin"
    if hermes_home is not None:
        os.environ["HERMES_HOME"] = str(hermes_home)
    try:
        yield
    finally:
        for key in controlled:
            os.environ.pop(key, None)
        os.environ.update(saved)


def _runtime_auth_home() -> Path:
    script = Path(__file__).resolve()
    if script.name != "gneu-content-adam-github.py" or script.parent.name != "scripts":
        raise AuthRequired("adapter must run from its versioned profile installation path")
    return script.parent.parent


def _git_environment(token: str) -> dict[str, str]:
    env = _clean_environment()
    encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    settings = (
        ("credential.helper", ""),
        ("credential.interactive", "never"),
        ("core.hooksPath", "/dev/null"),
        ("http.proxy", ""),
        ("http.sslVerify", "true"),
        ("http.https://github.com/.extraheader", ""),
        ("http.https://github.com/.extraheader", f"AUTHORIZATION: basic {encoded}"),
    )
    env["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (key, value) in enumerate(settings):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


def _verify_local_git_config(runner: Callable[..., object]) -> None:
    """Reject local config capable of redirecting or intercepting Git auth."""
    try:
        completed = runner(
            [GIT_EXECUTABLE, "config", "--local", "--name-only", "--list"],
            env=_clean_environment(),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        raise PolicyError("local Git config could not be verified") from exc
    if getattr(completed, "returncode", 1) != 0:
        raise PolicyError("local Git config could not be verified")

    stdout = getattr(completed, "stdout", "")
    if not isinstance(stdout, str):
        raise PolicyError("local Git config inspection was malformed")
    for raw_key in stdout.splitlines():
        key = raw_key.strip().lower()
        dangerous = (
            key.startswith(("url.", "http.", "credential.", "include.", "includeif.", "push."))
            or key in {"core.hookspath", "core.gitproxy", "core.sshcommand"}
            or bool(re.fullmatch(
                r"remote\..+\.(proxy|proxyauthmethod|push|pushurl|uploadpack|receivepack)",
                key,
            ))
        )
        if dangerous:
            raise PolicyError("local Git config contains a forbidden transport setting")


def execute(
    argv: Sequence[str],
    auth_module: ModuleType | None = None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    *,
    preflight_runner: Callable[..., object] = subprocess.run,
) -> int:
    """Run one validated operation with a freshly minted, always-cleaned token."""
    command = build_command(argv)
    if command[0] == GIT_EXECUTABLE:
        _verify_local_git_config(preflight_runner)
    auth_home = None if auth_module is not None else _runtime_auth_home()
    auth = auth_module or _load_auth_module()
    token: str | None = None
    try:
        try:
            with _sanitized_auth_environment(auth_home):
                auth._cleanup()
                token, meta = auth._mint_token()
            if not isinstance(meta, dict) or meta.get("owner_repo") != OWNER_REPO:
                raise AuthRequired("minted credential repository scope mismatch")
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 4096
                or any(character.isspace() for character in token)
            ):
                raise AuthRequired("minted credential is malformed")
        except AuthRequired:
            raise
        except Exception as exc:
            raise AuthRequired("ephemeral Adam authentication is unavailable") from exc

        env = _git_environment(token) if command[0] == GIT_EXECUTABLE else _clean_environment()
        if command[0] == GH_EXECUTABLE:
            env["GH_TOKEN"] = token
        try:
            with tempfile.TemporaryDirectory(prefix="gneu-adam-gh-") as gh_config:
                env["GH_CONFIG_DIR"] = gh_config
                completed = runner(command, env=env, shell=False, check=False)
        except Exception as exc:
            raise AdapterError("allowed command could not be executed") from exc
        return int(completed.returncode)
    finally:
        cleanup_failed = False
        try:
            with _sanitized_auth_environment(auth_home):
                if token is not None:
                    try:
                        status, _ = auth._request("DELETE", "/installation/token", token)
                        cleanup_failed = status != 204
                    except Exception:
                        cleanup_failed = True
                try:
                    auth._cleanup()
                except Exception:
                    cleanup_failed = True
        except Exception:
            cleanup_failed = token is not None
        if cleanup_failed:
            raise AdapterError("ephemeral credential cleanup failed") from None


def _isolated_runtime() -> bool:
    return bool(sys.flags.isolated and sys.flags.safe_path)


def main(argv: Sequence[str] | None = None) -> int:
    if not _isolated_runtime():
        print("ADAPTER_ERROR: isolated Python runtime required", file=sys.stderr)
        return 70
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "--":
        print("POLICY_DENIED: invocation must use '--' before the command", file=sys.stderr)
        return 64
    try:
        return execute(args[1:])
    except PolicyError:
        print("POLICY_DENIED", file=sys.stderr)
        return 64
    except AuthRequired:
        print("AUTH_REQUIRED", file=sys.stderr)
        return 69
    except AdapterError:
        print("ADAPTER_ERROR", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
