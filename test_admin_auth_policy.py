#!/usr/bin/env python3
import contextlib
import io
import subprocess
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
PLAYBOOK = (ROOT / "docs" / "ADMIN_PLAYBOOK.md").read_text(encoding="utf-8")
SECTION = PLAYBOOK.split("### Profilsäker Adam-auth-status\n", 1)[1].split("\n## ", 1)[0]
RUNTIME_README = (ROOT / "runtime" / "adam" / "README.md").read_text(encoding="utf-8")
PROMPT_PATH = ROOT / "runtime" / "adam" / "gneu-content-watch.prompt.md"
ADMIN_RUNTIME_README = (ROOT / "runtime" / "admin" / "README.md").read_text(encoding="utf-8")
BROKER_PATH = ROOT / "runtime" / "admin" / "gneu-github-app"
WRAPPER_PATH = ROOT / "runtime" / "admin" / "gneu-admin-github"

loader = SourceFileLoader("gneu_github_app", str(BROKER_PATH))
spec = spec_from_loader(loader.name, loader)
assert spec is not None, "could not load tracked Admin broker"
BROKER = module_from_spec(spec)
loader.exec_module(BROKER)

TEST_TOKEN = "TEST_TOKEN_MUST_NOT_LEAK"

EXPECTED_COMMAND = """HERMES_HOME=/root/.hermes/profiles/gneu \\
/usr/bin/python3 -I \\
/root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py status"""
PROMPT_SETUP = (
    "PROMPT_SENTINEL='__GNEU_PROMPT_SENTINEL__'\n"
    "PROMPT=\"$(cat runtime/adam/gneu-content-watch.prompt.md; printf '%s' \"$PROMPT_SENTINEL\")\"\n"
    'PROMPT="${PROMPT%$PROMPT_SENTINEL}"'
)
DOCUMENTED_PROMPT_SETUP = "\n".join(f"   {line}" for line in PROMPT_SETUP.splitlines())
BROKEN_PROMPT_INSTALL = '--prompt "$(cat runtime/adam/gneu-content-watch.prompt.md)"'

assert EXPECTED_COMMAND in SECTION, "Admin auth policy lost the exact GNEU-profile status command"
assert "OGILTIG\nEVIDENS" in SECTION, "Admin auth policy lost invalid-evidence handling"
assert "automatisk fail-closed-paus" in SECTION, "Admin auth policy lost the fail-closed pause guard"
assert "gneu-content-watch" in SECTION, "Admin auth policy no longer protects the Adam watch job"
assert EXPECTED_COMMAND in RUNTIME_README, "runtime auth status lost the explicit GNEU profile"
assert BROKEN_PROMPT_INSTALL not in RUNTIME_README, "runtime prompt install strips terminal newlines"
assert DOCUMENTED_PROMPT_SETUP in RUNTIME_README, "runtime prompt install lost the newline-safe sentinel setup"
assert '--prompt "$PROMPT"' in RUNTIME_README, "runtime prompt is not passed as one quoted argument"

original_prompt = PROMPT_PATH.read_bytes()
assert original_prompt.endswith(b"\n"), "runtime prompt must exercise terminal-LF preservation"
reconstructed_prompt = subprocess.run(
    ["/bin/bash", "-c", PROMPT_SETUP + "\nprintf '%s' \"$PROMPT\""],
    cwd=ROOT,
    check=True,
    capture_output=True,
).stdout
assert reconstructed_prompt == original_prompt, "sentinel method changed the exact runtime prompt bytes"


def expect_runtime_error(callback, message):
    try:
        callback()
    except RuntimeError:
        return
    raise AssertionError(message)


def permission_request(profile):
    requests = []

    def fake_request(method, path, bearer, body=None):
        requests.append((method, path, bearer, body))
        return {
            "token": TEST_TOKEN,
            "permissions": dict(body["permissions"]),
        }

    with (
        mock.patch.object(
            BROKER,
            "installation",
            return_value={"id": 123, "app_slug": profile},
        ),
        mock.patch.object(BROKER, "make_jwt", return_value="test-jwt"),
        mock.patch.object(BROKER, "github_request", side_effect=fake_request),
    ):
        token, _, _ = BROKER.mint(profile)

    assert token == TEST_TOKEN
    assert len(requests) == 1
    method, path, bearer, body = requests[0]
    assert method == "POST"
    assert path == "/app/installations/123/access_tokens"
    assert bearer == "test-jwt"
    assert body["repositories"] == ["gneu-content"]
    return body["permissions"]


def run_check(profile, permissions, expect_failure=False):
    revoked = []
    stdout = io.StringIO()
    stderr = io.StringIO()

    def fake_request(method, path, bearer, body=None):
        assert (method, path, bearer, body) == (
            "GET",
            "/installation/repositories",
            TEST_TOKEN,
            None,
        )
        return {
            "repositories": [
                {"full_name": "stebolainen/gneu-content"},
            ],
        }

    error = None
    with (
        mock.patch.object(
            BROKER,
            "mint",
            return_value=(
                TEST_TOKEN,
                {"permissions": permissions, "expires_at": "test-expiry"},
                {"id": 123, "app_slug": profile},
            ),
        ),
        mock.patch.object(BROKER, "github_request", side_effect=fake_request),
        mock.patch.object(BROKER, "revoke", side_effect=revoked.append),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        try:
            BROKER.check(profile)
        except RuntimeError as exc:
            error = exc

    combined_output = stdout.getvalue() + stderr.getvalue()
    if error is not None:
        combined_output += str(error)

    assert revoked == [TEST_TOKEN], "check did not revoke its token exactly once"
    assert TEST_TOKEN not in combined_output, "token value leaked to output"
    assert (error is not None) == expect_failure


assert BROKER.OWNER == "stebolainen"
assert BROKER.REPO == "gneu-content"
assert BROKER.PROFILE_DIRS.keys() == {"gneu-admin", "gneu-forvaltare"}

admin_permissions = permission_request("gneu-admin")
assert admin_permissions == {
    "contents": "write",
    "pull_requests": "write",
    "workflows": "write",
}

forvaltare_permissions = permission_request("gneu-forvaltare")
assert forvaltare_permissions == {
    "contents": "write",
    "pull_requests": "write",
}
assert "workflows" not in forvaltare_permissions

run_check("gneu-admin", admin_permissions)
run_check(
    "gneu-admin",
    {"contents": "write", "pull_requests": "write"},
    expect_failure=True,
)
run_check(
    "gneu-admin",
    {
        "contents": "write",
        "pull_requests": "write",
        "workflows": "read",
    },
    expect_failure=True,
)
run_check(
    "gneu-forvaltare",
    {
        "contents": "write",
        "pull_requests": "write",
        "workflows": "write",
    },
    expect_failure=True,
)

BROKER.authorize_command(
    "gneu-admin",
    ["git", "push", "origin", "admin/admin-app-workflows-permission"],
)
BROKER.authorize_command(
    "gneu-admin",
    [
        "gh",
        "pr",
        "create",
        "--repo",
        "stebolainen/gneu-content",
        "--base",
        "main",
        "--head",
        "admin/admin-app-workflows-permission",
    ],
)
expect_runtime_error(
    lambda: BROKER.authorize_command(
        "gneu-admin", ["git", "push", "--force", "origin", "admin/test"]
    ),
    "Admin force-push unexpectedly allowed",
)
expect_runtime_error(
    lambda: BROKER.authorize_command(
        "gneu-admin", ["git", "push", "origin", "main"]
    ),
    "Admin main push unexpectedly allowed",
)
expect_runtime_error(
    lambda: BROKER.authorize_command(
        "gneu-admin",
        ["gh", "pr", "create", "--base", "published", "--head", "admin/test"],
    ),
    "Admin PR to a non-main base unexpectedly allowed",
)

assert WRAPPER_PATH.read_text(encoding="utf-8") == (
    "#!/bin/sh\nexec /usr/local/sbin/gneu-github-app gneu-admin \"$@\"\n"
)
for required_text in (
    "source of truth",
    "/usr/local/sbin/gneu-github-app",
    "/usr/local/bin/gneu-admin-github",
    "verifierad mergecommit",
    "sha256sum",
    "cmp --silent",
    "/usr/local/bin/gneu-admin-github check",
    "aldrig handredigeras",
):
    assert required_text in ADMIN_RUNTIME_README, (
        f"Admin runtime install/hash contract lost: {required_text}"
    )

print("GNEU Admin Adam-auth policy contract OK")
