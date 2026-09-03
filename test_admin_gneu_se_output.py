#!/usr/bin/env python3
import contextlib
import io
import json
import urllib.error
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
BROKER_PATH = ROOT / "gneu-github-app"
if not BROKER_PATH.exists():
    BROKER_PATH = ROOT / "runtime" / "admin" / "gneu-github-app"

loader = SourceFileLoader("gneu_github_app_output_test", str(BROKER_PATH))
spec = spec_from_loader(loader.name, loader)
assert spec is not None
BROKER = module_from_spec(spec)
loader.exec_module(BROKER)

INSTALLATION_TOKEN = "SYNTHETIC_INSTALLATION_TOKEN_MUST_NOT_LEAK"
JWT_VALUE = "SYNTHETIC_JWT_MUST_NOT_LEAK"
POISON_VALUE = "SYNTHETIC_RESPONSE_CREDENTIAL_MUST_NOT_LEAK"
SHA = "a" * 40
OTHER_SHA = "b" * 40


def expect_runtime_error(callback, expected_message):
    try:
        callback()
    except RuntimeError as exc:
        assert str(exc) == expected_message
        return
    raise AssertionError("expected fail-closed RuntimeError")


def read_with_response(operation, args, response, expect_failure=False):
    revoked = []
    requests = []
    stdout = io.StringIO()
    stderr = io.StringIO()
    error = None

    def fake_request(method, path, bearer, body=None):
        requests.append((method, path, bearer, body))
        assert method == "GET"
        assert bearer == INSTALLATION_TOKEN
        assert body is None
        if path == "/installation/repositories":
            return {
                "repositories": [
                    {"full_name": "stebolainen/gneu-se"},
                ],
                "total_count": 1,
            }
        return response

    with (
        mock.patch.object(
            BROKER,
            "mint_gneu_se",
            return_value=(INSTALLATION_TOKEN, {}, {"jwt": JWT_VALUE}),
        ),
        mock.patch.object(BROKER, "github_request", side_effect=fake_request),
        mock.patch.object(BROKER, "revoke", side_effect=revoked.append),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        try:
            BROKER.read_gneu_se("gneu-admin", operation, args)
        except RuntimeError as exc:
            error = exc

    combined = stdout.getvalue() + stderr.getvalue()
    for forbidden in (INSTALLATION_TOKEN, JWT_VALUE, POISON_VALUE):
        assert forbidden not in combined
    assert revoked == [INSTALLATION_TOKEN]
    assert len(requests) == 2
    assert (error is not None) == expect_failure

    if error is not None:
        assert str(error) == BROKER.UNSAFE_RESPONSE
        assert stdout.getvalue() == ""
        assert stderr.getvalue() == ""
        return None

    projected = json.loads(stdout.getvalue())
    assert stdout.getvalue() == (
        json.dumps(
            projected,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return projected


repo = read_with_response(
    "repo",
    [],
    {
        "full_name": "stebolainen/gneu-se",
        "name": "gneu-se",
        "owner": {
            "login": "stebolainen",
            "credential": POISON_VALUE,
        },
        "private": True,
        "default_branch": "main",
        "archived": False,
        "disabled": False,
        "temp_clone_token": POISON_VALUE,
        "clone_url": f"https://example.invalid/repo?token={POISON_VALUE}",
        "authorization": POISON_VALUE,
        "jwt": JWT_VALUE,
    },
)
assert repo == {
    "archived": False,
    "default_branch": "main",
    "disabled": False,
    "full_name": "stebolainen/gneu-se",
    "name": "gneu-se",
    "owner": {"login": "stebolainen"},
    "private": True,
}

contents_file = read_with_response(
    "contents",
    ["data/example.json", "--ref", "main"],
    {
        "name": "example.json",
        "path": "data/example.json",
        "sha": SHA,
        "size": 8,
        "type": "file",
        "encoding": "base64",
        "content": "U0FGRQ==\n",
        "download_url": (
            f"https://example.invalid/file?X-Amz-Signature={POISON_VALUE}"
        ),
        "html_url": "https://example.invalid/html",
        "git_url": "https://example.invalid/git",
        "url": "https://example.invalid/api",
        "_links": {"token": POISON_VALUE},
    },
)
assert contents_file == {
    "content": "U0FGRQ==\n",
    "encoding": "base64",
    "name": "example.json",
    "path": "data/example.json",
    "sha": SHA,
    "size": 8,
    "type": "file",
}

contents_directory = read_with_response(
    "contents",
    ["data", "--ref", "main"],
    [
        {
            "name": "example.json",
            "path": "data/example.json",
            "sha": SHA,
            "size": 8,
            "type": "file",
            "download_url": (
                f"https://example.invalid/file?X-Goog-Signature={POISON_VALUE}"
            ),
            "url": "https://example.invalid/api",
        },
        {
            "name": "nested",
            "path": "data/nested",
            "sha": OTHER_SHA,
            "size": 0,
            "type": "dir",
            "_links": {"access_token": POISON_VALUE},
        },
    ],
)
assert contents_directory == [
    {
        "name": "example.json",
        "path": "data/example.json",
        "sha": SHA,
        "size": 8,
        "type": "file",
    },
    {
        "name": "nested",
        "path": "data/nested",
        "sha": OTHER_SHA,
        "size": 0,
        "type": "dir",
    },
]

pull_response = {
    "number": 21,
    "title": "Safe pull request",
    "state": "open",
    "draft": False,
    "merged_at": None,
    "created_at": "2026-09-01T10:00:00Z",
    "updated_at": "2026-09-02T10:00:00Z",
    "user": {"login": "operator", "token": POISON_VALUE},
    "base": {
        "ref": "main",
        "sha": SHA,
        "repo": {"credential": POISON_VALUE},
    },
    "head": {
        "ref": "candidate",
        "sha": OTHER_SHA,
        "repo": {"temp_clone_token": POISON_VALUE},
    },
    "_links": {"authorization": POISON_VALUE},
}
expected_pull = {
    "base": {"ref": "main", "sha": SHA},
    "created_at": "2026-09-01T10:00:00Z",
    "draft": False,
    "head": {"ref": "candidate", "sha": OTHER_SHA},
    "merged_at": None,
    "number": 21,
    "state": "open",
    "title": "Safe pull request",
    "updated_at": "2026-09-02T10:00:00Z",
    "user": {"login": "operator"},
}
assert read_with_response("pr-view", ["21"], pull_response) == expected_pull
assert read_with_response("pr-list", [], [pull_response]) == [expected_pull]

ordinary_word = dict(pull_response)
ordinary_word["title"] = "Token policy without a credential value"
ordinary_projection = read_with_response("pr-view", ["21"], ordinary_word)
assert ordinary_projection["title"] == ordinary_word["title"]

workflow_run = read_with_response(
    "workflow-run",
    ["33475420413"],
    {
        "id": 33475420413,
        "name": "AI-hot intake",
        "workflow_id": 99,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "head_branch": "main",
        "head_sha": SHA,
        "run_number": 12,
        "run_attempt": 1,
        "created_at": "2026-09-01T10:00:00Z",
        "run_started_at": "2026-09-01T10:00:01Z",
        "updated_at": "2026-09-01T10:01:00Z",
        "logs_url": f"https://example.invalid/logs?sig={POISON_VALUE}",
        "artifacts_url": f"https://example.invalid/artifacts?token={POISON_VALUE}",
        "rerun_url": "https://example.invalid/rerun",
    },
)
assert workflow_run == {
    "conclusion": "failure",
    "created_at": "2026-09-01T10:00:00Z",
    "event": "workflow_dispatch",
    "head_branch": "main",
    "head_sha": SHA,
    "id": 33475420413,
    "name": "AI-hot intake",
    "run_attempt": 1,
    "run_number": 12,
    "run_started_at": "2026-09-01T10:00:01Z",
    "status": "completed",
    "updated_at": "2026-09-01T10:01:00Z",
    "workflow_id": 99,
}

job_response = {
    "id": 88,
    "name": "validate",
    "status": "completed",
    "conclusion": "failure",
    "head_sha": SHA,
    "started_at": "2026-09-01T10:00:01Z",
    "completed_at": "2026-09-01T10:01:00Z",
    "url": "https://example.invalid/job",
    "html_url": "https://example.invalid/job/html",
    "runner_name": "unneeded",
    "steps": [
        {
            "number": 1,
            "name": "Validate intake",
            "status": "completed",
            "conclusion": "failure",
            "started_at": "2026-09-01T10:00:02Z",
            "completed_at": "2026-09-01T10:00:03Z",
            "url": f"https://example.invalid/step?signature={POISON_VALUE}",
        }
    ],
}
expected_job = {
    "completed_at": "2026-09-01T10:01:00Z",
    "conclusion": "failure",
    "head_sha": SHA,
    "id": 88,
    "name": "validate",
    "started_at": "2026-09-01T10:00:01Z",
    "status": "completed",
    "steps": [
        {
            "completed_at": "2026-09-01T10:00:03Z",
            "conclusion": "failure",
            "name": "Validate intake",
            "number": 1,
            "started_at": "2026-09-01T10:00:02Z",
            "status": "completed",
        }
    ],
}
assert read_with_response(
    "workflow-jobs",
    ["33475420413"],
    {
        "total_count": 1,
        "jobs": [job_response],
        "url": f"https://example.invalid/jobs?access_token={POISON_VALUE}",
    },
) == {"jobs": [expected_job], "total_count": 1}
assert read_with_response("workflow-job", ["88"], job_response) == expected_job

assert read_with_response(
    "branch",
    ["main"],
    {
        "name": "main",
        "protected": True,
        "commit": {"sha": SHA, "url": "https://example.invalid/commit"},
        "protection_url": f"https://example.invalid?token={POISON_VALUE}",
    },
) == {"commit": {"sha": SHA}, "name": "main", "protected": True}

assert read_with_response(
    "ref",
    ["heads/main"],
    {
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": SHA, "url": POISON_VALUE},
        "url": POISON_VALUE,
    },
) == {"object": {"sha": SHA, "type": "commit"}, "ref": "refs/heads/main"}

read_with_response("repo", [], [repo], expect_failure=True)
read_with_response(
    "repo",
    [],
    {
        "full_name": "stebolainen/gneu-se",
        "name": "gneu-se",
        "owner": {"login": "stebolainen"},
        "private": "yes",
        "default_branch": "main",
        "archived": False,
        "disabled": False,
        "temp_clone_token": POISON_VALUE,
    },
    expect_failure=True,
)

expect_runtime_error(
    lambda: BROKER.validate_gneu_se_repository_scope(
        {
            "repositories": [{"full_name": POISON_VALUE}],
            "total_count": 1,
        }
    ),
    "gneu-se-token har fel repository-scope",
)

signed_title = dict(pull_response)
signed_title["title"] = (
    f"https://example.invalid/report?X-Amz-Signature={POISON_VALUE}"
)
read_with_response("pr-view", ["21"], signed_title, expect_failure=True)

cli_revoked = []
cli_stdout = io.StringIO()
cli_stderr = io.StringIO()


def cli_request(method, path, bearer, body=None):
    if path == "/installation/repositories":
        return {
            "repositories": [{"full_name": "stebolainen/gneu-se"}],
            "total_count": 1,
        }
    return {
        "full_name": "stebolainen/gneu-se",
        "temp_clone_token": POISON_VALUE,
    }


with (
    mock.patch.object(
        BROKER.sys,
        "argv",
        ["gneu-github-app", "gneu-admin", "gneu-se-read", "repo"],
    ),
    mock.patch.object(
        BROKER,
        "mint_gneu_se",
        return_value=(INSTALLATION_TOKEN, {}, {}),
    ),
    mock.patch.object(BROKER, "github_request", side_effect=cli_request),
    mock.patch.object(BROKER, "revoke", side_effect=cli_revoked.append),
    contextlib.redirect_stdout(cli_stdout),
    contextlib.redirect_stderr(cli_stderr),
):
    assert BROKER.main() == 1
assert cli_stdout.getvalue() == ""
assert cli_stderr.getvalue() == "FEL: BLOCKED_UNSAFE_RESPONSE\n"
assert POISON_VALUE not in cli_stderr.getvalue()
assert INSTALLATION_TOKEN not in cli_stderr.getvalue()
assert cli_revoked == [INSTALLATION_TOKEN]

for unsafe_key in (
    "token",
    "access_token",
    "temp_clone_token",
    "authorization",
    "credential",
    "download_url",
    "signed",
    "signature",
    "x-amz-signature",
    "x-goog-signature",
):
    expect_runtime_error(
        lambda key=unsafe_key: BROKER.guard_gneu_se_output({key: "hidden"}),
        BROKER.UNSAFE_RESPONSE,
    )

error_body = io.BytesIO(
    json.dumps({"message": f"server echoed {POISON_VALUE}"}).encode("utf-8")
)
http_error = urllib.error.HTTPError(
    "https://api.github.com/test",
    403,
    "forbidden",
    {},
    error_body,
)
stdout = io.StringIO()
stderr = io.StringIO()
with (
    mock.patch.object(BROKER.urllib.request, "urlopen", side_effect=http_error),
    contextlib.redirect_stdout(stdout),
    contextlib.redirect_stderr(stderr),
):
    try:
        BROKER.github_request("GET", "/test", INSTALLATION_TOKEN)
    except RuntimeError as exc:
        assert str(exc) == "GitHub API HTTP 403"
    else:
        raise AssertionError("secret-bearing HTTP error did not fail closed")
assert stdout.getvalue() == ""
assert stderr.getvalue() == ""

assert BROKER.GNEU_SE_TOKEN_PERMISSIONS == {
    "actions": "read",
    "contents": "read",
    "pull_requests": "read",
}

print("GNEU Admin gneu-se output sanitization OK")
