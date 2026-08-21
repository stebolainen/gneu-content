#!/usr/bin/env python3
from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("auth", ROOT / "hermes_adam_auth.py")
auth = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(auth)

N = 0
def ok(v, label):
    global N
    N += 1
    if not v:
        raise SystemExit("FAIL: " + label)

ok(auth.OWNER == "stebolainen", "owner locked")
ok(auth.REPO == "gneu-content", "repo locked")
ok(auth._b64url(b"\xff").find("=") == -1, "base64url has no padding")
ok(not hasattr(auth, "_store_token"), "auth helper exposes no token-file writer")
ok(not hasattr(auth, "_mint"), "auth helper exposes no standalone disk mint")

with tempfile.TemporaryDirectory(prefix="gneu-auth-") as td:
    root = Path(td)
    sec = root / "secrets"
    tok = root / "inbox" / "github-token"
    os.environ["GNEU_ADAM_APP_SECRET_DIR"] = str(sec)
    os.environ["GNEU_GITHUB_TOKEN_FILE"] = str(tok)

    st = auth._status()
    ok(st["configured"] is False, "unconfigured by default")
    ok(st["status"] == "auth_required", "missing credentials are auth_required")
    ok(st["token_present"] is False, "no token by default")

    sec.mkdir(parents=True, mode=0o700)
    (sec / "app-id").write_text("12345\n", encoding="utf-8")
    (sec / "private-key.pem").write_text("dummy\n", encoding="utf-8")
    os.chmod(sec, 0o700)
    os.chmod(sec / "app-id", 0o600)
    os.chmod(sec / "private-key.pem", 0o600)
    os.chmod(sec / "app-id", 0o064)
    ok(auth._owner_only(sec / "app-id") is False, "group/other-readable app id is rejected")
    os.chmod(sec / "app-id", 0o600)
    with mock.patch.object(auth, "_validate_private_key", return_value=True):
        st = auth._status()
    ok(st["configured"] is True, "valid config files detected")
    ok(st["status"] == "ready", "valid configuration is ready without mint")

    tok.parent.mkdir(parents=True)
    tok.write_text("never-print-this-token", encoding="utf-8")
    auth.meta_file().write_text(json.dumps({"expires_at":"2026-08-20T16:00:00Z"}), encoding="utf-8")
    with mock.patch.object(auth, "_validate_private_key", return_value=True):
        st = auth._status()
    ok(st["token_present"] is True, "token presence detected")
    ok(st["status"] == "auth_required", "legacy token presence blocks ready status")
    ok("never-print" not in json.dumps(st), "status never exposes token")

    # Avoid network: blank token means cleanup removes local files without revoke.
    tok.write_text("", encoding="utf-8")
    os.chmod(tok.parent, 0o700)
    os.chmod(tok, 0o600)
    auth._cleanup()
    ok(not tok.exists(), "cleanup removes token file")
    ok(not auth.meta_file().exists(), "cleanup removes metadata")

    victim = root / "must-not-be-read"
    victim.write_text("sensitive-value", encoding="utf-8")
    tok.symlink_to(victim)
    requests = []
    with mock.patch.object(auth, "_request", side_effect=lambda *args, **kwargs: requests.append(args)):
        _, revoke = auth._cleanup()
    ok(victim.read_text(encoding="utf-8") == "sensitive-value", "symlink cleanup preserves target")
    ok(not tok.exists(), "symlink cleanup removes only legacy link")
    ok(requests == [], "symlink cleanup never exfiltrates target as bearer")
    ok(revoke == "unsafe_removed", "unsafe legacy token is reported")
    with mock.patch.object(auth, "_cleanup", return_value=(True, "revoke_failed")):
        with mock.patch.object(sys, "argv", ["hermes_adam_auth.py", "cleanup"]):
            ok(auth.main() == 2, "unverified revoke returns nonzero")

    original_jwt = auth._jwt
    original_installation_id = auth._installation_id
    original_request = auth._request
    original_validate_private_key = auth._validate_private_key
    try:
        setattr(auth, "_validate_private_key", lambda path: True)
        setattr(auth, "_jwt", lambda: "app-jwt")
        setattr(auth, "_installation_id", lambda app_jwt: 77)
        setattr(auth, "_request", lambda method, path, bearer, body=None: (201, {
            "token": "in-memory-installation-token",
            "expires_at": "2026-08-21T06:00:00Z",
            "repositories": [{"full_name": "stebolainen/gneu-content"}],
        }))
        token, meta = auth._mint_token()
        ok(token == "in-memory-installation-token", "in-memory mint returns token")
        ok(meta["owner_repo"] == "stebolainen/gneu-content", "in-memory mint locks repository")
        ok(not tok.exists(), "in-memory mint does not write token file")

        revoked = []
        def wrong_scope_request(method, path, bearer, body=None):
            if method == "DELETE":
                revoked.append(bearer)
                return 204, None
            return 201, {
                "token": "wrong-scope-token",
                "expires_at": "2026-08-21T06:00:00Z",
                "repositories": [{"full_name": "other/repository"}],
            }
        setattr(auth, "_request", wrong_scope_request)
        try:
            auth._mint_token()
        except RuntimeError:
            pass
        else:
            raise SystemExit("FAIL: wrong repository scope accepted")
        ok(revoked == ["wrong-scope-token"], "wrong-scope token revoked before failure")
    finally:
        setattr(auth, "_jwt", original_jwt)
        setattr(auth, "_installation_id", original_installation_id)
        setattr(auth, "_request", original_request)
        setattr(auth, "_validate_private_key", original_validate_private_key)

print(f"gneu-content 9.9.3 Adam auth helper OK · {N} kontroller")
