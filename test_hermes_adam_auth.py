#!/usr/bin/env python3
from __future__ import annotations

import base64
import importlib.util
import json
import os
import tempfile
from pathlib import Path

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

with tempfile.TemporaryDirectory(prefix="gneu-auth-") as td:
    root = Path(td)
    sec = root / "secrets"
    tok = root / "inbox" / "github-token"
    os.environ["GNEU_ADAM_APP_SECRET_DIR"] = str(sec)
    os.environ["GNEU_GITHUB_TOKEN_FILE"] = str(tok)

    st = auth._status()
    ok(st["configured"] is False, "unconfigured by default")
    ok(st["token_present"] is False, "no token by default")

    sec.mkdir(parents=True)
    (sec / "app-id").write_text("12345\n", encoding="utf-8")
    (sec / "private-key.pem").write_text("dummy\n", encoding="utf-8")
    st = auth._status()
    ok(st["configured"] is True, "config files detected")

    tok.parent.mkdir(parents=True)
    tok.write_text("never-print-this-token", encoding="utf-8")
    auth.meta_file().write_text(json.dumps({"expires_at":"2026-08-20T16:00:00Z"}), encoding="utf-8")
    st = auth._status()
    ok(st["token_present"] is True, "token presence detected")
    ok("never-print" not in json.dumps(st), "status never exposes token")

    # Avoid network: blank token means cleanup removes local files without revoke.
    tok.write_text("", encoding="utf-8")
    auth._cleanup()
    ok(not tok.exists(), "cleanup removes token file")
    ok(not auth.meta_file().exists(), "cleanup removes metadata")

    original_jwt = auth._jwt
    original_installation_id = auth._installation_id
    original_request = auth._request
    try:
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

print(f"gneu-content 9.9.2 Adam auth helper OK · {N} kontroller")
