#!/usr/bin/env python3
"""Short-lived GitHub App authentication for gneu-content Adam.

Secrets are read from the active Hermes profile:
  $HERMES_HOME/secrets/gneu-content-adam/app-id
  $HERMES_HOME/secrets/gneu-content-adam/private-key.pem

The installation token is written to /root/gneu-inbox/github-token (0600).
The token value is never printed. `cleanup` revokes it when possible and always
removes the local token file.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

OWNER = "stebolainen"
REPO = "gneu-content"
API = "https://api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "gneu-content-adam-auth/9.9.2"


def hermes_home() -> Path:
    return Path(os.getenv("HERMES_HOME", "~/.hermes")).expanduser()


def secret_dir() -> Path:
    override = os.getenv("GNEU_ADAM_APP_SECRET_DIR", "").strip()
    return Path(override).expanduser() if override else hermes_home() / "secrets" / "gneu-content-adam"


def token_file() -> Path:
    return Path(os.getenv("GNEU_GITHUB_TOKEN_FILE", "/root/gneu-inbox/github-token")).expanduser()


def meta_file() -> Path:
    p = token_file()
    return p.with_name(p.name + ".meta.json")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _read_app_id() -> str:
    p = secret_dir() / "app-id"
    if not p.is_file():
        raise RuntimeError(f"missing app id file: {p}")
    app_id = p.read_text(encoding="utf-8").strip()
    if not app_id.isdigit():
        raise RuntimeError("app-id must contain the numeric GitHub App ID")
    return app_id


def _private_key() -> Path:
    p = secret_dir() / "private-key.pem"
    if not p.is_file():
        raise RuntimeError(f"missing private key file: {p}")
    return p


def _jwt(now: int | None = None) -> str:
    now = int(time.time()) if now is None else int(now)
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": _read_app_id()}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode("ascii")
    cp = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(_private_key()), "-binary"],
        input=signing,
        capture_output=True,
    )
    if cp.returncode != 0:
        raise RuntimeError("openssl failed to sign GitHub App JWT")
    return f"{h}.{p}.{_b64url(cp.stdout)}"


def _request(method: str, path: str, bearer: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {bearer}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            obj = json.loads(raw) if raw else None
            return int(response.status), obj
    except urllib.error.HTTPError as exc:
        raw = exc.read(2048)
        try:
            msg = json.loads(raw).get("message", "")
        except Exception:
            msg = ""
        raise RuntimeError(f"GitHub API HTTP {exc.code}" + (f": {msg}" if msg else "")) from exc


def _installation_id(app_jwt: str) -> int:
    status, obj = _request("GET", f"/repos/{OWNER}/{REPO}/installation", app_jwt)
    if status != 200 or not isinstance(obj, dict) or not isinstance(obj.get("id"), int):
        raise RuntimeError("could not resolve GitHub App installation for exact repository")
    return obj["id"]


def _mint() -> dict[str, Any]:
    app_jwt = _jwt()
    installation_id = _installation_id(app_jwt)
    status, obj = _request(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        app_jwt,
        {
            "repositories": [REPO],
            "permissions": {
                "contents": "write",
                "pull_requests": "write",
            },
        },
    )
    if status != 201 or not isinstance(obj, dict):
        raise RuntimeError("GitHub did not create installation token")
    token = obj.get("token")
    expires_at = obj.get("expires_at")
    repos = obj.get("repositories") or []
    full_names = [r.get("full_name") for r in repos if isinstance(r, dict)]
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub installation response had no token")
    if full_names and full_names != [f"{OWNER}/{REPO}"]:
        raise RuntimeError(f"unexpected repository scope: {full_names}")

    dest = token_file()
    dest.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(dest.parent, 0o700)

    tmp = dest.with_name(dest.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    os.replace(tmp, dest)
    os.chmod(dest, 0o600)

    meta = {
        "schema": "gneu-content-adam-token-v1",
        "owner_repo": f"{OWNER}/{REPO}",
        "installation_id": installation_id,
        "expires_at": expires_at,
        "created_at_epoch": int(time.time()),
    }
    mp = meta_file()
    mp.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(mp, 0o600)
    return meta


def _cleanup() -> tuple[bool, str]:
    tf = token_file()
    mp = meta_file()
    revoke = "not_present"
    if tf.is_file():
        try:
            token = tf.read_text(encoding="utf-8").strip()
            if token:
                try:
                    status, _ = _request("DELETE", "/installation/token", token)
                    revoke = "revoked" if status == 204 else f"http_{status}"
                except Exception:
                    revoke = "revoke_failed"
        finally:
            try:
                tf.unlink()
            except FileNotFoundError:
                pass
    try:
        mp.unlink()
    except FileNotFoundError:
        pass
    return True, revoke


def _status() -> dict[str, Any]:
    sd = secret_dir()
    app_id_ok = (sd / "app-id").is_file()
    key_ok = (sd / "private-key.pem").is_file()
    meta = {}
    if meta_file().is_file():
        try:
            meta = json.loads(meta_file().read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    return {
        "configured": bool(app_id_ok and key_ok),
        "app_id_file": app_id_ok,
        "private_key_file": key_ok,
        "token_present": token_file().is_file(),
        "expires_at": meta.get("expires_at"),
        "owner_repo": f"{OWNER}/{REPO}",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("mint", "cleanup", "status"))
    args = ap.parse_args()

    try:
        if args.command == "mint":
            # Never leave an older token around before minting a fresh one.
            _cleanup()
            meta = _mint()
            print(json.dumps({
                "status": "MINTED",
                "owner_repo": meta["owner_repo"],
                "expires_at": meta.get("expires_at"),
            }, separators=(",", ":")))
            return 0

        if args.command == "cleanup":
            _, revoke = _cleanup()
            print(json.dumps({"status": "REMOVED", "revoke": revoke}, separators=(",", ":")))
            return 0

        print(json.dumps(_status(), separators=(",", ":")))
        return 0

    except Exception as exc:
        # No secret values are ever emitted.
        print(f"AUTH_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
