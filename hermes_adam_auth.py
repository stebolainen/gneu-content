#!/usr/bin/env python3
"""Short-lived GitHub App authentication for gneu-content Adam.

Secrets are read from the active Hermes profile:
  $HERMES_HOME/secrets/gneu-content-adam/app-id
  $HERMES_HOME/secrets/gneu-content-adam/private-key.pem

The 9.9.3 source gate uses only the non-minting `status` command. The credential
adapter uses `_mint_token()` in memory only when it executes an allowlisted
GitHub command. This helper has no CLI or function that writes a new token to
disk; `cleanup` only removes/revokes a legacy 9.9.2 token if one remains.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat as stat_module
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
USER_AGENT = "gneu-content-adam-auth/9.9.3"


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


def _owner_only(path: Path, *, directory: bool = False) -> bool:
    """Return whether a credential path is local, owner-controlled and expected."""
    try:
        stat = path.lstat()
    except OSError:
        return False
    expected_type = path.is_dir() if directory else path.is_file()
    maximum_mode = 0o700 if directory else 0o600
    return bool(
        expected_type
        and not path.is_symlink()
        and stat.st_uid == os.geteuid()
        and not (stat.st_mode & 0o077)
        and (stat.st_mode & 0o700) <= maximum_mode
    )


def _validate_private_key(path: Path) -> bool:
    """Validate key structure locally without minting, networking or output."""
    try:
        cp = subprocess.run(
            ["/usr/bin/openssl", "pkey", "-in", str(path), "-check", "-noout"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"},
            shell=False,
            check=False,
            timeout=10,
        )
    except Exception:
        return False
    return cp.returncode == 0


def _assert_credentials_ready() -> None:
    directory = secret_dir()
    app_path = directory / "app-id"
    key_path = directory / "private-key.pem"
    if not _owner_only(directory, directory=True):
        raise RuntimeError("credential directory is missing or unsafe")
    if not _owner_only(app_path):
        raise RuntimeError("app-id file is missing or unsafe")
    if not _owner_only(key_path):
        raise RuntimeError("private key file is missing or unsafe")
    if not _read_app_id().isdigit():
        raise RuntimeError("app-id is invalid")
    if not _validate_private_key(key_path):
        raise RuntimeError("private key is invalid")
    if token_file().exists() or token_file().is_symlink():
        raise RuntimeError("legacy token path must be clean before mint")


def _jwt(now: int | None = None) -> str:
    now = int(time.time()) if now is None else int(now)
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": _read_app_id()}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode("ascii")
    cp = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(_private_key()), "-binary"],
        input=signing,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin"},
        shell=False,
        timeout=10,
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


def _mint_token() -> tuple[str, dict[str, Any]]:
    """Mint and validate a repository-scoped token without writing it to disk."""
    _assert_credentials_ready()
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
    if full_names != [f"{OWNER}/{REPO}"]:
        try:
            _request("DELETE", "/installation/token", token)
        except Exception:
            pass
        raise RuntimeError(f"unexpected repository scope: {full_names}")

    meta = {
        "schema": "gneu-content-adam-token-v1",
        "owner_repo": f"{OWNER}/{REPO}",
        "installation_id": installation_id,
        "expires_at": expires_at,
        "created_at_epoch": int(time.time()),
    }
    return token, meta


def _cleanup() -> tuple[bool, str]:
    tf = token_file()
    mp = meta_file()
    revoke = "not_present"
    token_path_present = tf.exists() or tf.is_symlink()
    if token_path_present:
        try:
            if not _owner_only(tf.parent, directory=True):
                raise RuntimeError("unsafe legacy token directory")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(tf, flags)
            try:
                info = os.fstat(fd)
                if (
                    not stat_module.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > 4096
                ):
                    raise RuntimeError("unsafe legacy token file")
                token = os.read(fd, 4097).decode("ascii").strip()
            finally:
                os.close(fd)
            if len(token) > 4096 or any(character.isspace() for character in token):
                raise RuntimeError("malformed legacy token")
            if token:
                try:
                    status, _ = _request("DELETE", "/installation/token", token)
                    revoke = "revoked" if status == 204 else f"http_{status}"
                except Exception:
                    revoke = "revoke_failed"
        except Exception:
            revoke = "unsafe_removed"
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
    app_id_path = sd / "app-id"
    key_path = sd / "private-key.pem"
    directory_ok = _owner_only(sd, directory=True)
    app_id_file = _owner_only(app_id_path)
    key_file = _owner_only(key_path)
    app_id_ok = False
    if directory_ok and app_id_file:
        try:
            app_id = app_id_path.read_text(encoding="utf-8").strip()
            app_id_ok = bool(app_id.isdigit() and str(int(app_id)) == app_id and int(app_id) > 0)
        except Exception:
            app_id_ok = False
    key_ok = bool(directory_ok and key_file and _validate_private_key(key_path))
    legacy_token_present = token_file().exists() or token_file().is_symlink()
    configured = bool(app_id_ok and key_ok and not legacy_token_present)
    meta = {}
    if _owner_only(meta_file()) and _owner_only(meta_file().parent, directory=True):
        try:
            meta = json.loads(meta_file().read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    return {
        "status": "ready" if configured else "auth_required",
        "configured": configured,
        "app_id_file": app_id_file,
        "private_key_file": key_file,
        "app_id_valid": app_id_ok,
        "private_key_valid": key_ok,
        "token_present": legacy_token_present,
        "expires_at": meta.get("expires_at"),
        "owner_repo": f"{OWNER}/{REPO}",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("cleanup", "status"))
    args = ap.parse_args()

    try:
        if args.command == "cleanup":
            _, revoke = _cleanup()
            verified = revoke in {"not_present", "revoked"}
            print(json.dumps({
                "status": "REMOVED" if verified else "UNVERIFIED",
                "revoke": revoke,
            }, separators=(",", ":")))
            return 0 if verified else 2

        print(json.dumps(_status(), separators=(",", ":")))
        return 0

    except Exception as exc:
        # No secret values are ever emitted.
        print(f"AUTH_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
