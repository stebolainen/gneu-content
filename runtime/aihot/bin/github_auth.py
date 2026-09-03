from __future__ import annotations

import base64
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


ENV_FILE = Path("/root/gneu-aihot-bridge/credentials/app.env")

API = "https://api.github.com"
API_VERSION = "2022-11-28"

EXPECTED_OWNER = "stebolainen"
EXPECTED_REPO = "gneu-se"

EXPECTED_INSTALLATION_PERMISSIONS = {
    "actions": "write",
    "contents": "read",
    "metadata": "read",
}

PURPOSE_PERMISSIONS = {
    "read": {
        "contents": "read",
    },
    "dispatch": {
        "actions": "write",
    },
}


class AuthError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_env() -> dict[str, str]:
    if not ENV_FILE.is_file():
        raise AuthError("credential config missing")

    out: dict[str, str] = {}

    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        k, v = line.split("=", 1)
        out[k] = v

    return out


def _request_json(
    method: str,
    url: str,
    bearer: str,
    body: dict | None = None,
) -> dict:

    data = (
        json.dumps(body).encode("utf-8")
        if body is not None
        else None
    )

    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "gneu-aihot-trusted-bridge/2.0",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()

    except urllib.error.HTTPError as exc:
        raise AuthError(
            f"GitHub API HTTP {exc.code}"
        ) from None

    except Exception as exc:
        raise AuthError(
            f"GitHub API failure: {type(exc).__name__}"
        ) from None

    if not raw:
        return {}

    try:
        return json.loads(raw)

    except Exception:
        raise AuthError(
            "GitHub API returned invalid JSON"
        ) from None


def _exact_permissions(
    actual: dict,
    expected: dict,
    label: str,
) -> None:

    active = {
        k: v
        for k, v in actual.items()
        if v not in (None, "none")
    }

    if active != expected:
        raise AuthError(
            f"{label} permissions mismatch: "
            + ",".join(
                f"{k}={v}"
                for k, v in sorted(active.items())
            )
        )


def _make_jwt(
    app_id: str,
    key_path: Path,
) -> str:

    now = int(time.time())

    header = _b64url(
        json.dumps(
            {"alg": "RS256", "typ": "JWT"},
            separators=(",", ":"),
        ).encode()
    )

    payload = _b64url(
        json.dumps(
            {
                "iat": now - 60,
                "exp": now + 540,
                "iss": app_id,
            },
            separators=(",", ":"),
        ).encode()
    )

    unsigned = f"{header}.{payload}".encode()

    cp = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(key_path),
        ],
        input=unsigned,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    if cp.returncode != 0 or not cp.stdout:
        raise AuthError("JWT signing failed")

    return (
        f"{header}.{payload}."
        f"{_b64url(cp.stdout)}"
    )


def _configuration():
    env = _load_env()

    owner = env.get("GNEU_AIHOT_OWNER", "")
    repo = env.get("GNEU_AIHOT_REPO", "")
    app_id = env.get("GNEU_AIHOT_APP_ID", "")
    installation_id = env.get(
        "GNEU_AIHOT_INSTALLATION_ID",
        "",
    )

    key_path = Path(
        env.get("GNEU_AIHOT_PRIVATE_KEY", "")
    )

    if owner != EXPECTED_OWNER:
        raise AuthError("owner mismatch")

    if repo != EXPECTED_REPO:
        raise AuthError("repository mismatch")

    if not app_id.isdigit():
        raise AuthError("invalid App ID")

    if not installation_id.isdigit():
        raise AuthError("invalid Installation ID")

    if not key_path.is_file():
        raise AuthError("private key missing")

    if key_path.stat().st_mode & 0o077:
        raise AuthError(
            "private key permissions too broad"
        )

    return (
        app_id,
        installation_id,
        key_path,
    )


def mint_token(*, purpose: str = "read") -> str:
    if purpose not in PURPOSE_PERMISSIONS:
        raise AuthError("unknown token purpose")

    (
        app_id,
        installation_id,
        key_path,
    ) = _configuration()

    jwt = _make_jwt(
        app_id,
        key_path,
    )

    installation = _request_json(
        "GET",
        f"{API}/app/installations/{installation_id}",
        jwt,
    )

    account = installation.get("account") or {}

    if account.get("login") != EXPECTED_OWNER:
        raise AuthError(
            "installation owner mismatch"
        )

    if installation.get("repository_selection") != "selected":
        raise AuthError(
            "installation is not selected-repository scoped"
        )

    _exact_permissions(
        installation.get("permissions") or {},
        EXPECTED_INSTALLATION_PERMISSIONS,
        "installation",
    )

    requested = PURPOSE_PERMISSIONS[purpose]

    expected_token = {
        **requested,
        "metadata": "read",
    }

    token = None

    try:
        response = _request_json(
            "POST",
            (
                f"{API}/app/installations/"
                f"{installation_id}/access_tokens"
            ),
            jwt,
            {
                "repositories": [
                    EXPECTED_REPO
                ],
                "permissions": requested,
            },
        )

        token = response.get("token")

        if (
            not isinstance(token, str)
            or len(token) < 20
        ):
            raise AuthError(
                "installation token missing"
            )

        _exact_permissions(
            response.get("permissions") or {},
            expected_token,
            "token",
        )

        repos = _request_json(
            "GET",
            (
                f"{API}/installation/"
                "repositories?per_page=100"
            ),
            token,
        )

        rows = repos.get("repositories")

        if not isinstance(rows, list):
            raise AuthError(
                "repository list missing"
            )

        names = sorted(
            str(row.get("full_name"))
            for row in rows
            if isinstance(row, dict)
        )

        if repos.get("total_count") != 1:
            raise AuthError(
                "unexpected repository count"
            )

        if names != [
            "stebolainen/gneu-se"
        ]:
            raise AuthError(
                "repository scope mismatch"
            )

        return token

    except Exception:
        if token:
            try:
                revoke_token(token)
            except Exception:
                pass
        raise


def revoke_token(token: str) -> None:
    if (
        not isinstance(token, str)
        or len(token) < 20
    ):
        raise AuthError("invalid token object")

    req = urllib.request.Request(
        f"{API}/installation/token",
        method="DELETE",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "gneu-aihot-trusted-bridge/2.0",
        },
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=20,
        ):
            return

    except urllib.error.HTTPError as exc:
        raise AuthError(
            f"token revoke HTTP {exc.code}"
        ) from None

    except Exception as exc:
        raise AuthError(
            "token revoke failure: "
            + type(exc).__name__
        ) from None
