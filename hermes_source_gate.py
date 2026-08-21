#!/usr/bin/env python3
"""gneu-content 9.9.3 — deterministic source gate and non-minting auth status.

Hermes pre-run contract:
  {"wakeAgent": false}
or
  {"wakeAgent": true, "context": {...}}

When the agent is woken, this gate asks the sibling Adam GitHub App helper only
for local configuration status. It never creates a GitHub credential. The
policy-bound Adam adapter is the sole component allowed to mint a token, and it
does so only for one validated GitHub command.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat as stat_module
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

VERSION = "9.9.3"
FORCE_SWEEP_SECONDS = 6 * 60 * 60
ERROR_WAKE_THRESHOLD = 3
MAX_BODY_BYTES = 8 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 20

SOURCES = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cert-se": "https://www.cert.se/feed/atom.xml",
    "msrc": "https://api.msrc.microsoft.com/update-guide/rss",
}


def _now() -> int:
    return int(time.time())


def _state_path() -> Path:
    return Path("/root/.hermes/profiles/gneu/scripts/.gneu-content-source-gate-state.json")


def _empty_state() -> dict[str, Any]:
    return {
        "schema": "gneu-content-hermes-gate-v1",
        "version": VERSION,
        "sources": {},
        "last_agent_success_at": None,
        "last_check_at": None,
    }


class StateError(RuntimeError):
    """Persisted gate state cannot be trusted or safely interpreted."""


def _verify_state_parent(path: Path) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except OSError as exc:
        raise StateError("state directory is unavailable") from exc
    if (
        not stat_module.S_ISDIR(info.st_mode)
        or parent.is_symlink()
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise StateError("state directory is unsafe")


def load_state(path: Path) -> dict[str, Any]:
    _verify_state_parent(path)
    if not path.exists() and not path.is_symlink():
        return _empty_state()
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (
                not stat_module.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > 1_048_576
            ):
                raise StateError("state file is unsafe")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            obj = json.loads(b"".join(chunks).decode("utf-8"))
        finally:
            os.close(fd)
    except Exception as exc:
        if isinstance(exc, StateError):
            raise
        raise StateError("state is unreadable or malformed") from exc
    if not isinstance(obj, dict) or obj.get("schema") != "gneu-content-hermes-gate-v1":
        raise StateError("state schema is missing or invalid")
    obj.setdefault("sources", {})
    obj.setdefault("last_agent_success_at", None)
    obj.setdefault("last_check_at", None)
    obj["version"] = VERSION
    return obj


def save_state(path: Path, state: dict[str, Any]) -> None:
    _verify_state_parent(path)
    raw = json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        payload = raw.encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _acquire_state_lock(path: Path) -> int:
    _verify_state_parent(path)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    info = os.fstat(fd)
    if (
        not stat_module.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        os.close(fd)
        raise StateError("state lock is unsafe")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_source(source_id: str, url: str, baseline: dict[str, Any] | None) -> dict[str, Any]:
    headers = {
        "User-Agent": "gneu-content-watch/9.9.3 (+https://gneu.se)",
        "Accept": "application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.1",
        "Cache-Control": "no-cache",
    }
    if baseline:
        etag = str(baseline.get("etag") or "").strip()
        modified = str(baseline.get("last_modified") or "").strip()
        if etag:
            headers["If-None-Match"] = etag
        if modified:
            headers["If-Modified-Since"] = modified

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", 200))
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise RuntimeError(f"{source_id}: body exceeds {MAX_BODY_BYTES} bytes")
            return {
                "status": status,
                "sha256": _sha256(body),
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "content_length": len(body),
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return {"status": 304}
        raise RuntimeError(f"{source_id}: HTTP {exc.code}") from exc
    except Exception as exc:
        raise RuntimeError(f"{source_id}: {type(exc).__name__}: {exc}") from exc


def promote_pending(state: dict[str, Any], now: int) -> int:
    promoted = 0
    for source in state.get("sources", {}).values():
        if not isinstance(source, dict):
            continue
        pending = source.get("pending")
        if isinstance(pending, dict):
            source["baseline"] = pending
            source["pending"] = None
            promoted += 1
        source["consecutive_errors"] = 0
    state["last_agent_success_at"] = now
    return promoted


def _auth_helper() -> Path | None:
    here = Path(__file__).resolve().parent
    for name in ("gneu-content-adam-auth.py", "hermes_adam_auth.py"):
        p = here / name
        if p.is_file():
            return p
    return None


def _adam_adapter() -> Path | None:
    here = Path(__file__).resolve().parent
    for name in ("gneu-content-adam-github.py", "hermes_adam_github.py"):
        p = here / name
        if p.is_file():
            return p
    return None


def _safe_runtime_script(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        stat = path.lstat()
    except OSError:
        return False
    return bool(
        path.is_file()
        and not path.is_symlink()
        and stat.st_uid == os.geteuid()
        and not (stat.st_mode & 0o022)
        and os.access(path, os.X_OK)
    )


def check_agent_auth() -> dict[str, Any]:
    """Check local auth/adapter readiness without creating any credential."""
    helper = _auth_helper()
    adapter = _adam_adapter()
    if not _safe_runtime_script(helper):
        return {"status": "auth_required", "reason": "auth_helper_missing_or_unsafe"}
    if not _safe_runtime_script(adapter):
        return {"status": "auth_required", "reason": "credential_adapter_missing_or_unsafe"}
    assert helper is not None and adapter is not None
    try:
        cp = subprocess.run(
            ["/usr/bin/python3", "-I", str(helper), "status"],
            text=True,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin", "HERMES_HOME": str(helper.resolve().parent.parent)},
            shell=False,
            check=False,
            timeout=15,
        )
    except Exception:
        return {"status": "error", "reason": "auth_status_check_failed"}
    if cp.returncode != 0:
        return {"status": "error", "reason": "auth_status_check_failed"}
    try:
        status = json.loads(cp.stdout)
    except Exception:
        return {"status": "error", "reason": "auth_status_malformed"}
    value = status.get("status") if isinstance(status, dict) else None
    if value == "ready" and status.get("configured") is True:
        resolved = adapter.resolve()
        return {
            "status": "ready",
            "adapter": str(resolved),
            "invocation": f"/usr/bin/python3 -I {resolved} -- <allowlisted-command>",
        }
    if value == "auth_required":
        return {"status": "auth_required", "reason": "auth_configuration_invalid"}
    return {"status": "error", "reason": "auth_status_unknown"}


def attach_auth_status(result: dict[str, Any]) -> dict[str, Any]:
    """Attach auth readiness only to wake contexts; no-wake remains auth-free."""
    if result.get("wakeAgent") is True:
        result.setdefault("context", {})["auth"] = check_agent_auth()
    return result


def run_check(state: dict[str, Any], fetcher=fetch_source, now: int | None = None) -> dict[str, Any]:
    now = _now() if now is None else int(now)
    changed: list[str] = []
    errors: list[dict[str, str]] = []
    bootstrapped: list[str] = []

    sources_state = state.setdefault("sources", {})

    for source_id, url in SOURCES.items():
        src = sources_state.setdefault(source_id, {
            "url": url,
            "baseline": None,
            "pending": None,
            "consecutive_errors": 0,
            "last_checked_at": None,
            "last_error": None,
        })
        src["url"] = url
        src["last_checked_at"] = now

        baseline = src.get("baseline")
        try:
            result = fetcher(source_id, url, baseline if isinstance(baseline, dict) else None)
            src["consecutive_errors"] = 0
            src["last_error"] = None

            if result.get("status") == 304:
                continue

            snapshot = {
                "sha256": result["sha256"],
                "etag": result.get("etag"),
                "last_modified": result.get("last_modified"),
                "content_length": int(result.get("content_length", 0)),
                "observed_at": now,
            }

            if not isinstance(baseline, dict):
                src["baseline"] = snapshot
                src["pending"] = None
                bootstrapped.append(source_id)
                continue

            if snapshot["sha256"] == baseline.get("sha256"):
                # A previously observed change remains pending until verified ack,
                # even if the source later reverts to its baseline representation.
                if not isinstance(src.get("pending"), dict):
                    src["pending"] = None
                continue

            src["pending"] = snapshot
            changed.append(source_id)

        except Exception as exc:
            n = int(src.get("consecutive_errors") or 0) + 1
            src["consecutive_errors"] = n
            src["last_error"] = str(exc)[:300]
            if n >= ERROR_WAKE_THRESHOLD:
                errors.append({
                    "source": source_id,
                    "error": src["last_error"],
                    "consecutive": str(n),
                })

    state["last_check_at"] = now

    for source_id, src in sources_state.items():
        if isinstance(src, dict) and isinstance(src.get("pending"), dict) and source_id not in changed:
            changed.append(source_id)

    last_success = state.get("last_agent_success_at")
    safety_sweep = last_success is None or now - int(last_success) >= FORCE_SWEEP_SECONDS
    first_bootstrap = bool(bootstrapped) and last_success is None and not changed and not errors
    wake = bool(changed or errors or (safety_sweep and not first_bootstrap))

    if not wake:
        return {
            "wakeAgent": False,
            "context": {
                "gate_version": VERSION,
                "reason": "baseline_bootstrap" if first_bootstrap else "no_source_change",
                "checked_sources": list(SOURCES.keys()),
            },
        }

    reasons: list[str] = []
    if changed:
        reasons.append("source_change")
    if errors:
        reasons.append("source_error_threshold")
    if safety_sweep and not changed and not errors:
        reasons.append("six_hour_safety_sweep")

    return {
        "wakeAgent": True,
        "context": {
            "gate_version": VERSION,
            "reason": ",".join(reasons),
            "changed_sources": sorted(changed),
            "error_sources": errors,
            "instruction": (
                "Run the normal remote-first gneu-content-watch cycle. "
                "Before creating any branch, require context.auth.status=ready. "
                "If the cycle finishes successfully, acknowledge the gate with "
                f"python3 {Path(__file__).resolve()} --ack"
            ),
        },
    }


def _state_failure(ack: bool, exc: Exception) -> int:
    if ack:
        print(json.dumps({"ack": False, "reason": "state_corrupt"}, separators=(",", ":")))
        return 2
    print(json.dumps({
        "wakeAgent": True,
        "context": {
            "gate_version": VERSION,
            "reason": "state_corrupt",
            "auth": {"status": "unknown"},
            "error": f"{type(exc).__name__}: {exc}"[:300],
        },
    }, ensure_ascii=False, separators=(",", ":")))
    return 0


def _run_locked(path: Path, ack: bool, now: int) -> int:
    try:
        state = load_state(path)
    except StateError as exc:
        return _state_failure(ack, exc)

    if ack:
        promoted = promote_pending(state, now)
        state["last_check_at"] = state.get("last_check_at") or now
        save_state(path, state)
        print(json.dumps({
            "ack": True,
            "promoted": promoted,
            "version": VERSION,
        }, ensure_ascii=False, separators=(",", ":")))
        return 0

    try:
        result = run_check(state, now=now)
        attach_auth_status(result)
        save_state(path, state)
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({
            "wakeAgent": True,
            "context": {
                "gate_version": VERSION,
                "reason": "gate_internal_error",
                "auth": {"status": "unknown"},
                "error": f"{type(exc).__name__}: {exc}"[:300],
            },
        }, ensure_ascii=False, separators=(",", ":")))
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ack", action="store_true", help="ack a verified successful agent cycle")
    args = parser.parse_args()

    path = _state_path()
    try:
        lock_fd = _acquire_state_lock(path)
    except StateError as exc:
        return _state_failure(args.ack, exc)
    try:
        return _run_locked(path, args.ack, _now())
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
