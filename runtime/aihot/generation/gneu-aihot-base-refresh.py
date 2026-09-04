#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff/inbox")
URL = "https://gneu.se/data/aihot.json"
MAX_BYTES = 5 * 1024 * 1024


def atomic(path: Path, payload: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    request = urllib.request.Request(
        URL,
        headers={
            "User-Agent": "gneu-aihot-adam-base/1.0 (+https://gneu.se)",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if int(getattr(response, "status", 200)) != 200:
            raise SystemExit("BASE_REFRESH_FAILED: unexpected HTTP status")
        raw = response.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise SystemExit("BASE_REFRESH_FAILED: invalid response size")
    try:
        data = json.loads(raw)
    except Exception:
        raise SystemExit("BASE_REFRESH_FAILED: invalid JSON")
    if not isinstance(data, dict) or set(data) != {"generated", "editions", "articles"}:
        raise SystemExit("BASE_REFRESH_FAILED: root schema mismatch")
    if not isinstance(data["editions"], list) or not isinstance(data["articles"], list):
        raise SystemExit("BASE_REFRESH_FAILED: arrays missing")
    digest = hashlib.sha256(raw).hexdigest()
    atomic(ROOT / "current.json", raw)
    atomic(ROOT / "current.sha256", (digest + "\n").encode())
    meta = {
        "schema": "gneu-aihot-base-v1",
        "source": URL,
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "sha256": digest,
        "generated": data.get("generated"),
        "edition_count": len(data["editions"]),
        "article_count": len(data["articles"]),
        "latest_edition": (
            data["editions"][-1].get("id")
            if data["editions"] and isinstance(data["editions"][-1], dict)
            else None
        ),
    }
    atomic(
        ROOT / "current.meta.json",
        (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode(),
    )
    print(json.dumps(meta, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
