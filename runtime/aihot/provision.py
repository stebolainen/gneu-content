#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "runtime/aihot/manifest.sha256"
RUNTIME_ROOT = Path("/root/gneu-aihot-bridge")
OUTBOX_ROOT = Path("/root/.hermes/profiles/gneu/aihot-handoff/outbox")
PROVENANCE_PATH = RUNTIME_ROOT / "PROVENANCE.json"
DEFAULT_STAGE_PARENT = Path("/var/tmp")

INSTALL_SPECS = {
    "runtime/aihot/bin/aihot_rejection.py": (
        RUNTIME_ROOT / "bin/aihot_rejection.py",
        0o600,
    ),
    "runtime/aihot/bin/operator-disposition.py": (
        RUNTIME_ROOT / "bin/operator-disposition.py",
        0o700,
    ),
    "runtime/aihot/bin/process-ready.py": (
        RUNTIME_ROOT / "bin/process-ready.py",
        0o700,
    ),
    "runtime/aihot/bin/validate-intake.py": (
        RUNTIME_ROOT / "bin/validate-intake.py",
        0o700,
    ),
    "runtime/aihot/bin/build-intake-payload.py": (
        RUNTIME_ROOT / "bin/build-intake-payload.py",
        0o700,
    ),
    "runtime/aihot/bin/dispatch-trusted-intake.py": (
        RUNTIME_ROOT / "bin/dispatch-trusted-intake.py",
        0o700,
    ),
    "runtime/aihot/bin/github_auth.py": (
        RUNTIME_ROOT / "bin/github_auth.py",
        0o600,
    ),
    "runtime/aihot/bin/github-adapter.py": (
        RUNTIME_ROOT / "bin/github-adapter.py",
        0o700,
    ),
    "runtime/aihot/bin/aihot-freshness.py": (
        RUNTIME_ROOT / "bin/aihot-freshness.py",
        0o700,
    ),
    "runtime/aihot/bin/configure-generation-scheduler.py": (
        RUNTIME_ROOT / "bin/configure-generation-scheduler.py",
        0o700,
    ),
    "runtime/aihot/generation/gneu-aihot-daily-gate.py": (
        Path("/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py"),
        0o700,
    ),
    "runtime/aihot/generation/gneu-aihot-base-refresh.py": (
        Path("/root/.hermes/profiles/gneu/scripts/gneu-aihot-base-refresh.py"),
        0o700,
    ),
    "runtime/aihot/generation/gneu-aihot-handoff-validate.py": (
        Path("/root/.hermes/profiles/gneu/scripts/gneu-aihot-handoff-validate.py"),
        0o700,
    ),
    "runtime/aihot/generation/CONTRACT.md": (
        Path("/root/.hermes/profiles/gneu/aihot-handoff/CONTRACT.md"),
        0o600,
    ),
    "runtime/aihot/generation/ADAM_DAILY.md": (
        Path("/root/.hermes/profiles/gneu/aihot-handoff/ADAM_DAILY.md"),
        0o600,
    ),
    "runtime/aihot/generation/hermes-scheduler.json": (
        RUNTIME_ROOT / "config/hermes-scheduler.json",
        0o600,
    ),
    "runtime/aihot/systemd/gneu-aihot-ready.service": (
        Path("/etc/systemd/system/gneu-aihot-ready.service"),
        0o644,
    ),
    "runtime/aihot/systemd/gneu-aihot-ready.timer": (
        Path("/etc/systemd/system/gneu-aihot-ready.timer"),
        0o644,
    ),
}

FORBIDDEN_ROOTS = (
    RUNTIME_ROOT / "state",
    RUNTIME_ROOT / "credentials",
    OUTBOX_ROOT,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ProvisionError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProvisionError(f"not a regular non-symlink file: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_within(path: Path, root: Path) -> bool:
    path_abs = Path(os.path.abspath(path))
    root_abs = Path(os.path.abspath(root))
    try:
        path_abs.relative_to(root_abs)
    except ValueError:
        return False
    return True


def reject_symlink_components(root: Path, relative: str) -> Path:
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ProvisionError(f"symlink forbidden: {candidate}")
    return candidate


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ProvisionError("manifest must be a regular non-symlink file")

    entries: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        parts = raw.split()
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
            raise ProvisionError(f"invalid manifest line {number}")
        relative = parts[1]
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in entries:
            raise ProvisionError(f"unsafe or duplicate manifest path: {relative}")
        entries[relative] = parts[0]
    return entries


def require_allowed_destinations(specs=INSTALL_SPECS) -> None:
    for _, (destination, mode) in specs.items():
        if not isinstance(mode, int) or mode & ~0o777:
            raise ProvisionError(f"invalid explicit mode for {destination}")
        if any(is_within(destination, forbidden) for forbidden in FORBIDDEN_ROOTS):
            raise ProvisionError(f"forbidden destination: {destination}")


def verify_sources(
    root: Path,
    manifest: dict[str, str],
    specs=INSTALL_SPECS,
) -> dict[str, str]:
    if set(manifest) != set(specs):
        missing = sorted(set(specs) - set(manifest))
        extra = sorted(set(manifest) - set(specs))
        raise ProvisionError(f"manifest coverage mismatch missing={missing} extra={extra}")

    require_allowed_destinations(specs)
    verified: dict[str, str] = {}
    for relative in sorted(specs):
        source = reject_symlink_components(root, relative)
        actual = sha256_file(source)
        if actual != manifest[relative]:
            raise ProvisionError(f"source hash mismatch: {relative}")
        verified[relative] = actual
    return verified


def git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def require_trusted_checkout(root: Path = REPO_ROOT) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ProvisionError("source root must be a regular directory")

    try:
        top = Path(git_output(root, "rev-parse", "--show-toplevel")).resolve()
        head = git_output(root, "rev-parse", "HEAD")
        trusted = git_output(root, "rev-parse", "origin/main")
        dirty = git_output(root, "status", "--porcelain")
    except subprocess.CalledProcessError as exc:
        raise ProvisionError("source checkout Git verification failed") from exc

    if top != root.resolve():
        raise ProvisionError("source root is not repository top level")
    if not COMMIT_RE.fullmatch(head) or head != trusted:
        raise ProvisionError("HEAD is not exact origin/main")
    if dirty:
        raise ProvisionError("source checkout is not clean")
    return head


def require_separate_stage_parent(stage_parent: Path, source_root: Path) -> None:
    stage = Path(os.path.abspath(stage_parent))
    forbidden_stage_roots = (
        Path(os.path.abspath(source_root)),
        RUNTIME_ROOT,
        Path("/etc/systemd/system"),
        *FORBIDDEN_ROOTS,
    )
    if any(is_within(stage, root) or is_within(root, stage) for root in forbidden_stage_roots):
        raise ProvisionError("staging parent is not separate from source/live paths")


def stage_sources(
    source_root: Path,
    manifest: dict[str, str],
    stage_parent: Path = DEFAULT_STAGE_PARENT,
    specs=INSTALL_SPECS,
) -> Path:
    require_separate_stage_parent(stage_parent, source_root)
    stage_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="gneu-aihot-stage.", dir=stage_parent))
    try:
        for relative, (_, mode) in specs.items():
            source = reject_symlink_components(source_root, relative)
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target, follow_symlinks=False)
            os.chmod(target, mode)
            if sha256_file(target) != manifest[relative]:
                raise ProvisionError(f"staged hash mismatch: {relative}")
        return stage
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_install(source: Path, destination: Path, mode: int) -> None:
    if destination.is_symlink():
        raise ProvisionError(f"destination symlink forbidden: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ProvisionError(f"destination parent symlink forbidden: {destination.parent}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_provenance(
    source_commit: str,
    manifest_hash: str,
    installed_hashes: dict[str, str],
    installed_at: str | None = None,
    specs=INSTALL_SPECS,
) -> dict:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ProvisionError("invalid source commit")
    if not SHA256_RE.fullmatch(manifest_hash):
        raise ProvisionError("invalid manifest hash")
    return {
        "schema": "gneu-aihot-runtime-provenance-v1",
        "source_commit": source_commit,
        "manifest_sha256": manifest_hash,
        "installed_at": installed_at or dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat(),
        "files": {
            relative: {
                "destination": str(specs[relative][0]),
                "mode": format(specs[relative][1], "04o"),
                "sha256": installed_hashes[relative],
            }
            for relative in sorted(specs)
        },
    }


def write_atomic_json(path: Path, value: dict, mode: int = 0o600) -> None:
    if any(is_within(path, forbidden) for forbidden in FORBIDDEN_ROOTS):
        raise ProvisionError(f"provenance destination forbidden: {path}")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def install(stage: Path, manifest: dict[str, str], source_commit: str) -> None:
    if os.geteuid() != 0:
        raise ProvisionError("installation requires root")

    installed: dict[str, str] = {}
    for relative, (destination, mode) in INSTALL_SPECS.items():
        staged = reject_symlink_components(stage, relative)
        if sha256_file(staged) != manifest[relative]:
            raise ProvisionError(f"staged source changed: {relative}")
        atomic_install(staged, destination, mode)
        actual = sha256_file(destination)
        metadata = destination.stat()
        if actual != manifest[relative]:
            raise ProvisionError(f"destination hash mismatch: {destination}")
        if stat.S_IMODE(metadata.st_mode) != mode or metadata.st_uid != 0 or metadata.st_gid != 0:
            raise ProvisionError(f"destination ownership/mode mismatch: {destination}")
        installed[relative] = actual

    provenance = build_provenance(
        source_commit,
        sha256_file(MANIFEST_PATH),
        installed,
    )
    write_atomic_json(PROVENANCE_PATH, provenance)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify or install AI-hot runtime")
    parser.add_argument("action", choices=("check", "install"))
    parser.add_argument("--restart-services", action="store_true")
    args = parser.parse_args(argv)
    if args.restart_services and args.action != "install":
        parser.error("--restart-services requires install")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_commit = require_trusted_checkout(REPO_ROOT)
    manifest = load_manifest(MANIFEST_PATH)
    verified = verify_sources(REPO_ROOT, manifest)
    print(f"AIHOT_RUNTIME_SOURCE_VERIFIED commit={source_commit} files={len(verified)}")

    if args.action == "check":
        return 0

    stage = stage_sources(REPO_ROOT, manifest)
    try:
        install(stage, manifest, source_commit)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    if args.restart_services:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "restart", "gneu-aihot-ready.timer"], check=True
        )
    print(f"AIHOT_RUNTIME_INSTALLED commit={source_commit}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProvisionError as exc:
        raise SystemExit(f"BLOCKED: {exc}")
