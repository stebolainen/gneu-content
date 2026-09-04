#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROVISION_PATH = ROOT / "runtime" / "aihot" / "provision.py"
SPEC = importlib.util.spec_from_file_location("aihot_provision", PROVISION_PATH)
assert SPEC is not None and SPEC.loader is not None
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


manifest = PROVISION.load_manifest()
assert set(manifest) == set(PROVISION.INSTALL_SPECS), "manifest lacks runtime files"
verified = PROVISION.verify_sources(ROOT, manifest)
assert verified == manifest, "tracked runtime hashes do not match manifest"

expected_modes = {
    "runtime/aihot/bin/aihot_rejection.py": 0o600,
    "runtime/aihot/bin/operator-disposition.py": 0o700,
    "runtime/aihot/bin/process-ready.py": 0o700,
    "runtime/aihot/bin/validate-intake.py": 0o700,
    "runtime/aihot/bin/build-intake-payload.py": 0o700,
    "runtime/aihot/bin/dispatch-trusted-intake.py": 0o700,
    "runtime/aihot/bin/github_auth.py": 0o600,
    "runtime/aihot/bin/github-adapter.py": 0o700,
    "runtime/aihot/bin/aihot-freshness.py": 0o700,
    "runtime/aihot/bin/configure-generation-scheduler.py": 0o700,
    "runtime/aihot/bin/aihot_claim_resume.py": 0o600,
    "runtime/aihot/bin/authorize-generation-resume.py": 0o700,
    "runtime/aihot/bin/aihot_local_retry.py": 0o600,
    "runtime/aihot/bin/aihot_package_identity.py": 0o600,
    "runtime/aihot/bin/authorize-local-retry.py": 0o700,
    "runtime/aihot/bin/aihot_ready_retry.py": 0o600,
    "runtime/aihot/bin/authorize-ready-retry.py": 0o700,
    "runtime/aihot/generation/gneu-aihot-daily-gate.py": 0o700,
    "runtime/aihot/generation/gneu-aihot-base-refresh.py": 0o700,
    "runtime/aihot/generation/gneu-aihot-handoff-validate.py": 0o700,
    "runtime/aihot/generation/CONTRACT.md": 0o600,
    "runtime/aihot/generation/ADAM_DAILY.md": 0o600,
    "runtime/aihot/generation/hermes-scheduler.json": 0o600,
    "runtime/aihot/systemd/gneu-aihot-ready.service": 0o644,
    "runtime/aihot/systemd/gneu-aihot-ready.timer": 0o644,
}
assert {key: value[1] for key, value in PROVISION.INSTALL_SPECS.items()} == expected_modes

for relative, (destination, _) in PROVISION.INSTALL_SPECS.items():
    assert "state" not in Path(relative).parts
    assert "credentials" not in Path(relative).parts
    assert not any(
        PROVISION.is_within(destination, forbidden)
        for forbidden in PROVISION.FORBIDDEN_ROOTS
    ), f"forbidden destination included: {destination}"

with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    source_root = temp / "source"
    source = source_root / "runtime/aihot/bin/example.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"example\n")
    relative = "runtime/aihot/bin/example.py"
    specs = {relative: (temp / "destination/example.py", 0o700)}
    good_manifest = {relative: digest(source.read_bytes())}

    try:
        PROVISION.verify_sources(source_root, {relative: "0" * 64}, specs)
    except PROVISION.ProvisionError:
        pass
    else:
        raise AssertionError("source hash mismatch was accepted")

    source.unlink()
    target = temp / "target.py"
    target.write_bytes(b"example\n")
    source.symlink_to(target)
    try:
        PROVISION.verify_sources(source_root, good_manifest, specs)
    except PROVISION.ProvisionError:
        pass
    else:
        raise AssertionError("symlink source was accepted")

    source.unlink()
    source.write_bytes(b"example\n")
    separate_stage = temp / "stage"
    separate_stage.mkdir()
    stage = PROVISION.stage_sources(
        source_root,
        good_manifest,
        separate_stage,
        specs,
    )
    try:
        assert not PROVISION.is_within(stage, source_root)
        assert not PROVISION.is_within(stage, PROVISION.RUNTIME_ROOT)
        assert (stage / relative).read_bytes() == b"example\n"
        assert os.stat(stage / relative).st_mode & 0o777 == 0o700
    finally:
        import shutil

        shutil.rmtree(stage)

try:
    PROVISION.require_allowed_destinations(
        {"bad": (PROVISION.RUNTIME_ROOT / "state/bad", 0o600)}
    )
except PROVISION.ProvisionError:
    pass
else:
    raise AssertionError("state destination was accepted")

try:
    PROVISION.require_allowed_destinations(
        {"bad": (PROVISION.RUNTIME_ROOT / "credentials/bad", 0o600)}
    )
except PROVISION.ProvisionError:
    pass
else:
    raise AssertionError("credential destination was accepted")

provenance = PROVISION.build_provenance(
    "a" * 40,
    "b" * 64,
    manifest,
    installed_at="2026-09-03T00:00:00+00:00",
)
assert provenance["source_commit"] == "a" * 40
assert provenance["manifest_sha256"] == "b" * 64
assert set(provenance["files"]) == set(PROVISION.INSTALL_SPECS)

receipt_schema = json.loads(
    (ROOT / "runtime/aihot/rejection-receipt.schema.json").read_text()
)
assert receipt_schema["properties"]["schema"]["const"] == "gneu-aihot-rejection-v1"
assert receipt_schema["properties"]["disposition"]["const"] == "rejected"
assert set(receipt_schema["required"]) == set(receipt_schema["properties"])

print("AI-hot runtime provenance tests OK")
