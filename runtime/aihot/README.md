# AI-hot runtime provenance contract

This directory is the source of truth for the AI-hot READY processor runtime.
The trusted source is the `main` branch of this repository. Technical changes
must use an `admin/*` branch and a pull request to `main`.

## Tracked runtime and installation paths

The deployable files listed in `manifest.sha256` map as follows:

- `bin/*.py` -> `/root/gneu-aihot-bridge/bin/*.py`
- `systemd/gneu-aihot-ready.service` ->
  `/etc/systemd/system/gneu-aihot-ready.service`
- `systemd/gneu-aihot-ready.timer` ->
  `/etc/systemd/system/gneu-aihot-ready.timer`

The runtime install root is `/root/gneu-aihot-bridge`. The systemd units live
outside that root at the paths above.

## Runtime data is never provisioned from Git

The following are runtime data and must never be copied from, committed to, or
deleted by this source tree or its provisioner:

- `/root/gneu-aihot-bridge/state/`
- `/root/gneu-aihot-bridge/credentials/`
- `/root/.hermes/profiles/gneu/aihot-handoff/outbox/`

`manifest.sha256` covers only the eight deployable runtime files. It does not
cover documentation, tests, the provisioner itself, state, credentials, or
outbox packages.

## Provisioning contract

Provisioning is allowed only after merge from a clean checkout whose `HEAD`
equals the fetched `origin/main`. Before installation, `provision.py` verifies
the source commit, the complete manifest, every source hash, regular-file
status, and the absence of symlinks. It stages the complete payload outside
the live runtime and installs each allowlisted destination with an atomic
replace and an explicit owner/mode.

After installation it verifies each destination hash and writes
`/root/gneu-aihot-bridge/PROVENANCE.json` containing the source commit,
manifest hash, installation timestamp, and installed file hashes. A service
reload/restart is never implicit and requires the explicit
`--restart-services` flag.

Validation only:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 runtime/aihot/provision.py check
```

Installation is intentionally not part of a PR/bootstrap session. A later,
separately authorised post-merge session may use:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 runtime/aihot/provision.py install
```

Do not hand-edit installed runtime files. Correct tracked source through a new
Admin PR, merge it, and provision the exact verified merge commit.

W36 operator recovery and rejected/disposition semantics are deliberately out
of scope here and are not defined by this bootstrap.
