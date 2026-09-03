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

`manifest.sha256` covers only deployable runtime files. This includes
`operator-disposition.py` and its shared `aihot_rejection.py` verifier. It does
not cover documentation, tests, the provisioner itself, state, credentials,
or outbox packages.

`rejection-receipt.schema.json` is the tracked contract for rejection receipts;
it is not installed into runtime. A receipt is runtime state, never source.

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

## Rejection disposition

After this change is reviewed, merged, and separately provisioned, the runtime
supports an explicit, offline operator transition from a latched
`FAILED_REQUIRES_OPERATOR` package to a terminal rejection receipt. The only
initial allowlisted reason is `ARTICLE_DATE_OUTSIDE_EDITION`. The tool
recomputes the ISO calendar week with
`date.fromisoformat(article.date).isocalendar()` and binds the operation to the
exact failed latch, package files, transport, decoded canonical payload,
base-main SHA, workflow run, and first failing article.

The tool never deletes or changes the failed latch, READY package, transport,
payload, or content. It creates only `state/rejected/<edition>.json`, using an
atomic create-without-overwrite. It does not use GitHub credentials. See
[`../../docs/AIHOT_OPERATOR_RECOVERY.md`](../../docs/AIHOT_OPERATOR_RECOVERY.md)
for the required remote review and operator procedure.
