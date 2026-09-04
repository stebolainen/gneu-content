# AI-hot runtime provenance contract

This directory is the source of truth for the AI-hot generator gate, handoff
validator, freshness probe, READY processor runtime, and Hermes schedule
contract.
The trusted source is the `main` branch of this repository. Technical changes
must use an `admin/*` branch and a pull request to `main`.

## Tracked runtime and installation paths

The deployable files listed in `manifest.sha256` map as follows:

- `bin/*.py` -> `/root/gneu-aihot-bridge/bin/*.py`
- `bin/aihot-content-schema.json` ->
  `/root/gneu-aihot-bridge/bin/aihot-content-schema.json`
- `generation/gneu-aihot-*.py` ->
  `/root/.hermes/profiles/gneu/scripts/gneu-aihot-*.py`
- `generation/CONTRACT.md` and `generation/ADAM_DAILY.md` ->
  `/root/.hermes/profiles/gneu/aihot-handoff/`
- `generation/hermes-scheduler.json` ->
  `/root/gneu-aihot-bridge/config/hermes-scheduler.json`
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
or outbox packages. Provisioning may install generator code and contracts, but
it never installs or edits inbox, outbox, claims, failed, rejected, processed,
or transport state.

The installed `aihot-content-schema.json` is the single machine-readable local
article contract. Its pure validator is shared by the generation handoff and
trusted local intake stages. Pinned fixtures capture the authoritative gneu-se
contract without adding a runtime network dependency. Adam must author every
required field, including evidence; bridge build/transport remains content
transparent and never backfills content.

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

The scheduler is a separate mutation and must be reconciled only after the
runtime installation and provenance checks pass:

```bash
/root/gneu-aihot-bridge/bin/configure-generation-scheduler.py check
/root/gneu-aihot-bridge/bin/configure-generation-scheduler.py install
/root/gneu-aihot-bridge/bin/configure-generation-scheduler.py check
```

The tracked Hermes contract uses `0 5,6 * * *` on the UTC Hermes host. The
tracked gate admits exactly one run at or after 07:00 Europe/Stockholm, so the
two UTC candidates cover CET and CEST. Hermes collapses missed recurring
occurrences to one catch-up and prevents an overlapping run of the same job.
The gate's atomic date claim adds a same-day deduplication boundary.

Public freshness is observable with:

```bash
/root/gneu-aihot-bridge/bin/aihot-freshness.py
```

It reports `STALE` and exits 2 when public `generated` is at least 26 hours old.

The daily gate's no-argument mode is exclusively the scheduler execution path.
These inspection forms are side-effect-free and never create a claim or resume
receipt:

```bash
/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py --help
/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py inspect
/root/.hermes/profiles/gneu/scripts/gneu-aihot-daily-gate.py check
```

Never delete a generation claim to retry. The only supported orphan recovery
is the append-only authorization and exact-once scheduler re-admission in
[`../../docs/AIHOT_CLAIM_RECOVERY.md`](../../docs/AIHOT_CLAIM_RECOVERY.md).

Never edit or delete a locally rejected daily package. The only supported
same-day correction is the append-only, operator-authorized `--r1` flow in
[`../../docs/AIHOT_LOCAL_RETRY.md`](../../docs/AIHOT_LOCAL_RETRY.md). Normal
scheduling creates revision zero only; revision 1 is consumed exactly once by
the same tracked Hermes job.

The only supported r2 is the incident-bound 2026-09-04 content-contract
correction in
[`../../docs/AIHOT_CONTENT_RETRY.md`](../../docs/AIHOT_CONTENT_RETRY.md). It
requires the exact immutable r1 and recovery hashes, the fixed evidence
contract, and operator-attested proof that remote validation failed before all
write steps. It is consumed once by the normal Hermes job. R3 and arbitrary r2
requests are rejected.

Never delete or overwrite a trusted READY failure to retry it. The only
supported processing recovery is the narrowly fingerprinted, append-only
authorization in
[`../../docs/AIHOT_READY_RECOVERY.md`](../../docs/AIHOT_READY_RECOVERY.md).
It applies only to the fixed validator `date` import defect, requires deployed
fixed-runtime provenance, re-enters at validate under the existing processor
lock, and permits exactly one attempt. Content, replay, build, dispatch and
arbitrary runtime failures are not authorizable by that mechanism.

Do not hand-edit installed runtime files. Correct tracked source through a new
Admin PR, merge it, and provision the exact verified merge commit.

## Daily attempt identity

Legacy `outbox/YYYY-Www` packages and their edition-keyed state remain valid
and immutable. Daily packages use `outbox/YYYY-Www--YYYY-MM-DD`; an authorized
local correction uses `outbox/YYYY-Www--YYYY-MM-DD--r1`, and the single
incident-bound correction uses `outbox/2026-W36--2026-09-04--r2`. The attempt
date must belong to the edition. Failed and processed state uses that complete
package ID, so rejection of a legacy W36 payload does not reject a different
W36 attempt. Before dispatch, every tracked rejection receipt is verified and
the decoded canonical payload hash is compared. An exact rejected-payload
replay is blocked even if copied under a new attempt name.

Research may inspect roughly seven days of sources, but candidate eligibility
is narrower: every new article date must belong to the supplied ISO edition.
Older events may be report context or supporting evidence, never new entries in
that edition. A successful no-change research run does not alter public
`generated`; research freshness and content-edition freshness remain separate.

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
