# AI-hot trusted READY processing recovery

This runbook covers one narrow trusted-runtime incident: an immutable `r1`
package passed the local handoff validator and has READY, but its first trusted
processing attempt was latched at `failed_stage=validate` solely because the
deployed `validate-intake.py` referenced an unimported `date` name. It does not
authorize content regeneration, a new package identity, replay recovery,
dispatch retry, or a general failed-package retry.

## Required evidence

Before deployment, preserve and record the exact candidate, handoff, report,
READY, and failed-receipt SHA-256 values. The original failed receipt must show
exactly one attempted stage, `validate`, with the bounded
`NameError: name 'date' is not defined` fingerprint at the tracked article-date
line. Processed and transport state must be absent. No process-ready instance
may be active, and the package must be an authorized `--r1` generation package.

Never delete, edit, move, rename, or overwrite the package, READY, original
failed receipt, generation authorization, or generation-consumed receipt.

## Deploy the fix first

Human-merge the Admin hotfix and provision that exact `origin/main` through
`runtime/aihot/provision.py`. Record the merge SHA. The operator tool verifies
the installed provenance, hashes of the validator, processor, and recovery
tools, and the presence of the fixed `datetime` article-date path.

## Authorize exactly one processing retry

Use independently recomputed evidence. The failed-receipt SHA selects and
derives the package identity; the caller cannot redirect recovery to a free
package ID.

```bash
/root/gneu-aihot-bridge/bin/authorize-ready-retry.py authorize \
  --failed-receipt-sha256 FAILED_SHA256 \
  --candidate-sha256 CANDIDATE_SHA256 \
  --handoff-sha256 HANDOFF_SHA256 \
  --report-sha256 REPORT_SHA256 \
  --ready-sha256 READY_SHA256 \
  --runtime-source-commit FIXED_MERGE_SHA \
  --reason VALIDATE_RUNTIME_DATE_IMPORT_ERROR
```

This creates, without overwrite:

`state/ready-retry/authorized/PACKAGE_ID.json`

Verify the authorization with the same hash and commit arguments, replacing
`authorize` with `verify` and omitting `--reason`.

## Consume through normal READY processing

Only after authorization verification, use the normal documented
`gneu-aihot-ready` service path. `process-ready.py` holds its existing lock,
re-verifies the original failed receipt and package hashes, verifies current
fixed-runtime provenance, and atomically creates:

`state/ready-retry/consumed/PACKAGE_ID.json`

It then starts again at `validate`, followed by build, canonical replay guard,
and dispatch. It never jumps to dispatch. Verify the consumed receipt with the
operator command `verify-consumed` and the same evidence arguments.

The authorization is exact-once. A consumed authorization can never start a
second processing run. If the run succeeds, the normal processed receipt binds
the original failed, authorization, and consumed hashes; the original failed
receipt remains immutable. Only that verified lineage permits failed and
processed state to coexist and return `ALREADY_PROCESSED`.

If the retry fails at any stage, the processor preserves the original failed
receipt and creates one append-only receipt at:

`state/ready-retry/failed/PACKAGE_ID.json`

No second retry is supported. Replay matches, content validation failures,
build failures, dispatch failures, changed evidence, stale provenance, or any
other failure require a new operator decision; never delete state to retry.
For the single terminal 2026-09-04 missing-evidence incident, that separate
decision is documented in
[`AIHOT_CONTENT_RETRY.md`](AIHOT_CONTENT_RETRY.md); READY processing itself is
never retried again.
