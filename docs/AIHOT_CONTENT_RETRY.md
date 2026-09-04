# AI-hot incident-bound r2 correction

This runbook covers one terminal content-contract incident only. The immutable
package `2026-W36--2026-09-04--r1` reached trusted intake run `33874811080`,
where validation failed exactly because `evidence` was missing. Token
preparation, scope verification, and constrained repository write were all
skipped. No repository write occurred.

R2 is a fresh generation, not a redelivery or edit. Never change r1, its READY,
its local retry lineage, its READY-retry lineage, its transport, or its failed
receipts. Never rerun the old workflow. Never create r3.

## Required preflight

1. Use the sanitized `gneu-admin-github gneu-se-read` operations to reverify
   run `33874811080`, head `4bb9ba39c74323a158460295ab04923c6d9fa53d`,
   failed `Validate transported intake`, and every skipped credential/write
   step. The operator performs this remote verification; the offline tool
   records it as an attestation and does not claim network verification.
2. Fetch Admin main and provision the exact human-merged r2 runtime with
   `runtime/aihot/provision.py`. Record that merge SHA.
3. Require the same Europe/Stockholm day, no active generator, the exact source
   and lineage hashes, the #71 schema fingerprint, and complete absence of r2
   package or downstream state.

## Authorize once

From the provisioned runtime, run exactly once:

```text
/root/gneu-aihot-bridge/bin/authorize-content-retry.py authorize \
  --attempt 2026-09-04 \
  --runtime-source-commit R2_MERGE_SHA \
  --reason TRUSTED_CONTENT_CONTRACT_MISSING_EVIDENCE
```

Then verify without mutation:

```text
/root/gneu-aihot-bridge/bin/authorize-content-retry.py verify \
  --attempt 2026-09-04 \
  --runtime-source-commit R2_MERGE_SHA
```

The receipt is canonical root:root 0600 state under
`state/generation/retry-authorized/2026-09-04-r2.json`. It is bound to the
derived r2 target; callers cannot supply another package ID.

Run the normal Hermes job exactly once:

```text
hermes cron run fbd796dbb875
```

The gate consumes the authorization under the generation lock and writes
`state/generation/retry-consumed/2026-09-04-r2.json` without overwrite. Verify:

```text
/root/gneu-aihot-bridge/bin/authorize-content-retry.py verify-consumed \
  --attempt 2026-09-04 \
  --runtime-source-commit R2_MERGE_SHA
```

Expected gate context is `reason=operator_content_contract_retry`,
`revision=2`, and `package_id=2026-W36--2026-09-04--r2`. A subsequent gate
call must return `content_retry_already_consumed`; a second wake is forbidden.
The ordinary handoff validator, READY processor, content-transparent build,
replay guard, and trusted intake remain mandatory. Tomorrow's normal daily
identity remains revision zero.
