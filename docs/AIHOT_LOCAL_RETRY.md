# AI-hot local validation retry

This runbook covers one narrow recovery: a daily revision-zero package exists,
the tracked local handoff validator reproducibly rejected it with
`ARTICLE_DATE_OUTSIDE_EDITION`, and no READY or downstream trusted state was
created. The source package is immutable evidence and is never retried in
place.

## Required evidence

Record the revision-zero package ID, candidate, handoff and report SHA-256, and
the terminal Hermes execution ID. Verify that the package contains exactly
`candidate.json`, `handoff.json`, and `report.md`; READY, processed, failed and
transport state must all be absent. The execution ledger must be terminal, no
AI-hot generation may be active, and its bounded output must identify the same
package and local date-validation failure.

Never delete, rename, move, overwrite, or edit revision zero. Never create a
retry merely because a run is old. A retry is operator-authorized only, on the
same Europe/Stockholm calendar day, and only revision 1 is supported.

## Authorize revision 1

Run the root-only tool with independently recomputed evidence:

```bash
/root/gneu-aihot-bridge/bin/authorize-local-retry.py authorize \
  --attempt YYYY-MM-DD \
  --source-candidate-sha256 CANDIDATE_SHA256 \
  --source-handoff-sha256 HANDOFF_SHA256 \
  --source-report-sha256 REPORT_SHA256 \
  --hermes-execution-id TERMINAL_EXECUTION_ID \
  --reason ARTICLE_DATE_OUTSIDE_EDITION
```

The tool derives edition, source package, target
`YYYY-Www--YYYY-MM-DD--r1`, and revision. It independently reproduces the
local failure and creates, without overwrite:

`state/generation/retry-authorized/YYYY-MM-DD-r1.json`

Verify it before triggering Hermes:

```bash
/root/gneu-aihot-bridge/bin/authorize-local-retry.py verify \
  --attempt YYYY-MM-DD \
  --source-candidate-sha256 CANDIDATE_SHA256 \
  --source-handoff-sha256 HANDOFF_SHA256 \
  --source-report-sha256 REPORT_SHA256
```

## Consume through the normal scheduler job

Run the existing job exactly once:

```bash
hermes cron run fbd796dbb875
```

The normal gate consumes the authorization under the generation lock, creates
`state/generation/retry-consumed/YYYY-MM-DD-r1.json`, and emits one
`wakeAgent=true` context with reason `operator_local_retry`, revision `1`, and
the derived `--r1` package ID. A later gate call returns
`retry_already_consumed`; there is no timeout retry.

Verify consumption:

```bash
/root/gneu-aihot-bridge/bin/authorize-local-retry.py verify-consumed \
  --attempt YYYY-MM-DD \
  --source-candidate-sha256 CANDIDATE_SHA256 \
  --source-handoff-sha256 HANDOFF_SHA256 \
  --source-report-sha256 REPORT_SHA256
```

Follow the new package through the ordinary validator, READY processor, replay
guard, trusted intake, and publication gates. This local-validation recovery
never synthesizes r2. The only r2 exception is the separately reviewed,
incident-bound content-contract procedure in
[`AIHOT_CONTENT_RETRY.md`](AIHOT_CONTENT_RETRY.md); it is not a continuation
of this generic flow.

If READY exists and trusted processing is latched by the specifically verified
validator import defect, do not regenerate content or alter the failed receipt.
The distinct, post-hotfix trusted-processing procedure is documented in
[`AIHOT_READY_RECOVERY.md`](AIHOT_READY_RECOVERY.md).

## No-change and freshness

A successful no-change run proves that daily research occurred, but the
append-only public content contract leaves public `generated` unchanged.
Consequently content-edition freshness may remain stale even though research
freshness is current. This is a separate observability/product-semantics gap;
do not mutate `generated` or fabricate an edition through this recovery.
