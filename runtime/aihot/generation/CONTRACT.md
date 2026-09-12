# GNEU AI-hot daily handoff v2

The AI-hot generator runs once per Stockholm calendar day after 07:00. It has
no GitHub or production credential. Its only output is an untrusted package
for the separately provisioned trusted READY processor.

The gate supplies an ISO edition, an attempt date and a package ID:

`YYYY-Www--YYYY-MM-DD`

An operator-authorized correction of a locally rejected daily package uses
`YYYY-Www--YYYY-MM-DD--r1`. The single incident-bound content correction uses
`2026-W36--2026-09-04--r2`. Revision zero is the normal daily identity and is
never renamed or changed. The scheduler never creates a revision automatically;
`r3` or later revisions are invalid.

The date must belong to the edition's ISO week. A legacy package named only
`YYYY-Www` remains valid, but is immutable historical evidence. A daily
attempt must never overwrite, delete, move or add files to a legacy package.

Before research, run the tracked base refresh script and use exactly
`inbox/current.json`. Create exactly these files in `outbox/PACKAGE_ID/`:

- `handoff.json`
- `candidate.json`
- `report.md`

The handoff is `gneu-aihot-handoff-v2` and contains the existing v1 fields plus
`"attempt": "YYYY-MM-DD"`. An r1 or r2 handoff also contains the exact numeric
`revision`.
Adam never creates `READY`; the tracked validator
creates it atomically after validation. Existing READY, failed, rejected,
processed or generation-claim state must never be deleted or overwritten.

A generation claim is also immutable. An orphaned claim may be re-admitted
only by the separately documented, append-only operator authorization. The
only automatic exception is one same-day fallback after the trusted Hermes
execution ledger records the primary invocation's exact
`usage_limit_reached`/HTTP 429 provider failure before research or any package,
intake or publication state exists. The gate binds that fallback to the claim
and both execution IDs plus the initial provider-request evidence hash in a
create-without-overwrite receipt before waking the agent. A second provider
failure is terminal. There is no age-, timeout- or other failure-class retry.

The content contract remains append-only. If the current edition is absent,
mode `edition` adds exactly one edition and 1–6 articles. If the current
edition already exists, mode `current-week-append` may append 1–6 new articles
only when that edition is the latest trusted edition and the current ISO week in
Europe/Stockholm. Its edition delta is empty; existing editions and articles
remain byte/object-identical prefixes, and every appended article has a unique
ID, points to that edition, and has a date in its ISO week. After the ISO week
ends, this mode is rejected locally for that candidate. It is forwarded as a
human-review shape; it does not authorize a merge. If there is no publishable
new material, mode `no-change` contains no delta and the report still records
that day's research. Top-level `generated` is never changed by Adam.

The canonical daily package identity is already `YYYY-Www--YYYY-MM-DD`.
Handoff v2 binds its `edition` and `attempt`; the bridge transports that exact
`package_id` and `attempt` with a current-week append so a downstream trusted
writer can later create distinct review artefacts without inventing identity.

Every new article must satisfy the complete machine-readable contract installed
as `/root/gneu-aihot-bridge/bin/aihot-content-schema.json`. In particular, the
article key set is exact and `evidence` is mandatory. Evidence is original
content authored by Adam from the research: it records the allowed grade,
verification method, a non-empty basis, and optional source-bound claims. Adam
must create it before writing `candidate.json`. The bridge must never invent,
derive, synthesize, backfill, or enrich evidence or any other article field.
If adequate evidence cannot be authored, exclude the article; if no qualifying
articles remain, create a strict `no-change` package.

## Reader-context check (pre-handoff only)

Before creating an outbox package, Adam runs the state-free
`gneu-aihot-reader-context.py` check on every proposed new article. It reports
exactly `reader_context_actor_terms`, `reader_context_standalone` and
`reader_context_distinct_fields` as `PASS` or `REWRITE`. It is an editorial
authoring check, not part of READY validation, retry authorization, release,
fast lane, timer or service state.

On `REWRITE`, Adam may make one editorial rewrite of that article only, then
runs the same three checks again. The rewrite may clarify existing facts and
remove repetition, but must not change sources, evidence (including claims),
severity, dates or factual scope. If any check remains `REWRITE`, mark that
candidate `EDITORIAL_REVIEW_REQUIRED` and create no outbox package or PR for
it. Do not create a latch, receipt, retry authorization or historical state;
the next daily package remains independent. `no-change` bypasses this check.

The research window and candidate eligibility are separate rules. Research
normally looks back approximately seven days and may use earlier events as
background, report context, or supporting sources. Every article entry added
to an edition candidate must, however, have an article date whose ISO year and
week exactly match the supplied edition. Before writing the candidate, Adam
must evaluate `date.fromisoformat(article_date).isocalendar()` for every
proposed article and exclude any entry outside that edition. The validator
repeats this check fail-closed and is never weakened by operator retry.

An `r1` run is a fresh generation from the refreshed public baseline and
current sources. It must never copy, edit, overwrite, or delete the revision-0
package. If no qualifying material exists, it produces the normal strict
`no-change` result; content must never be fabricated for freshness.

The r2 identity is not a general retry tier. It is admitted only by the
append-only, exact-once operator authorization for the immutable 2026-09-04 r1
whose trusted intake failed on missing evidence before every credential and
write step. R2 performs fresh research from the refreshed baseline and authors
the complete trusted article schema, including evidence. It never copies or
edits r1, and its article dates may not be later than the local run date. Its
only valid gate context has `reason=operator_content_contract_retry` and
`revision=2`. The
ordinary scheduler remains revision-zero-only.

The trusted bridge transports only a validated delta, rebinds it to current
gneu-se `main`, and dispatches the existing trusted intake. A rejection receipt
continues to terminate its exact legacy payload. A daily attempt is independent,
but a canonical payload hash matching any verified rejection is blocked as a
replay before dispatch.

The schema provenance is pinned to `stebolainen/gneu-se`,
`scripts/aihot_intake_validate.py` at the ref and fingerprints recorded in the
schema. A change to that authoritative content contract requires an Admin PR
that updates the local schema, Adam instructions, both local validation stages,
and deterministic compatibility fixtures before production provisioning.
