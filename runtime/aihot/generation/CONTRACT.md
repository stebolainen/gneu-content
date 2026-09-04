# GNEU AI-hot daily handoff v2

The AI-hot generator runs once per Stockholm calendar day after 07:00. It has
no GitHub or production credential. Its only output is an untrusted package
for the separately provisioned trusted READY processor.

The gate supplies an ISO edition, an attempt date and a package ID:

`YYYY-Www--YYYY-MM-DD`

The date must belong to the edition's ISO week. A legacy package named only
`YYYY-Www` remains valid, but is immutable historical evidence. A daily
attempt must never overwrite, delete, move or add files to a legacy package.

Before research, run the tracked base refresh script and use exactly
`inbox/current.json`. Create exactly these files in `outbox/PACKAGE_ID/`:

- `handoff.json`
- `candidate.json`
- `report.md`

The handoff is `gneu-aihot-handoff-v2` and contains the existing v1 fields plus
`"attempt": "YYYY-MM-DD"`. Adam never creates `READY`; the tracked validator
creates it atomically after validation. Existing READY, failed, rejected,
processed or generation-claim state must never be deleted or overwritten.

A generation claim is also immutable. An orphaned claim may be re-admitted
only by the separately documented, append-only operator authorization. The
ordinary scheduler gate verifies and consumes that authorization exactly once
under the generation lock. There is no age- or timeout-based retry.

The content contract remains append-only. If the current edition is absent,
mode `edition` adds exactly one edition and 1–6 articles. If there is no
publishable new material, or the current edition is already present in the
public baseline, mode `no-change` contains no delta and the report still records
that day's research. Existing editions, articles and top-level `generated` are
never changed by Adam. Updating an already published edition requires a
separate human-reviewed gneu-se contract change and is not smuggled through
this Admin runtime.

The trusted bridge transports only a validated delta, rebinds it to current
gneu-se `main`, and dispatches the existing trusted intake. A rejection receipt
continues to terminate its exact legacy payload. A daily attempt is independent,
but a canonical payload hash matching any verified rejection is blocked as a
replay before dispatch.
