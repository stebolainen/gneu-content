# GNEU AI-hot daily handoff v2

The AI-hot generator runs once per Stockholm calendar day after 07:00. It has
no GitHub or production credential. Its only output is an untrusted package
for the separately provisioned trusted READY processor.

The gate supplies an ISO edition, an attempt date and a package ID:

`YYYY-Www--YYYY-MM-DD`

An operator-authorized correction of a locally rejected daily package uses the
single supported revision identity `YYYY-Www--YYYY-MM-DD--r1`. Revision zero is
the normal daily identity and is never renamed or changed. The scheduler never
creates `r1` automatically, and `r2` or later revisions are not supported.

The date must belong to the edition's ISO week. A legacy package named only
`YYYY-Www` remains valid, but is immutable historical evidence. A daily
attempt must never overwrite, delete, move or add files to a legacy package.

Before research, run the tracked base refresh script and use exactly
`inbox/current.json`. Create exactly these files in `outbox/PACKAGE_ID/`:

- `handoff.json`
- `candidate.json`
- `report.md`

The handoff is `gneu-aihot-handoff-v2` and contains the existing v1 fields plus
`"attempt": "YYYY-MM-DD"`. An `r1` handoff also contains `"revision": 1`.
Adam never creates `READY`; the tracked validator
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

The trusted bridge transports only a validated delta, rebinds it to current
gneu-se `main`, and dispatches the existing trusted intake. A rejection receipt
continues to terminate its exact legacy payload. A daily attempt is independent,
but a canonical payload hash matching any verified rejection is blocked as a
replay before dispatch.
