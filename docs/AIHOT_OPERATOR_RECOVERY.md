# AI-hot operator rejection recovery

This runbook is owned by GNEU Admin. It applies only to a latched
`FAILED_REQUIRES_OPERATOR` package whose failure is in the disposition
allowlist and can be reproduced from immutable local evidence. It never makes
an editorial correction and never changes package content.

## Safety model

`operator-disposition.py` needs no GitHub token and performs no network call.
It distinguishes two evidence classes in the receipt:

- `machine_verified_local_evidence` is recomputed by the tool from the failed
  latch, package, transport, decoded payload, and dispatch output.
- `operator_attested_remote_evidence` is the operator's assertion after a
  separate read-only GitHub investigation. Its `verified_by_tool` field is
  always `false`; the tool never claims to have verified GitHub.

The only v1 allowlisted failure is `ARTICLE_DATE_OUTSIDE_EDITION`. The tool
selects the first article, in payload order, for which
`date.fromisoformat(article.date).isocalendar()` differs from the declared
edition. Any other failure, ambiguous state, missing evidence, changed byte,
symlink, or identity mismatch is `BLOCKED`.

The receipt contract is
[`../runtime/aihot/rejection-receipt.schema.json`](../runtime/aihot/rejection-receipt.schema.json).
Receipts use UTF-8 JSON with sorted keys, compact separators, and one final
newline. They are atomically linked into `state/rejected/` without overwrite,
then the parent directory is fsynced. The original failed latch, package, and
transport remain unchanged.

## Required operator procedure

Use the exact deployed runtime only after its source change has been reviewed,
merged to trusted `main`, separately provisioned, and hash-verified.

1. Record `systemctl status gneu-aihot-ready.service --no-pager -l` and confirm
   `FAILED_REQUIRES_OPERATOR <edition>` in the journal.
2. Temporarily pause execution with
   `systemctl stop gneu-aihot-ready.timer`. Do not disable the timer or edit its
   unit.
3. Confirm the timer is inactive and the processor is not running with
   `systemctl is-active gneu-aihot-ready.timer`,
   `systemctl is-active gneu-aihot-ready.service`, and a process listing. Stop
   if a processor process exists.
4. Collect exact SHA-256 values, without changing files, for
   `failed/<edition>.json`, `READY`, `handoff.json`, `candidate.json`,
   `report.md`, and `intake/<edition>.transport.json`. Decode the transport's
   URL-safe base64 and gzip layers read-only and hash the resulting canonical
   JSON bytes for `--payload-sha256`. Record `base_main_sha` from both transport
   and decoded payload. Extract the run-id and failing article only as
   candidates; the tool will independently verify them.
5. Through the documented read-only Admin GitHub route, inspect the exact
   GitHub run-id bound in the failed dispatch output. Verify its event, head
   SHA, completion status and conclusion; inspect jobs and steps to confirm no
   write step completed. Search remote publication and open-PR state for the
   exact payload/article identity. Require proof that nothing was published or
   merged and no matching valid candidate or PR remains. If the Admin wrapper
   cannot perform these read-only checks, stop; do not bypass it with another
   credential.
6. Run the disposition once with every value recorded above:

   ```bash
   /usr/bin/python3 -B -I /root/gneu-aihot-bridge/bin/operator-disposition.py reject \
     --edition YYYY-Www \
     --failing-article ARTICLE_ID \
     --run-id RUN_ID \
     --failure-sha256 FAILED_FILE_SHA256 \
     --ready-sha256 READY_SHA256 \
     --handoff-sha256 HANDOFF_SHA256 \
     --candidate-sha256 CANDIDATE_SHA256 \
     --report-sha256 REPORT_SHA256 \
     --transport-sha256 TRANSPORT_SHA256 \
     --payload-sha256 DECODED_CANONICAL_PAYLOAD_SHA256 \
     --base-main-sha SHA40 \
     --reason "specific operator disposition reason" \
     --remote-proof "operator-verified summary of no matching publication side effect"
   ```

   `REJECTED <edition>` is a new receipt. `ALREADY_REJECTED <edition>` is
   idempotent success only when the existing receipt and both operator strings
   match exactly. Any `BLOCKED` result stops recovery.
7. Read the receipt and verify that it contains no secret or token. Do not edit
   it.
8. Run:

   ```bash
   /usr/bin/python3 -B -I /root/gneu-aihot-bridge/bin/operator-disposition.py verify \
     --edition YYYY-Www
   ```

   Require `VERIFIED_REJECTED <edition>`.
9. Run `systemctl reset-failed gneu-aihot-ready.service`.
10. Run `systemctl start gneu-aihot-ready.service`.
11. Require `ALREADY_REJECTED <edition>` in the journal and service exit 0. No
    validate, build, dispatch, GitHub, or content operation may occur for the
    rejected edition.
12. Restore scheduling with `systemctl start gneu-aihot-ready.timer`. Do not
    change enable-state or cadence.
13. Verify `systemctl --failed`, timer health, and the next scheduled run.
14. Repeat the read-only GitHub/content checks and confirm that the recovery
    created no remote or publication side effect.

## When REJECTED is forbidden

Do not use rejection if the failure is outside the explicit allowlist; the
failed stage or run-id is unclear; any bound hash has changed; the payload is
not canonical; the article/date failure cannot be reproduced locally; the
remote run, head SHA, jobs, or side effects cannot be verified; a matching PR
or valid candidate remains; anything may have been published or merged; a
processed receipt exists; or the timer/process cannot be safely isolated.

Never delete a failed latch or READY package, edit an article date or payload,
manually create/edit a receipt, add an ad-hoc allowlist entry, use a GitHub
credential with the disposition tool, or retry a latched dispatch.
