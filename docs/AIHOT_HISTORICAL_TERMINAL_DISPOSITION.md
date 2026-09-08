# AI-hot historical terminal disposition recovery

This GNEU Admin runbook closes only the three explicitly reviewed historical
READY queue blockers listed below. It does not retry, regenerate, dispatch,
delete, rename, or modify any package, failed latch, authorization, consumed
receipt, retry failure, transport, or other immutable evidence.

The deployed runtime and this runbook must come from the same reviewed and
merged `origin/main`. A source-tree checkout is never used to write runtime
state.

## Closed historical allowlist

The v1 mechanism has no prefix, wildcard, or caller-defined package support.
It accepts only these exact package and failure-code pairs:

| Package | Failure code | Bound failure |
| --- | --- | --- |
| `2026-W36--2026-09-04--r1` | `RUNTIME_SOURCE_COMMIT_MISMATCH` | Consumed local retry plus consumed and terminally failed READY retry lineage |
| `2026-W36--2026-09-04--r2` | `INVALID_RUNTIME_PROVENANCE` | Consumed incident-bound content retry lineage; r3 remains forbidden |
| `2026-W37--2026-09-07` | `CANDIDATE_EDITION_PREFIX_DIFFERS_FROM_ORIGIN_MAIN` | Build failure whose exact output line is `candidate edition prefix differs from origin/main` |

Every receipt has schema
`gneu-aihot-historical-terminal-disposition-v1`, disposition
`historical_terminal`, status `closed_non_actionable`, and
`retry_allowed: false`. The tracked JSON contract is
[`../runtime/aihot/historical-terminal-disposition.schema.json`](../runtime/aihot/historical-terminal-disposition.schema.json).

Receipts are created with no-overwrite semantics at
`state/historical-terminal-dispositions/<exact-package-id>.json`. They bind the
exact package identity, exact failure code and detail, and SHA-256 of every
required immutable package and lineage record. An identical repeated command
is an idempotent no-op. Any different receipt, argument, state byte, missing
evidence, extra evidence key, or unknown directory entry is `BLOCKED`.

## Required operator sequence

Use the exact deployed runtime only after this change has been human-reviewed,
merged to trusted `main`, separately provisioned, and source/runtime hashes
match.

1. Obtain explicit human approval naming every exact package and failure code.
2. Stop `gneu-aihot-ready.timer` without disabling it. Require the timer and
   processor to be inactive.
3. Hash all immutable evidence named by
   `historical-terminal-disposition.py append --help`. Independently verify the
   package IDs, failed stages, consumed retry lineage, and exact failure
   strings. Do not modify any evidence or old receipt.
4. Append one exact disposition per approved package. Supply every evidence
   digest as `--evidence-sha256 NAME=SHA256`; callers cannot supply paths.

   ```text
   /usr/bin/python3 -B -I /root/gneu-aihot-bridge/bin/historical-terminal-disposition.py append \
     --package-id EXACT_PACKAGE_ID \
     --failure-code EXACT_FAILURE_CODE \
     --evidence-sha256 NAME=SHA256 \
     --human-approval "exact recorded human approval" \
     --reason "specific historical terminal disposition reason"
   ```

   Repeat `--evidence-sha256` for every name required by that exact case.
   Require `HISTORICAL_TERMINAL_DISPOSED`. An identical
   `ALREADY_HISTORICAL_TERMINAL` is success only after verification; any
   `BLOCKED_HISTORICAL_TERMINAL_DISPOSITION` stops recovery.
5. Verify immutable binding for each receipt:

   ```text
   /usr/bin/python3 -B -I /root/gneu-aihot-bridge/bin/historical-terminal-disposition.py verify \
     --package-id EXACT_PACKAGE_ID
   ```

   Require `VERIFIED_HISTORICAL_TERMINAL`. Confirm old receipt and evidence
   hashes are unchanged and no retry authorization, generation, transport, or
   dispatch occurred.
6. Run the READY processor manually exactly once:

   ```text
   systemctl reset-failed gneu-aihot-ready.service
   systemctl start gneu-aihot-ready.service
   ```

   Require one `HISTORICAL_TERMINAL_NON_ACTIONABLE` result per disposed
   package, continued queue scanning, service exit 0, and no processing of the
   historical packages. A current valid `NO_CHANGE` may complete normally and
   must not create a content PR.
7. Only after the manual service exits 0, reactivate the existing timer:

   ```text
   systemctl start gneu-aihot-ready.timer
   ```

   Verify enabled/active timer state and a later successful one-shot cycle.

## Fail-closed boundaries

Missing dispositions preserve the existing blocker. Future or current failed
packages, unknown package identities, r3, wildcard/prefix identities, changed
evidence, wrong hashes, wrong failure codes, conflicts, malformed state, and
unsupported failure classes remain blocking. This mechanism never grants a
retry and does not weaken local retry, READY retry, content retry, publication
retry, provenance, validation, or dispatch policy.
