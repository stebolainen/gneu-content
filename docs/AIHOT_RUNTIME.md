# AI-hot runtime

GNEU Admin is the technical owner of the AI-hot generator gate, handoff
validator, freshness probe and READY processor. Their tracked source belongs
under `runtime/aihot/` on trusted repository branch `main`. Installation,
scheduler reconciliation and service activation are separate, explicitly
authorised operations performed only after merge.

## State machine and identities

```text
legacy package (YYYY-Www), daily package (YYYY-Www--YYYY-MM-DD),
operator-authorized local correction (YYYY-Www--YYYY-MM-DD--r1),
or the single incident-bound 2026-09-04 r2 correction
  -> validate
  -> build trusted transport
  -> reject-replay guard
  -> dispatch trusted intake
     -> processed/<package-id>.json on success
     -> failed/<package-id>.json on failure
        -> FAILED_REQUIRES_OPERATOR while it is the current package
        -> HISTORICAL_TERMINAL_SKIPPED after a later READY identity exists

legacy rejected/<week>.json
  -> verifies and terminates its exact legacy package
  -> blocks the same canonical payload under any daily attempt name
```

The processor and operator disposition tool use the same filesystem lock to
prevent concurrent trusted processing. `processed/<package-id>.json` prevents
duplicate successful processing. A failed package remains latched because its
run may have crossed the GitHub dispatch boundary; that exact package is never
retried automatically.

The READY queue is ordered by canonical package identity. A valid immutable
failed latch blocks while its package is the newest READY identity. Once a
later READY identity exists, the failed package is historical and terminal:
the processor verifies its receipt identity, owner, mode, schema, stage and
bounded stage evidence, logs `HISTORICAL_TERMINAL_SKIPPED`, and continues the
queue. It never retries, regenerates, dispatches, deletes, or rewrites that
package. A malformed historical latch still blocks, and the newest unresolved
failure remains `FAILED_REQUIRES_OPERATOR`.

The explicit historical-disposition receipts introduced for the three 2026
incident lineages remain available as append-only audit records, but queue
liveness does not depend on their presence. See
[`AIHOT_HISTORICAL_TERMINAL_DISPOSITION.md`](AIHOT_HISTORICAL_TERMINAL_DISPOSITION.md).

The v1 operator receipt remains edition-named because it preserves the legacy
package for which it was created. It does not blanket-reject a sibling daily
attempt. Daily attempt names include the Stockholm date, and that date must be
in the declared ISO week. Before a daily attempt can dispatch, the processor
verifies every existing rejection receipt and blocks any canonical payload hash
already rejected. The old W36 package therefore remains terminal while a
genuinely different W36 attempt may use the normal pipeline.

The initial disposition allowlist remains the locally reproducible
`ARTICLE_DATE_OUTSIDE_EDITION` failure. It has no general operator-asserted
fallback. Remote GitHub review remains a separate, mandatory Admin step; the
receipt distinguishes machine-verified local evidence from operator-attested
remote evidence.

## Daily generation and freshness

Generation and READY processing are separate schedulers. The Hermes generation
job uses the tracked UTC slots `0 5,6,7 * * *` plus a Europe/Stockholm gate.
The first eligible slot is 07:00 across CET and CEST, the next slot is its one
DST-safe fallback opportunity, and the remaining slot only observes terminal
state. The gate atomically claims one local calendar-day attempt. Hermes
independently prevents overlap and collapses missed recurring occurrences to
one catch-up. The READY timer continues to poll independently and does not
prove generation freshness.

`gneu-aihot-ready.timer` is normally enabled and active. Verified historical
terminal failures do not make the one-shot service fail, so they do not require
the timer to be stopped. Only the newest unresolved or invalid queue state
causes a nonzero processor result and operator notification.

Gate CLI inspection is explicit and side-effect-free: `--help`, `help`,
`inspect`, and `check` never enter the claim path. The no-argument invocation is
reserved for the Hermes scheduler and is the normal claim-creating operation.

An existing claim is never deleted or changed to retry. One automatic fallback
is allowed only after the Hermes ledger records the primary invocation's exact
`usage_limit_reached`/HTTP 429 provider failure and citation, outbox, candidate,
handoff, READY, transport, rejected, failed and processed state are all absent.
The root-owned provider request evidence must also show only the initial user
input and no tool/research result. The gate writes one append-only receipt bound
to the claim, provider-evidence hash and both execution IDs before returning
`FALLBACK_RETRY`; a second failure is terminal. Other
claims stay closed. If evidence instead proves that a claim was created outside
the Hermes agent boundary, the root-only operator tool may create one
append-only authorization bound to the exact claim hash. The normal Hermes job
then consumes it once and records a second append-only receipt before waking
the agent. Without the authorization, with an invalid binding, or after
consumption, the gate stays closed. See
[`AIHOT_CLAIM_RECOVERY.md`](AIHOT_CLAIM_RECOVERY.md).

The tracked scheduler check combines Hermes job configuration with the gate's
read-only daily status. `PRIMARY_TRANSIENT_FAILURE`, terminal fallback results
and unsafe fallback state are never reported as a healthy scheduler merely
because a later Hermes slot returned `wakeAgent=false`.

A daily package that fails local validation before READY is likewise immutable.
For the single allowlisted `ARTICLE_DATE_OUTSIDE_EDITION` class, a root-only
operator may authorize one independently bound `--r1` correction after proving
the source hashes, terminal Hermes execution, reproducible failure, and absence
of all downstream state. The ordinary Hermes job consumes that authorization
exactly once. The scheduler never creates a revision automatically. See
[`AIHOT_LOCAL_RETRY.md`](AIHOT_LOCAL_RETRY.md).

An `r1` package that passed the local validator but was latched by the single
verified trusted-validator `date` import runtime defect may receive one
separate, append-only READY-processing authorization after the fixed runtime is
human-merged and provisioned. The authorization binds the immutable package,
READY and original failed receipt to the fixed provenance. The normal READY
processor consumes it once under its existing lock and re-enters at
`validate`; build, replay guard and dispatch remain mandatory and ordered. The
original failed receipt is never changed. See
[`AIHOT_READY_RECOVERY.md`](AIHOT_READY_RECOVERY.md).

The terminal 2026-09-04 r1 content failure may authorize exactly one r2 fresh
generation only after operator verification of remote run 33874811080. The
authorization binds every immutable r1/recovery/transport hash, the pinned
trusted content-contract fingerprint, the failed validation result, and the
fact that all remote credential and write steps were skipped. The normal gate
consumes it once under the generation lock. This is not an unlimited retry
mechanism: other incidents, failure classes, dates, r3, and automatic revision
creation remain blocked. See
[`AIHOT_CONTENT_RETRY.md`](AIHOT_CONTENT_RETRY.md).

`aihot-freshness.py` performs a bounded read-only check of public
`data/aihot.json`. Public age below 26 hours is `FRESH`; age at or above 26
hours is `STALE` with exit code 2. Network, schema or timestamp errors are
`UNKNOWN` and fail closed. The daily generation gate also includes the last
locally observed freshness state in Hermes execution output.

A no-change package records successful research but does not change the public
append-only content payload or its `generated` timestamp. After trusted local
intake validation succeeds, the READY processor writes its terminal processed
receipt directly; it does not build transport, dispatch GitHub intake, create a
PR, or write content. Research freshness and public content-edition freshness
are therefore distinct; this runtime does not silently rewrite content
freshness.

## AI-hot content contract

The machine-readable local article contract is v2 in
`runtime/aihot/bin/aihot-content-schema.json`. Its pinned provenance identifies
the authoritative `stebolainen/gneu-se` validator ref, path, blob and SHA-256.
The pure `aihot_content_contract.py` module has no network, credential or state
access and is used by both the pre-READY handoff validator and trusted local
intake validator. This keeps the untrusted generation boundary fail-closed
without duplicating article key sets or evidence rules.

Adam authors mandatory `evidence` as part of the original candidate, including
explicit publication class, confidence and source-bound claims. AUTO-intended
class A/verified claims use source-language verbatim excerpts grouped by stable
claim ID across at least two sources. The bridge transports the complete article
object unchanged and never enriches it.
Any missing/extra field, invalid evidence or source shape, duplicate ID, or
out-of-edition date is blocked before READY. When the authoritative gneu-se
validator changes its article contract, the schema, Adam instructions, local
validators and pinned compatibility fixtures must be updated together in an
Admin PR before provisioning. Runtime generation has no network dependency on
the remote contract.

See [`../runtime/aihot/README.md`](../runtime/aihot/README.md) for source,
manifest, provisioning, scheduler reconciliation and provenance details.
