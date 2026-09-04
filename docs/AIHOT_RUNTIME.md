# AI-hot runtime

GNEU Admin is the technical owner of the AI-hot generator gate, handoff
validator, freshness probe and READY processor. Their tracked source belongs
under `runtime/aihot/` on trusted repository branch `main`. Installation,
scheduler reconciliation and service activation are separate, explicitly
authorised operations performed only after merge.

## State machine and identities

```text
legacy package (YYYY-Www), daily package (YYYY-Www--YYYY-MM-DD),
or operator-authorized correction (YYYY-Www--YYYY-MM-DD--r1)
  -> validate
  -> build trusted transport
  -> reject-replay guard
  -> dispatch trusted intake
     -> processed/<package-id>.json on success
     -> failed/<package-id>.json on failure
        -> FAILED_REQUIRES_OPERATOR for that package

legacy rejected/<week>.json
  -> verifies and terminates its exact legacy package
  -> blocks the same canonical payload under any daily attempt name
```

The processor and operator disposition tool use the same filesystem lock to
prevent concurrent trusted processing. `processed/<package-id>.json` prevents
duplicate successful processing. A failed package remains latched because its
run may have crossed the GitHub dispatch boundary; that exact package is never
retried automatically.

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
job uses the tracked UTC pair `0 5,6 * * *` plus a Europe/Stockholm gate, so the
admitted run is 07:00 across CET and CEST. The gate atomically claims one local
calendar-day attempt. Hermes independently prevents overlap and collapses
missed recurring occurrences to one catch-up. The READY timer continues to
poll independently and does not prove generation freshness.

Gate CLI inspection is explicit and side-effect-free: `--help`, `help`,
`inspect`, and `check` never enter the claim path. The no-argument invocation is
reserved for the Hermes scheduler and is the normal claim-creating operation.

An existing claim is never deleted to retry. If evidence proves that a claim
was created outside the Hermes agent boundary, the root-only operator tool may
create one append-only authorization bound to the exact claim hash. The normal
Hermes job then consumes it once and records a second append-only receipt before
waking the agent. Without the authorization, with an invalid binding, or after
consumption, the gate stays closed. See
[`AIHOT_CLAIM_RECOVERY.md`](AIHOT_CLAIM_RECOVERY.md).

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

`aihot-freshness.py` performs a bounded read-only check of public
`data/aihot.json`. Public age below 26 hours is `FRESH`; age at or above 26
hours is `STALE` with exit code 2. Network, schema or timestamp errors are
`UNKNOWN` and fail closed. The daily generation gate also includes the last
locally observed freshness state in Hermes execution output.

A no-change package records successful research but does not change the public
append-only content payload or its `generated` timestamp. Research freshness
and public content-edition freshness are therefore distinct; this runtime does
not silently rewrite content freshness.

See [`../runtime/aihot/README.md`](../runtime/aihot/README.md) for source,
manifest, provisioning, scheduler reconciliation and provenance details.
