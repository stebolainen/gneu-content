# AI-hot runtime

GNEU Admin is the technical owner of the AI-hot READY processor. Its tracked
source belongs under `runtime/aihot/` on trusted repository branch `main`.
Runtime installation and service activation are separate, explicitly
authorised operations performed only after merge.

## State machine

The byte-preserved bootstrap runtime implements this state machine:

```text
READY package
  -> validate
  -> build trusted transport
  -> dispatch trusted intake
     -> processed/<week>.json on success
     -> failed/<week>.json on failure
        -> FAILED_REQUIRES_OPERATOR on every later processor run
        -> rejected/<week>.json after an explicit, eligible operator disposition
           -> ALREADY_REJECTED on every later processor run
```

The processor and operator disposition tool use the same filesystem lock to
prevent concurrent execution.
`processed/<week>.json` prevents duplicate successful processing. A failed
package is latched because the original run may have crossed the GitHub
dispatch boundary; the current implementation never retries it automatically.

`rejected/<week>.json` is an append-only terminal receipt. The failed latch,
READY package, transport, and outbox evidence remain in place. A valid receipt
must remain cryptographically and semantically bound to all of them. A
`processed` and `rejected` receipt for the same edition is a state conflict and
the processor fails closed. A rejected package is never validated, rebuilt, or
redispatched.

The first version deliberately permits only the locally reproducible
`ARTICLE_DATE_OUTSIDE_EDITION` failure. It has no general operator-asserted
fallback. Remote GitHub review remains a separate, mandatory Admin step; the
receipt distinguishes machine-verified local evidence from operator-attested
remote evidence.

## Current operational debt: W36

The runtime currently reports `FAILED_REQUIRES_OPERATOR` for the
`2026-W36` READY package. The trusted intake run rejected an article whose
declared date did not belong to ISO week 36. The package remains READY and its
failure remains latched.

This incident is the motivating example for the generic transition. The
package, failed-state contents, transport payload, credentials, and other
runtime state remain outside Git. Adding the implementation does not
acknowledge, change, or disposition W36. Actual recovery requires review,
merge, separate provisioning, and the operator procedure in
[`AIHOT_OPERATOR_RECOVERY.md`](AIHOT_OPERATOR_RECOVERY.md).

See [`../runtime/aihot/README.md`](../runtime/aihot/README.md) for the source,
manifest, installation, and provenance contract.
