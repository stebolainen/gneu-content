# AI-hot runtime

GNEU Admin is the technical owner of the AI-hot READY processor. Its tracked
source belongs under `runtime/aihot/` on trusted repository branch `main`.
Runtime installation and service activation are separate, explicitly
authorised operations performed only after merge.

## Current state machine

The byte-preserved bootstrap runtime implements this state machine:

```text
READY package
  -> validate
  -> build trusted transport
  -> dispatch trusted intake
     -> processed/<week>.json on success
     -> failed/<week>.json on failure
        -> FAILED_REQUIRES_OPERATOR on every later processor run
```

The processor uses a filesystem lock to prevent concurrent execution.
`processed/<week>.json` prevents duplicate successful processing. A failed
package is latched because the original run may have crossed the GitHub
dispatch boundary; the current implementation never retries it automatically.

There is currently no `rejected` or `dismissed` terminal state and no tracked
operator-disposition tool. Those semantics must be designed, reviewed, tested,
and introduced in a separate Admin change. This provenance bootstrap does not
change the state machine or failure behaviour.

## Current operational debt: W36

The runtime currently reports `FAILED_REQUIRES_OPERATOR` for the
`2026-W36` READY package. The trusted intake run rejected an article whose
declared date did not belong to ISO week 36. The package remains READY and its
failure remains latched.

This is recorded only as an example of the missing operator state transition.
The package, failed-state contents, transport payload, credentials, and other
runtime state must remain outside Git. This bootstrap neither acknowledges nor
dispositions W36.

See [`../runtime/aihot/README.md`](../runtime/aihot/README.md) for the source,
manifest, installation, and provenance contract.
