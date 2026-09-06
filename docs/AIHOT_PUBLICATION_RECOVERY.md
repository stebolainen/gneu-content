# AI-hot publication recovery after a pre-write branch collision

This runbook covers one narrow failure class:
`REMOTE_TARGET_BRANCH_COLLISION_NO_WRITE`. It applies only when local validate,
build and replay checks passed; the trusted run passed transported-intake,
trusted validators, token creation and repository-scope verification; and the
trusted executor failed at its branch-existence guard before its first blob,
ref or PR write.

Use only sanitized `gneu-admin-github gneu-se-read` operations to verify the
original run and job steps. Verify the conflicting PR is closed without merge,
the exact `aihot/EDITION` branch is absent, and no replacement AI-hot PR is
open. Never delete state, rerun the old workflow, rebuild content, or overwrite
the existing transport.

## Executor source proof

The verifier parses Python with `ast.parse`; it never imports or executes the
remote file. It locates exactly one `if branch(token, head_ref) is not None`
guard whose sole body statement is
`fail("target AI-hot branch already exists")`. The guard must be directly in
the function invoked by the module's `__main__` block. That function's name is
not fixed. The proof walks local helper calls to reject repository writes
before or inside the collision arm, and requires a later write in that same
execution body.

This is deliberately a verifier for reviewed executor semantics, not a general
Python security analyzer. A pinned whole-module AST fingerprint also covers
the `aihot/{edition}` plan binding, terminal `fail`/`SystemExit`, GET-only
helpers, imports, and all write primitives. Unknown semantic changes fail
closed, including writes hidden in a helper or changed target validation.
Comments, formatting and a consistently renamed entry function do not change
the fingerprint. The returned Contents blob is verified against the source;
authorization retains the blob and remote-head bindings and additionally
records source and AST SHA-256 hashes.

Reviewed source: `stebolainen/gneu-se`, `scripts/aihot_pr_execute.py`, ref
`4bb9ba39c74323a158460295ab04923c6d9fa53d`, blob
`0e51ae713c3b62f70aa82a7cfcb0f5560e5e9736`, source SHA-256
`c8e94143adbecd593257426799f66cd98d4400df491427b430fd8d093c060c23`.
Run-head and current main matched at review. The first write is
`create_blob(token, candidate_raw)` at line 550 (POST `/git/blobs`); it follows
the collision guard at lines 519–520. Subsequent writes create the report blob,
tree, commit, branch ref and PR. The later branch-race failure occurs after
blob writes and is **not** this recovery class.

The full source is a non-executable `.py.txt` regression fixture under
`runtime/aihot/tests/fixtures/`, with separate provenance. Tests exercise the
real `remote_no_write()` and mock only sanitized remote responses. If the
executor changes semantically, review all paths before updating the fingerprint
and fixture together in an Admin PR. Source structure proves the conditional
collision boundary; run/job and incident evidence must still establish that
this is the failure that actually occurred. A generic failed write step alone
does not prove zero writes.

## Operator execution

After merge and exact provisioning, authorize once:

```text
/root/gneu-aihot-bridge/bin/authorize-publication-retry.py authorize \
  --package-id PACKAGE_ID \
  --runtime-source-commit MERGE_SHA \
  --conflicting-pr PR_NUMBER \
  --reason REMOTE_TARGET_BRANCH_COLLISION_NO_WRITE
```

Verify with the same command using `verify` and omitting `--reason`. The tool
recomputes all local hashes, queries only the sanitized repository-scoped read
API, and creates `state/publication-retry/authorized/PACKAGE_ID.json` with
root:root mode 0600 and without overwrite.

Pause only `gneu-aihot-ready.timer`, verify no processor is active, then start
`gneu-aihot-ready.service` exactly once. Under the normal processor lock the
authorization is reverified and consumed into
`state/publication-retry/consumed/PACKAGE_ID.json`. Processing restarts at
local validate, verifies the existing deterministic transport without writing
it, runs the canonical rejected-payload replay guard, and only then dispatches.
A second consumption is impossible. A second failure is preserved separately
under `state/publication-retry/failed/` and requires a new human decision.
