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
