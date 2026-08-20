# gneu-content 9.9.2 — Adam ephemeral GitHub authentication

> **Releasehistorik.** Detta dokument beskriver införandet av 9.9.2. Det är inte
> den auktoritativa instruktionen för ny installation, cold start eller
> recovery. Använd [`OPERATING_MODEL.md`](OPERATING_MODEL.md),
> [`ADMIN_PLAYBOOK.md`](ADMIN_PLAYBOOK.md) och
> [`ADAM_PLAYBOOK.md`](ADAM_PLAYBOOK.md). Tekniska fakta om 9.9.2-koden nedan
> bevaras för spårbarhet.

9.9.2 extends the 9.9.1 economical Hermes watch without changing the Publisher
Gate.

## Changes

- `--ack` instruction is derived from the gate script's actual absolute path.
  This makes profile installs such as `/root/.hermes/profiles/gneu/scripts/...`
  correct without hard-coded profile names.
- A separate `hermes_adam_auth.py` helper mints a short-lived GitHub App
  installation token only when the source gate actually wakes Adam.
- The App is locked in code to `stebolainen/gneu-content`.
- Requested installation-token permissions are only:
  - contents: write
  - pull_requests: write
- The token value is never printed.
- Runtime token file remains `/root/gneu-inbox/github-token`, matching the
  existing Adam contract.
- A successful gate `--ack` removes/revokes the temporary token.
- Missing auth is exposed to Adam as `context.auth.status != ready`; Adam must
  return AUTH_REQUIRED before creating a branch.

## Separate identities

The Adam GitHub App and Publisher GitHub App must be separate applications and
must not share private keys.

Adam:
- may push `adam/*`
- may create/update pull requests
- must never merge
- must have no branch-protection/ruleset bypass

Publisher:
- remains controlled by the 9.9 Publisher Gate
- is the only autonomous merge identity

## Historiska 9.9.2 runtimefiler

Install into the active Hermes profile:

- `hermes_source_gate.py` -> `scripts/gneu-content-source-gate.py`
- `hermes_adam_auth.py` -> `scripts/gneu-content-adam-auth.py`

Secrets are not stored in Git:

- `$HERMES_HOME/secrets/gneu-content-adam/app-id`
- `$HERMES_HOME/secrets/gneu-content-adam/private-key.pem`

Both secret directory and private key must be owner-only.

## Required Adam behavior

When `context.auth.status` is not `ready`, Adam must return `AUTH_REQUIRED`
without creating a branch/worktree/commit.

After a successful NO_CHANGE or valid PR cycle, Adam runs only:

`python3 <absolute gate path> --ack`

The gate records success, promotes pending fingerprints and cleans the
temporary GitHub token.
