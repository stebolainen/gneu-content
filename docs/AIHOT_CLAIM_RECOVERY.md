# AI-hot orphaned generation-claim recovery

This runbook covers one narrow failure: the daily gate created a valid claim,
but no Hermes scheduler-agent execution owned it and no package or downstream
state was created. It never covers a slow, active, completed, failed, or
otherwise ambiguous generation.

## Safety invariants

- **Never delete, move, overwrite, or edit a generation claim to retry.**
- Never use an elapsed timeout as evidence that an agent is absent.
- Never run the gate's no-argument execution path for CLI inspection. Use
  `--help`, `help`, `inspect`, or `check`; all are side-effect-free.
- Never invoke the underlying generator directly.
- Recovery is allowed only on the same Europe/Stockholm calendar day as the
  claim.
- Authorization and consumption receipts are root-owned mode `0600`, canonical
  JSON, create-without-overwrite, and bound to the original claim SHA-256.

## Required orphan evidence

Before authorization, verify all of the following without mutation:

1. The canonical claim exists at
   `/root/gneu-aihot-bridge/state/generation/YYYY-MM-DD.json`.
2. Owner/group is `root:root`, mode is `0600`, and its SHA-256 is recorded.
3. The claim's edition, attempt, package ID and claimed timestamp agree.
4. The package directory, READY, handoff, candidate, report, processed receipt,
   failed receipt and trusted transport are all absent.
5. No AI-hot generation process is active.
6. Hermes `executions.db` has no active execution for the tracked job and no
   execution at or after the claim timestamp.
7. The tracked job's output directory contains neither the package ID nor an
   output created at or after the claim timestamp.

Any missing or ambiguous evidence blocks recovery.

## Authorize one resume

Use the attempt and the independently calculated claim SHA-256. The reason is
an allowlisted enum, not operator prose:

```bash
/root/gneu-aihot-bridge/bin/authorize-generation-resume.py authorize \
  --attempt YYYY-MM-DD \
  --claim-sha256 CLAIM_SHA256 \
  --reason CLAIM_CREATED_WITHOUT_AGENT
```

The tool re-reads and validates the claim, derives edition and package ID from
it, rechecks all downstream state and Hermes ownership, and atomically creates:

`state/generation/resume-authorized/YYYY-MM-DD.json`

It never accepts edition or package ID from the caller. Verify the immutable
authorization before triggering Hermes:

```bash
/root/gneu-aihot-bridge/bin/authorize-generation-resume.py verify \
  --attempt YYYY-MM-DD \
  --claim-sha256 CLAIM_SHA256
```

## Trigger the ordinary Hermes job exactly once

The documented Hermes one-shot command for the existing tracked job is:

```bash
hermes cron run fbd796dbb875
```

This schedules the same job, script, workdir, skills and prompt on the next
scheduler tick. It does not bypass the gate. Under the generation lock, the
gate verifies the authorization and current package state, creates the
append-only consumed receipt, and returns `wakeAgent=true` with reason
`operator_resume_claim`. Context identity comes only from the original claim.

Do not issue the one-shot command twice. A later gate invocation returns
`resume_already_consumed` and cannot wake the agent from the same authorization.

Verify consumption with:

```bash
/root/gneu-aihot-bridge/bin/authorize-generation-resume.py verify-consumed \
  --attempt YYYY-MM-DD \
  --claim-sha256 CLAIM_SHA256
```

The consumed receipt is:

`state/generation/resume-consumed/YYYY-MM-DD.json`

It binds the original claim, authorization SHA-256, allowlisted reason and
consumption timestamp. After the run, verify the Hermes execution ID and the
package's candidate, handoff, report and READY evidence through the normal
daily pipeline. If authorization, consumption, execution ownership or package
state is inconsistent, stop; do not create another authorization.
