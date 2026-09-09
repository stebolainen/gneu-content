# AI-hot reader-context check

The reader-context check is a lightweight, state-free pre-handoff authoring
control for new AI-hot articles. It sits after research-to-article drafting and
before an outbox package, READY validation or content PR.

It flags only the current candidate for one bounded editorial rewrite. A second
failure ends that candidate as `EDITORIAL_REVIEW_REQUIRED`; it creates no
READY/retry/recovery/historical state and cannot block a later daily package,
the READY processor, timer, service or fast lane.

The check covers actor/term introduction, standalone opening context and
summary/why/action distinction. It preserves sources, evidence and claims,
severity, date and factual scope.

Follow-up UI work: `ai-hot.html` currently renders the latest edition summary
both in the page header and again above that edition's first article. That
presentation duplication is deliberately outside this runtime-only change.
