# Operations runbook

## SLOs and measures

Target 99.9% event-processing availability, p95 decision latency under 250 ms,
Graph request initiation under one minute from accepted high-confidence event,
zero automated break-glass revocations, and complete immutable evidence for
accepted events. CAE critical-event propagation can take up to 15 minutes and
must be measured separately with a supported client/resource.

Alert on Event Grid dead-letter/retry volume, stale events, break-glass events,
Graph 401/403/429/5xx, audit write failures, duplicate rate, Function health,
policy changes, and missing evidence. Never log tokens or raw event bodies.

## Failure handling

Graph 429/5xx uses bounded exponential retry honoring `Retry-After`; Event Grid
provides outer retry. Repeating `revokeSignInSessions` is acceptable, but audit
the repeat. If Graph or immutable Storage is unavailable, fail the Function so
Event Grid retries; do not record success without action status and evidence.
Step-up intents remain pending until the configured CA integration acknowledges
them.

For false positives, disable the Event Grid subscription, preserve evidence,
review source signals and policy version, and restore the user through the
tenant-approved identity process. Do not add the user to break-glass as a quick
fix. Roll back a policy via reviewed version control and replay both benign and
malicious fixtures.

Lock the immutability policy only after retention, legal, recovery, and teardown
review because locked retention blocks deletion. Teardown first disables event
delivery and Graph permission, exports evidence, waits for retention/legal
approval, and then removes disposable resources.
