# Threat model

| Threat | Control | Evidence | Residual risk |
|---|---|---|---|
| Attacker forges tenant/event | canonical schema and tenant allowlist | negative tests | publisher identity/RBAC configuration |
| One noisy signal revokes user | two-domain high-confidence rule | single-domain test | correlated false positives |
| Duplicate delivery repeats work | deterministic decision; duplicate evidence refusal; Graph revocation is repeat-safe | duplicate test | crash timing can repeat Graph request |
| Event ID reused with changed body | payload collision rejection | collision test | distributed adapter must preserve body hash |
| Audit is altered | hash chain locally; WORM versioned Blob in Azure | tamper test/template assertion | policy unlocked until operator review |
| Break-glass lockout | explicit no-op plus human alert | break-glass test | allowlist governance |
| Stale/future event acts | freshness quarantine and skew rejection | freshness tests | source clock quality |
| Managed identity overprivileged | exact Graph revoke permission | IaC/docs assertion | admin-consent mistakes |
| PII leaks through telemetry | pseudonymous subject; no raw event logging | repository test | platform HTTP diagnostics |

Audit access, policy updates, Event Grid publishers, and Graph permission grants
are privileged operations. Use PIM, approvals, diagnostic alerts, and regular
access review.
