# Architecture and decisions

Normalized `risk.signal.v1` events carry tenant, subject, time, risk level,
correlation ID, and named signals. The rules engine validates the envelope,
scores versioned signals, requires independent evidence domains for revocation,
and emits one deterministic decision ID. Raw subject IDs are needed only at the
Graph execution boundary; evidence stores a one-way subject reference.

## Decisions

- **ADR-001:** automatic revocation requires high risk, score threshold, and at
  least two domains. A single noisy source can trigger step-up review but not
  revocation.
- **ADR-002:** break-glass identities are never automatically revoked. Their
  risk events alert and require a human runbook.
- **ADR-003:** stale events are quarantined, not acted on. Future-skew and tenant
  boundaries are strict.
- **ADR-004:** `User.RevokeSessions.All` is the sole Graph application
  permission. It requires explicit admin consent after infrastructure deploy.
- **ADR-005:** immutable evidence is versioned and initially unlocked so
  operators can validate retention before locking. Locking is an irreversible
  production change.

CAE-capable resource providers can react to the revocation event, but clients
and resources have different support. Step-up requires a preconfigured
Conditional Access authentication context; this engine does not create dynamic
per-user Conditional Access policies.
