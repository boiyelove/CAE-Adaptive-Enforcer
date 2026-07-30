# Test matrix

| Scenario | Expected result | Automated locally |
|---|---|---|
| High risk, identity + network | revoke sessions | Yes |
| Medium/single-domain score | step-up intent | Yes |
| Benign low score | monitor | Yes |
| Break-glass high risk | no automatic action; human alert | Yes |
| Stale high risk | quarantine | Yes |
| Future/cross-tenant/unknown signal | reject | Yes |
| Exact duplicate | one evidence record | Yes |
| Same ID, changed body | reject collision | Yes |
| Tampered evidence | chain verification fails | Yes |
| Graph 429/5xx and retry | bounded retry, observable failure | Azure integration |
| Immutable Blob duplicate | no overwrite | Azure integration |
| Managed identity permission | revoke only; broader writes denied | Tenant integration |
| CAE-aware session | observed downstream invalidation latency | Tenant drill |
| Unsupported client | limitation and token-expiry behavior recorded | Tenant drill |
| False-positive rollback | event paused, access recovered, evidence retained | Tenant drill |
| Teardown | permission revoked and retention handled | Azure integration |

Local replay proves decision logic and local audit integrity, not Graph, CAE,
Conditional Access, Event Grid, Function, Storage WORM, latency, licensing, or
end-user session behavior.
