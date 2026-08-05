# CAE Adaptive Enforcer

An explainable, fail-safe intervention engine for high-confidence Entra identity
and network risk. It validates tenant-scoped events, correlates independent
signal domains, protects break-glass identities, rejects stale or malformed
evidence, emits deterministic actions, deduplicates event IDs, and maintains a
tamper-evident decision chain.

`revoke_sessions` is an executable Microsoft Graph action.
`require_step_up` is an intent for a preconfigured Conditional Access
authentication context or downstream policy integration; this sample does not
mutate Conditional Access policies per event.

## Problem statement

Fresh multi-domain risk events are correlated into monitor, step-up, quarantine, or session-revocation decisions while break-glass users, duplicates, collisions, and stale evidence are handled safely.

A production implementation can still fail even when every resource deploys successfully. The material risk is apparently successful automation that lacks bounded scope, a reproducible denial path, or evidence operators can use during review and recovery. The design therefore treats Entra ID, Event Hubs, Functions, and the surrounding identity and evidence controls as one reviewable system rather than unrelated configuration tasks.

## Example case study

### Situation

A security team needs to react to token theft faster than normal access-token expiry. The enforcer turns high-confidence risk signals into explainable interventions without claiming that every client supports instantaneous CAE enforcement.

### Response

A risky sign-in and device-compliance change arrive seconds apart for one session. The enforcer deduplicates the stream, evaluates current state, issues the bounded revocation once, and preserves evidence responders can use to explain the decision.

The team first exercises the repository's synthetic approved and denied fixtures. An approved request must produce the same idempotent plan on replay; a stale, unscoped, public, or unapproved request must fail before an Azure adapter is allowed to run.

### Expected outcome

Stakeholders receive a decision package they can attach to a change record: requested scope, controls evaluated, the reason for approval or denial, and the explicit handoff to live integration. The example supports design review and incident rehearsal without pretending that a local test changed Azure.

## Architecture

![Icon-based architecture for CAE-Adaptive-Enforcer](docs/architecture.svg)

The upper boundary names the principal services and technologies used by this repository. The lower boundary shows the implemented control flow: desired state is validated, provider action remains an explicit integration gate, and sanitized evidence is retained for review and deterministic replay.

## Best complementary diagram

**Recommended view: Risk-correlation and adaptive-enforcement sequence diagram.** A sequence view is the strongest complement because it exposes runtime order, trust hand-offs, fail-closed decisions, and the evidence returned to the caller.

![Icon-based risk-correlation and adaptive-enforcement sequence diagram for CAE Adaptive Enforcer](docs/operational-view.svg)

The view follows **Ingest tenant risk signals → Validate freshness and scope → Correlate and protect → Enforce and chain evidence**. Use it during design reviews, operational walkthroughs, and failure-mode discussions; use the logical architecture above when the question is which technologies integrate.

## Reproduce the vertical slice

The rules engine uses Python 3.11+ and no third-party packages.

```bash
python3 src/enforcer.py replay \
  --policy config/policy.json \
  --events examples/risk-events.json \
  --database build/replay.db \
  --output build/replay-report.json
./scripts/validate.sh
```

The fixture includes malicious, benign, break-glass, stale, step-up, and
duplicate scenarios. The report contains pseudonymous subject references and
hash-chained evidence, not raw user identifiers.

## Azure application asset

[`function_app.py`](function_app.py) is an Azure Functions Event Grid adapter. It obtains tokens
with managed identity, calls Graph only for a `revoke_sessions` decision, and
writes one immutable audit Blob per event. Dependencies are pinned in
[`requirements.txt`](requirements.txt).

The managed identity requires admin-consented Microsoft Graph application
permission `User.RevokeSessions.All` (`77f3a031-c388-4f99-b373-dc68676a979e`).
Grant it only after security review and verify it does not hold broader
directory write roles.

## Deploy

```bash
az deployment group what-if \
  --resource-group <disposable-rg> \
  --template-file infra/main.bicep \
  --parameters deployPlatform=true tenantId=<tenant-guid>
```

Deploy code and validate the Function before setting
`deployEventSubscription=true`. The template creates chargeable Premium
Functions, Storage, Event Grid, and monitoring resources. It disables storage
shared keys and uses identity-based host storage. Public endpoints remain
service-authenticated integration surfaces in this slice; production private
networking and egress controls are explicit follow-up gates.

## Honest CAE boundary

Session revocation is a critical event that CAE-capable resource providers can
enforce near real time, but propagation can take up to 15 minutes and unsupported
clients may retain access until token expiry. This project measures request and
Graph response latency; it cannot claim every downstream session is terminated
at that instant.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[runbook](docs/runbook.md), [test matrix](docs/test-matrix.md), and
[cost model](docs/cost-model.md).

## Repository guide

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Operations runbook](docs/runbook.md)
- [Test matrix](docs/test-matrix.md)
- [Cost model](docs/cost-model.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Support policy](SUPPORT.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)

## Infrastructure inputs

Resource behavior and deploy-time values are intentionally separated:

- [Bicep template](infra/main.bicep) — Azure resources, modules, and security controls.
- [Bicep parameters](infra/main.bicepparam) — environment-specific names, regions, identities, and feature inputs.

Start with the parameter file's safe values, replace synthetic identifiers, and run an Azure what-if before deployment.

## Attribution

Azure product icons come from [Microsoft's official Azure Architecture Icons](https://learn.microsoft.com/azure/architecture/icons/). Open-source marks are sourced from [Simple Icons](https://simpleicons.org/) when shown; each mark identifies its respective technology.
