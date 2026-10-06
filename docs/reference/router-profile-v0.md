# Router Profile v0

## Purpose

Q17 defines AIDE's first advisory routing profile. It lets AIDE inspect compact
task/context packets plus verifier, token, golden-task, review, and outcome
signals, then explain what route class is justified before spending model
tokens.

The Router Profile is a contract and report generator, not a live router.

## Files

- `.aide/policies/routing.yaml`: routing policy, route classes, hard floors, quality gates, and forbidden behaviors.
- `.aide/models/providers.yaml`: advisory provider-family metadata with `live_calls_allowed_in_q17: false`.
- `.aide/models/capabilities.yaml`: capability dimensions used by route profiles.
- `.aide/models/routes.yaml`: task-class route profiles and escalation rules.
- `.aide/models/hard-floors.yaml`: minimum route classes for architecture, security, self-modification, promotion, governance, destructive, and high-stakes work.
- `.aide/models/fallback.yaml`: advisory fallback behavior.
- `.aide/routing/latest-route-decision.json`: latest machine-readable route decision.
- `.aide/routing/latest-route-decision.md`: compact human-readable route decision.

## Commands

```bash
py -3 .aide/scripts/aide_lite.py route list
py -3 .aide/scripts/aide_lite.py route validate
py -3 .aide/scripts/aide_lite.py route explain
py -3 .aide/scripts/aide_lite.py route explain --task-packet .aide/context/latest-task-packet.md
```

`route explain` is deterministic and writes route artifacts. It does not call a
provider, model, network service, Gateway, Runtime, UI, or local model manager.

## Route Classes

- `no_model_tool`: deterministic local tools and tests should do the work.
- `local_small`: future advisory class for low-risk local model work.
- `local_strong`: future advisory class for bounded local model work with verification.
- `cheap_remote`: future advisory class for low-cost remote draft work with verification.
- `frontier`: premium review or reasoning is justified.
- `human_review`: accountable human review is required or preferred.
- `blocked`: required gates are missing or failing.

## Hard Floors

Hard floors prevent cost optimization from weakening review gates.

- architecture decisions
- security review
- self-modification
- final promotion review
- governance policy changes
- irreversible or destructive changes
- high-stakes review

Q17 hard floors are advisory but must not be demoted by future automation.

## Token-Saving Behavior

Routing reduces token waste by selecting `no_model_tool` when deterministic
commands can answer the question, by blocking premium review when verifier or
golden-task gates fail, and by reserving frontier/human review for uncertainty,
security, governance, architecture, or promotion decisions.

## Deferred Work

Q17 does not implement Gateway, provider calls, live model routing, provider
pricing, provider billing, exact tokenization, local model setup, cache/local
state boundaries, Runtime, Service, Commander, UI, Mobile, MCP/A2A, semantic
cache, vector search, or automatic prompt/policy mutation. Q18 should define
cache and local-state boundaries separately.
