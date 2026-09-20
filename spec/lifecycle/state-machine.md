---
type: "Engineering Specification"
title: "Operation and transaction state machines"
description: "Define durable boundaries, partial completion and truthful outcomes before implementing effectful code."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TXN","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PLAN","USK-S-OWN"]}
---

# Operation and transaction state machines

## Operation states
```text
created -> planning -> planned -> authorized -> preparing -> staging
        -> verifying-stage -> ready-to-publish -> publishing
        -> payload-published -> integrating -> verifying-installed
        -> state-published -> completed
```
Refusal may terminate before effects. At any effectful boundary, failure routes to recovering, retained-for-operator or outcome-unknown according to current evidence. Cancellation requested is orthogonal to phase; completed-after-cancel-request is possible. A worker death does not prove that no effects occurred.

## Transition contract
Each transition identifies old phase, new phase, expected sequence, prerequisites, durable intent, external effect, observed outcome and next recovery action. Write-ahead intent is durable before the external effect. Completion becomes durable after independent observation. The phase graph forbids silently rewinding a published operation to unstarted.

A payload directory rename, service registration and application data migration are not globally atomic. Report payload-published/integration-pending when appropriate. State publication and audit append can fail after payload visibility; recovery inspects reality and reconstructs only under exact original operation context, not by trusting filenames alone.

## Outcomes
Use refused-before-effects, completed-verified, cancelled-before-effects, cancelled-recovered, completed-after-cancel-request, failed-recoverable, recovery-required and outcome-unknown as semantic categories. Native exit codes are transport mappings. A success requiring reboot is success-with-restart-disposition, not generic failure.

## Model tests
A reference state machine consumes events and predicts legal next actions. Generated event sequences include duplicated requests, delayed callbacks, loss of acknowledgement, repeated recovery and competing workers. The real implementation must match the model's safety properties; timing and progress coalescing may differ.

## Verifiable requirements

### USK-R-TXN-001 — Truthful uncertain outcomes

**Requirement.** A disconnect or crash after dispatch MUST NOT be reported as no-effects failure without proof.

**Rationale.** Effects may outlive the frontend.

**Acceptance.** `USK-AT-TXN-001` in the acceptance catalogue.

### USK-R-TXN-002 — Durable effect ordering

**Requirement.** Every critical external effect MUST have durable prior intent and a distinguishable observed completion record.

**Rationale.** Crash recovery needs a reconstruction boundary.

**Acceptance.** `USK-AT-TXN-002` in the acceptance catalogue.

### USK-R-TXN-003 — No global atomicity claim

**Requirement.** A multi-resource operation MUST report partial completion when rollback cannot atomically restore all resources.

**Rationale.** Registry, files and product databases differ.

**Acceptance.** `USK-AT-TXN-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
