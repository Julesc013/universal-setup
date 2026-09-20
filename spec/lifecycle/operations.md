---
type: "Engineering Specification"
title: "Lifecycle operation semantics and idempotence"
description: "Define every install and maintenance verb with distinct preconditions, effects and recovery."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-OPS","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-GEN"]}
---

# Lifecycle operation semantics and idempotence

## Operation table
| Operation | Meaning | Default preservation |
|---|---|---|
| inspect/detect | Observe package/installation identity and health | No writes |
| plan | Resolve exact requested change | No target writes |
| extract | Materialize verified portable payload under declared ownership mode | No implicit enrollment |
| install | Create a new managed installation from exact source | Refuse conflicting existing target |
| verify | Compare current owned resources with expected state | No repair |
| doctor | Assess health/prerequisites/recovery and propose remedies | No repair |
| repair | Restore selected release's damaged owned material | Preserve configuration/user data |
| modify | Change selected components/integration | Preserve retained components/data |
| update/downgrade | Transition exact versions with migration law | Explicit data compatibility |
| move | Materialize/verify destination then retire old owned resources when permitted | Cross-volume recovery explicit |
| rollback | Restore a retained compatible state | Never infer DB reversibility |
| uninstall | Remove still-owned payload/integration | Preserve user data by default |
| purge | Separate authorized data-removal plan | Scope precisely enumerated |
| recover | Execute one reviewed recovery disposition | Retain ambiguity |

No command is made available merely because it is listed. Each profile advertises inspect/plan/apply separately. An alias maps to the same descriptor and implementation, not another lifecycle path.

## Idempotency
A request key is scoped to principal, installation, semantic operation and request digest. Repeating the same key and same request returns the original operation/result. Reusing the key for different input refuses conflict. Retrying after transport loss first inspects the original operation; it does not allocate an unrelated second install.

## Move and self-maintenance
Cross-volume move cannot be assumed atomic: copy/stage, verify destination, publish and retain source until the retirement conditions are met. Self-maintenance must hand off to an intact worker outside the target. Post-install product launch, when requested, uses an explicit safe client/launcher path and must not inherit unintended elevated privilege.

## Verifiable requirements

### USK-R-OPS-001 — Doctor is nonmutating

**Requirement.** Doctor MUST emit findings/remedy plans without directly applying them.

**Rationale.** Diagnostic convenience is not elevated authority.

**Acceptance.** `USK-AT-OPS-001` in the acceptance catalogue.

### USK-R-OPS-002 — Idempotency conflict

**Requirement.** Reusing an idempotency key for different semantic input MUST refuse before effects.

**Rationale.** Retries cannot become unrelated changes.

**Acceptance.** `USK-AT-OPS-002` in the acceptance catalogue.

### USK-R-OPS-003 — Safe move

**Requirement.** Move MUST verify the new target and retain source material until the declared retirement guarantee is satisfied.

**Rationale.** Cross-volume copy can be interrupted.

**Acceptance.** `USK-AT-OPS-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
