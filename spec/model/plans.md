---
type: "Engineering Specification"
title: "Machine plans, typed effects and verification obligations"
description: "Specify exact reviewed effects without arbitrary script escape hatches."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PLAN","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-BUNDLE","USK-S-POLICY"]}
---

# Machine plans, typed effects and verification obligations

## Plan envelope
A plan binds format version, plan ID/digest, product bundle digest, installation ID, expected installation revision, target/provider identities, effective policy digest, requested lifecycle operation, selected components, source identities, prerequisite observations, effects, ordering, resource estimates, expiration rules and recovery strategy.

The plan digest covers semantic inputs and ordering but excludes display formatting and the digest field itself. A plan is not executable authority. Display names are advisory. Execution matches IDs and digests.

## Typed effects
Initial families are directory.create, file.materialize, file.remove-owned, metadata.apply, generation.publish, generation.activate, state.publish and audit.append. Native integration later adds shortcut, application registration, association, service, environment and package-manager delegation effects.

Every effect includes: ID, target root class and relative locator, expected pre-state, desired state, required capability, required privilege, idempotence key, verification, compensation/forward-recovery rule, criticality and dependencies. Unknown critical effects refuse. Unknown optional effects can be skipped only when the authored recipe permits that exact degradation, and the skip is recorded.

External vendor executables are not arbitrary shell hooks. An explicitly admitted delegation adapter binds exact executable identity, structured arguments, detect/eligibility logic, time/space budgets, return-code mapping and non-atomic/recovery limits. It gains no generic recursive write authority from being a prerequisite.

## Verification
Execution success is not verification. Each effect has an independent observer of the filesystem, native registration, service or external package receipt. Verification may conclude verified, failed, inconclusive or blocked. A partly verified operation cannot be flattened into success.

## Verifiable requirements

### USK-R-PLAN-001 — Effect closure

**Requirement.** Every externally visible setup effect MUST appear in the reviewed plan or be a specifically declared internal staging/journal effect.

**Rationale.** Frontends must not bolt on unmanaged registrations.

**Acceptance.** `USK-AT-PLAN-001` in the acceptance catalogue.

### USK-R-PLAN-002 — No arbitrary hook

**Requirement.** Recipes MUST NOT admit unrestricted shell, downloaded-code or administrator hooks.

**Rationale.** Extensibility must not erase safety law.

**Acceptance.** `USK-AT-PLAN-002` in the acceptance catalogue.

### USK-R-PLAN-003 — Independent verification

**Requirement.** Terminal success MUST require all critical effect verification obligations to succeed.

**Rationale.** Executor assertions are insufficient.

**Acceptance.** `USK-AT-PLAN-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
