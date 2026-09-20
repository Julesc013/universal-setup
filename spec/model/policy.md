---
type: "Engineering Specification"
title: "Policy composition, authorization and deployment intent"
description: "Separate engineering delegation, endpoint intent, technical capability and trusted publisher identity."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-POLICY","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CAPS"]}
---

# Policy composition, authorization and deployment intent

## Four questions
Can the implementation perform this operation? Is the exact package trusted under local policy? Is the requesting principal permitted to perform these effects? Has the specific machine plan remained valid? None of these implies the others.

## Policy composition
Effective policy is the intersection of kernel safety constraints, target/provider limitations, administrator policy, deployment policy, product policy and user request. Lower layers narrow authority. Scalar precedence is used only for preferences within the surviving permitted set. Deny and critical constraints are never silently replaced by a later file.

A reviewed plan may be authorized interactively or by a previously admitted unattended-deployment policy. End users do not require a maintainer-issued CI receipt for every install. Engineering acceptance lanes and D0–D4 delegations control development, not a mandatory customer deployment service.

## Execution authorization
A local authorization binds principal, exact plan digest, install/target identity, allowed effects, provider identity, effective-policy revision, expiry/deadline rules and replay scope. It may use authenticated IPC and OS credentials rather than inventing a universal token cryptosystem. Exported or remote authorization requires an explicitly specified authentication/signature mechanism.

A plan is immutable. Changed machine observations cause explicit replanning and renewed authorization when the material effect set changes. Cancellation is a request subject to transaction phase; it does not erase effects.

## Configuration and secrets
Response files contain typed choices and secret references, not arbitrary commands. Broker/worker mode uses plan-bound configuration and ignores unrelated current-directory files, environment overrides, themes and UI plugins. A credential handle is meaningful only to its admitted provider and scope.

## Verifiable requirements

### USK-R-POLICY-001 — Narrowing composition

**Requirement.** Effective policy MUST NOT grant an operation denied by a higher safety or administrator constraint.

**Rationale.** Untrusted product data cannot elevate itself.

**Acceptance.** `USK-AT-POLICY-001` in the acceptance catalogue.

### USK-R-POLICY-002 — Unattended equivalence

**Requirement.** Unattended deployment MUST use the same planning, authorization and verification semantics as interactive deployment without unexpected UI.

**Rationale.** Enterprise mode is not a bypass.

**Acceptance.** `USK-AT-POLICY-002` in the acceptance catalogue.

### USK-R-POLICY-003 — No plan drift

**Requirement.** Execution MUST revalidate all declared material inputs and MUST NOT silently replace the reviewed effect set.

**Rationale.** Plans can become stale.

**Acceptance.** `USK-AT-POLICY-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
