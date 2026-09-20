---
type: "Engineering Specification"
title: "Setup application service and presentation model"
description: "One setup meaning behind native GUI, TUI, CLI and embedded maintenance."
tags: ["universal-setup","interfaces"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PRESENT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-API","USK-S-OPS"]}
---

# Setup application service and presentation model

## Stable view model
A SetupPresentationSnapshot contains product identity, installation observation, supported/available actions, current selection, expected revision, component/prerequisite choices, plan summary, effect groups, space/restart estimates, warnings, progress, terminal result and recovery actions. The snapshot is immutable derived state, not another installation database.

Semantic actions contain action ID, resource references, expected snapshot/state revision, request/idempotency identity, choices and policy context. Native widgets never call filesystem or native-registration APIs directly. They may retain selection, focus, drafts and layout, but not independent readiness, permission, verification or recovery truth.

## Flow
First-time default installation should normally be Review -> Install -> Verified result. Add destination, scope, prerequisites or components pages only when a real choice exists. Maintenance offers inspect, Doctor, verify, repair, modify, update/downgrade, uninstall and recovery according to actual capability. Do not display future features as apparently working buttons.

The stock kit is product-neutral. Products supply identity, text, defaults, help links, legal notices and branding; no product-specific semantics enter the kernel. Custom frontends may replace the stock shell while satisfying semantic/accessibility conformance.

## Authority display
Separate integrity, publisher authenticity, eligibility, permissions, verification and support. A checksum match is not an authenticated publisher. A visible button is not consent. Show significant effects and retained data before authorization; do not hide privilege changes behind artwork or adaptive UI.

## Verifiable requirements

### USK-R-PRESENT-001 — Semantic frontend parity

**Requirement.** Every required ordinary setup journey MUST have equivalent normalized plans, effects and outcomes through the declared interfaces.

**Rationale.** Multiple frontends must not mean multiple installers.

**Acceptance.** `USK-AT-PRESENT-001` in the acceptance catalogue.

### USK-R-PRESENT-002 — No UI authority

**Requirement.** Presentation MAY render only backend-admitted actions and MUST NOT implement installed-state effects.

**Rationale.** Native polish cannot bypass policy.

**Acceptance.** `USK-AT-PRESENT-002` in the acceptance catalogue.

### USK-R-PRESENT-003 — Stale view handling

**Requirement.** An action against a stale relevant revision MUST refresh or refuse before effects.

**Rationale.** Concurrent interfaces can change state.

**Acceptance.** `USK-AT-PRESENT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^USR-FACMAN], [^USR-SYSPANE].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
