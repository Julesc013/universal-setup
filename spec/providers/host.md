---
type: "Engineering Specification"
title: "Provider host, registration and extension contracts"
description: "Make platform specialization explicit, bounded and replaceable without a premature giant SPI."
tags: ["universal-setup","providers"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-HOST","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CAPS","USK-S-API"]}
---

# Provider host, registration and extension contracts

## Provider families
Separate source, archive, filesystem/target, native-effect, state, cache, trust, privilege, package-manager, restart, clock/random and diagnostic interfaces. Each has an ID/version, implementation digest, target constraints, capability/guarantee set, execution mode, memory/lifetime contract and qualification references. Start with built-in implementations and test doubles; publish an SPI only when concrete variation is proved.

Registration is explicit and registry configuration freezes before concurrent operations begin. Dynamic unload while operations retain a provider is initially unsupported. Selection follows the capability/policy law, not discovery order. The plan pins exact selected providers; apply validates them again.

## Execution modes
Built-in static is the simplest release closure. Trusted shared providers require exact identity and loader search protection. Out-of-process providers offer crash separation and require authenticated bounded protocol; they are not automatically sandboxed. Privileged providers are independently installed/admitted and never an incidental effect of selecting a theme.

## Contracts
Use sized/versioned records, opaque handles, explicit allocator/ownership and cancellation. Provider failure reports preserve native error evidence without leaking secrets. State-write authority is not handed out through arbitrary path strings. Provider callbacks receive only admitted service capabilities.

## Extensibility
Products customize data first: names, payloads, components, recipes, policy, strings, presentation and target selection. Namespaced critical extensions refuse when unknown; optional extensions are retained and reported. No extension can grant capability absent from host/build/policy.

## Verifiable requirements

### USK-R-HOST-001 — Explicit provider loading

**Requirement.** Only explicitly configured and identity-verified providers MAY enter the runtime.

**Rationale.** Search paths are injection surfaces.

**Acceptance.** `USK-AT-HOST-001` in the acceptance catalogue.

### USK-R-HOST-002 — Provider lifetime

**Requirement.** A provider MUST remain alive while any operation/handle depends on it; unsupported unloading MUST refuse.

**Rationale.** Use-after-free crosses FFI/process boundaries.

**Acceptance.** `USK-AT-HOST-002` in the acceptance catalogue.

### USK-R-HOST-003 — Extension authority ceiling

**Requirement.** An extension MUST NOT widen effective policy or create arbitrary effects.

**Rationale.** No-fork customization cannot be privilege escalation.

**Acceptance.** `USK-AT-HOST-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
