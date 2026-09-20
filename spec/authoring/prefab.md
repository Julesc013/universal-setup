---
type: "Engineering Specification"
title: "Prefab composition and customization without forks"
description: "Offer generic hosts, embedded bundles and custom shells as equivalent product profiles."
tags: ["universal-setup","authoring"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PREFAB","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTHOR","USK-S-GUI"]}
---

# Prefab composition and customization without forks

## Delivery alternatives
One-file setup, bootstrapper-plus-sidecar, full offline layout, portable archive with maintenance host, and native package delegation are explicit profiles. A single entrypoint, single physical file, zero extraction, self-contained runtime and portable behavior are independent properties. Do not advertise one from another.

For small modern Windows products, a native bootstrap can host or start the chosen GUI and worker with a sealed local bundle. For a large asset product, verified sidecar packages avoid enormous executable resources. On macOS, use native signed bundle/package conventions; on Linux, retain complete terminal installation even when graphical setup is optional.

## Customization tiers
Data: product names, icons, strings, help, component/default choices. Policy: permitted scopes, source trust, confirmation, retention and network. Declarative extension: schema/digest-bound optional data. Built-in provider: first-party customization requiring compilation. Out-of-process provider: separately qualified executable boundary. Custom shell: consumes presentation/operation contracts. Kernel forks are reserved for changed lifecycle law, not branding.

## Small-product budget
Provide an inspect-only and local-portable closure without native registration, network, GUI or service dependencies. Publish actual artifact size and runtime dependency inventories per target rather than promising one universal kilobyte size. The developer should be able to remove optional components at build composition, not merely hide UI controls that still import incompatible runtimes.

## Verifiable requirements

### USK-R-PREFAB-001 — Delivery properties explicit

**Requirement.** Release manifests MUST separately state entrypoint count, physical-file closure, extraction behavior, runtime dependency and installation mode.

**Rationale.** Single file is not zero dependency.

**Acceptance.** `USK-AT-PREFAB-001` in the acceptance catalogue.

### USK-R-PREFAB-002 — Customization cannot change law

**Requirement.** Data-only customization MUST NOT alter plan authorization, verification or recovery semantics.

**Rationale.** OEM appearance should not create a forked engine.

**Acceptance.** `USK-AT-PREFAB-002` in the acceptance catalogue.

### USK-R-PREFAB-003 — No incompatible closure

**Requirement.** Unselected providers/frontends MUST be absent from the final binary dependency closure when their runtime raises the target floor.

**Rationale.** Hiding a button does not fix loader imports.

**Acceptance.** `USK-AT-PREFAB-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^USR-DISKED], [^USR-SYSPANE].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
