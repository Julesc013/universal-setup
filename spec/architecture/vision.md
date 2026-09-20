---
type: "Engineering Specification"
title: "Product vision, scope and measurable completion"
description: "Define the embeddable engine and ready-made setup family without requiring a universal monolith."
tags: ["universal-setup","architecture"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-VISION","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTH"]}
---

# Product vision, scope and measurable completion

## End product
Universal Setup makes simple installations trivial, complex deployments explicit, and failures recoverable. It has two first-class consumption modes: a small embeddable SDK and a product-branded native setup/maintenance application compiled from declarative data. Both use the same installation authority.

The platform includes a semantic kernel (USK), replaceable host/platform implementations (USU), authoring/compiler tools, a setup application service, optional CLI/TUI/native shells and conformance tooling. These are independently selectable modules inside one repository. A tiny CLI must not depend on a fleet manager, a web server, AIDE, model inference, every codec or every GUI toolkit.

## Product promises
A developer can define a neutral single-binary product, construct a setup package, inspect its plan, install, verify, deliberately damage, repair, update, recover interruption, roll back where supported and uninstall while preserving user data. A larger application adds components and policies rather than editing the kernel.

## Non-goals
USK is not product-specific business logic, a storefront, a DRM server, a raw-disk engine, a launcher, an unrestricted scripting host or a mandatory background service. Fleet scheduling and dashboards are integrations outside the mutation kernel. A native package manager remains the authority for its owned resources.

## Done is profile-specific
A supported profile names operations, target/runtime/filesystem, input formats, resource limits, authority assumptions, recovery ceilings, UI coverage and retained proof. A folder, command or API name being present does not make it usable or supported. A first supported local profile need not wait for every optional network or enterprise capability.

## Verifiable requirements

### USK-R-VISION-001 — No-fork tiny product

**Requirement.** A supported authoring profile MUST create a usable setup/maintenance product for a one-binary payload using only a declarative definition and optional assets.

**Rationale.** Reusability must be externally demonstrable.

**Acceptance.** `USK-AT-VISION-001` in the acceptance catalogue.

### USK-R-VISION-002 — Selective composition

**Requirement.** Consumers MUST be able to select contracts, authoring, inspect-only, embedded or prefab use without linking unrelated applications and providers.

**Rationale.** Small products should remain small.

**Acceptance.** `USK-AT-VISION-002` in the acceptance catalogue.

### USK-R-VISION-003 — Profile-specific claims

**Requirement.** Support MUST be expressed per operation and exact target profile, independently of implementation and permission.

**Rationale.** Universal semantics are not universal guarantees.

**Acceptance.** `USK-AT-VISION-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^REPO-README], [^USR-SYSPANE], [^USR-DISKED].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
