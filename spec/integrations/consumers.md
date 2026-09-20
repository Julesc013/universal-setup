---
type: "Engineering Specification"
title: "Consumer boundaries and qualification roles"
description: "Reuse setup machinery across products without importing their business or hazardous-domain semantics."
tags: ["universal-setup","integrations"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-EUREKA","resource": "urn:sha256:d466fef4c8c06adb4a64c1069ba098e623bee0bdce1af13baddf4c0b30c7097b","title": "User-supplied Eureka setup integration review"},{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CONSUMER","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-OWN","USK-S-PREFAB"]}
---

# Consumer boundaries and qualification roles

| Consumer | Product-owned meaning | USK-owned handoff | Special test |
|---|---|---|---|
| Dominium | Engine/game/tool/assets composition, rights, product data | Qualified package lifecycle | Large component graph and generations |
| FacMan | Game versions, instances, content, saves, readiness | Managed software and FacMan payload lifecycle | Leases, exact payload, user content retained |
| SysPane | Telemetry, settings, themes and native desktop behavior | App files and declared integration | Runtime independent; mutable history preserved |
| DiskEd | Raw devices, partitions, filesystem/storage operations | DiskEd application lifecycle only | Setup cannot gain raw-device rights; active storage interlock |
| Eureka | Candidate identity, provenance, rights and action eligibility | Exact reviewed artifact plan/effects | Discovery never grants installation rights |
| AIDE | Developer tasks, models/tools and workspaces | Its own qualified product/tool packages | No agent state or secrets bundled; not required at endpoint |
| Catalogue app | User catalogue schema and saves | App package lifecycle | Database never removed by ordinary uninstall |
| Neutral tiny app | One binary and simple data | Stock setup definition | No source changes or internal infrastructure required |

These are integration contracts and planned qualification roles, not current product implementation claims. No consumer must use both ULK and USK. Product-specific migration/quiescence adapters have bounded protocols; the kernel does not parse their application data.

Embedded maintenance and separate setup envelopes are alternatives selected per target. Both consume the same finalized portable payload and require an independent intact recovery source. A single-public-entrypoint goal must not contaminate a storage-privileged broker with general software installation authority.

## Verifiable requirements

### USK-R-CONSUMER-001 — Storage authority separation

**Requirement.** A DiskEd-like consumer setup path MUST have no general raw-device or filesystem-repair dispatch authority.

**Rationale.** Repair application is not repair user storage.

**Acceptance.** `USK-AT-CONSUMER-001` in the acceptance catalogue.

### USK-R-CONSUMER-002 — Eureka eligibility remains product-owned

**Requirement.** A discovered or cached artifact MUST NOT become eligible for installation solely because the consumer found it.

**Rationale.** Evidence/rights/access remain independent.

**Acceptance.** `USK-AT-CONSUMER-002` in the acceptance catalogue.

### USK-R-CONSUMER-003 — One installed-state authority

**Requirement.** Consumers MUST reference USK state/receipts rather than maintain competing installed-state truth.

**Rationale.** Two repair/uninstall inventories drift.

**Acceptance.** `USK-AT-CONSUMER-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-DISKED], [^USR-SYSPANE], [^USR-EUREKA], [^REPO-README], [^CONVERSATION].

[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-EUREKA]: User-supplied Eureka setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:d466fef4c8c06adb4a64c1069ba098e623bee0bdce1af13baddf4c0b30c7097b`.
[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
