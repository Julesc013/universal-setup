---
type: "Engineering Specification"
title: "Ownership, configuration and user-data preservation"
description: "One mutation owner per resource with separate repair, uninstall and purge semantics."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-OWN","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-ID","USK-S-PLAN"]}
---

# Ownership, configuration and user-data preservation

## Ownership classes
An installation distinguishes immutable shipped payload, mutable application configuration, user-created data, cache, USK state, retained recovery material and secret references. Physical proximity never merges ownership. Prefer separate sibling roots; signed app bundles contain no mutable settings or receipts.

Owner types are USK-managed, native-package-managed, storefront-managed, imported-read-only and unmanaged. Observation and registration do not create overwrite authority. An adoption operation either proves an explicit custody transfer or copies into a new managed root; it does not manufacture an ownership manifest for arbitrary existing files.

Each owned effect records its identity and expected current value. A shortcut, PATH entry, registry value, service or association modified by another actor is a conflict, not a resource to overwrite blindly. Ownership keys must include platform namespace, scope and architecture view where relevant.

## Lifecycle rules
Repair restores the exact selected release's payload using a verified source; it is not an upgrade. Uninstall removes still-owned payload/integration and preserves user data by default. Purge is a separate plan with explicit classes and destructive acknowledgement. Unknown or modified content is retained or reported for review. Do not recursively delete a containing directory merely to make uninstall appear clean.

Configuration migrations have independent version edges, backup rules, merge/conflict handling and rollback loss reports. Restoring old program binaries does not establish that new user data is readable by the old version. Logs and recovery evidence have privacy and retention policies but must not be deleted while needed by an unresolved transaction.

## Verifiable requirements

### USK-R-OWN-001 — Preserve unknown content

**Requirement.** Repair and uninstall MUST preserve unknown or externally modified resources unless a separately reviewed plan explicitly owns that change.

**Rationale.** Prevent user data loss.

**Acceptance.** `USK-AT-OWN-001` in the acceptance catalogue.

### USK-R-OWN-002 — Repair is not upgrade

**Requirement.** Repair MUST bind a specific release/generation and MUST NOT silently substitute the latest available package.

**Rationale.** Recoverability needs deterministic sources.

**Acceptance.** `USK-AT-OWN-002` in the acceptance catalogue.

### USK-R-OWN-003 — Native owner delegation

**Requirement.** USK MUST NOT directly alter payload owned by a native package manager.

**Rationale.** Two mutation owners corrupt servicing.

**Acceptance.** `USK-AT-OWN-003` in the acceptance catalogue.

### USK-R-OWN-004 — Separate purge

**Requirement.** Uninstall MUST NOT imply deletion of product data, secrets or unrelated recovery records.

**Rationale.** Removal and data destruction have different authority.

**Acceptance.** `USK-AT-OWN-004` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-SYSPANE], [^USR-DISKED], [^CONVERSATION].

[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
