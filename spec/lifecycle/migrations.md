---
type: "Engineering Specification"
title: "State and application-data migration"
description: "Version readers, writers and transformation edges without conflating payload and user-data rollback."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-MIG","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-OWN","USK-S-REC"]}
---

# State and application-data migration

## Migration graph
Each edge identifies source/target schema versions, implementation identity, applicability, preconditions, loss classification, backup policy, output verification and inverse/restore disposition. Cycles are not assumed useful; select a deterministic compatible route and reject ambiguity. A new reader may preserve unknown optional fields; unknown critical state blocks mutation.

USK migrates its own installed-state/journal representations under USK authority. Product configuration or databases require a product-owned migration definition executed through a bounded adapter. USK must not interpret a catalogue, disk image, save file or repository merely because it carries the product's files.

## Safe sequence
Inspect source, obtain exclusive required scope, bind revision, create verified backup/snapshot where required, transform into staging, validate complete target, publish with recorded recovery boundary, retain source/backup for the specified window. Migration is not performed on every read. Inspection of a future format may report unsupported and preserve the bytes.

## Downgrade
Identify whether the old application can read current data; if not, choose supported backward migration or explicit backup restoration. Surface data loss before authorization. Installing old payload while leaving incompatible data must not be called a completed downgrade.

A release compatibility matrix records min reader/writer versions separately. Journal recovery readers should remain distributable after the generating version is retired.

## Verifiable requirements

### USK-R-MIG-001 — Unknown critical format

**Requirement.** Unknown critical state fields or record versions MUST block mutation while permitting safe retention/export.

**Rationale.** Forward compatibility must not mean data loss.

**Acceptance.** `USK-AT-MIG-001` in the acceptance catalogue.

### USK-R-MIG-002 — Migration rollback truth

**Requirement.** A migration MUST declare inverse, backup restore, forward-only or operator-only recovery.

**Rationale.** Payload rollback cannot establish data reversal.

**Acceptance.** `USK-AT-MIG-002` in the acceptance catalogue.

### USK-R-MIG-003 — Migration atomic scope

**Requirement.** State migration MUST stage and validate outputs before replacing its declared authoritative records.

**Rationale.** Interrupted partial rewrite destroys history.

**Acceptance.** `USK-AT-MIG-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
