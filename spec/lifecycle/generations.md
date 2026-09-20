---
type: "Engineering Specification"
title: "Generations, retention and garbage collection"
description: "Maintain immutable payload generations with explicit activation and safe reclamation."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-GEN","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-REC","USK-S-OWN"]}
---

# Generations, retention and garbage collection

## Layout semantics
A generation is an immutable, verified payload closure with installation binding and manifest. Its physical layout may use directories, content-store objects or a native package receipt. Mutable configuration, user data and setup journals are outside the immutable payload. An active-generation reference selects future launches; it is not necessarily a symlink on every target.

## Update sequence
Plan from exact active state. Stage candidate, verify closure, record publish intent, publish candidate generation, perform compatible native integration, activate using the profile's declared visibility mechanism, verify, publish state/audit, retain predecessor and finally schedule optional cleanup. The exact ordering of native effects and activation must be declared by each plan's recovery model.

Running processes may retain old generations. Use optional ULK/product leases or a conservative quiescence policy. An update can prepare while a previous version runs only when the profile qualifies that behavior. Binary rollback is separate from configuration/database compatibility.

## Retention and GC
Roots include current generation, retained rollback generations, active sessions, pending operations, unresolved recovery, user pins and native-owner references. GC first emits a reviewed collection plan; it never follows untrusted links or deletes outside owned storage. Age and disk pressure may select candidates but do not override roots. Immutable cache blocks may be shared only with an explicit safety and licensing policy; writable hardlinks to installed payload are prohibited.

## Verifiable requirements

### USK-R-GEN-001 — Keep live generations

**Requirement.** Generation reclamation MUST preserve generations referenced by active leases or unresolved operations.

**Rationale.** Files can remain in use after activation changes.

**Acceptance.** `USK-AT-GEN-001` in the acceptance catalogue.

### USK-R-GEN-002 — Rollback compatibility

**Requirement.** Rollback MUST evaluate product-data compatibility separately from payload availability.

**Rationale.** Old binary plus migrated DB can corrupt data.

**Acceptance.** `USK-AT-GEN-002` in the acceptance catalogue.

### USK-R-GEN-003 — Immutable cache isolation

**Requirement.** Shared cached content MUST NOT be writable through an installed application path.

**Rationale.** One product could poison every consumer.

**Acceptance.** `USK-AT-GEN-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
