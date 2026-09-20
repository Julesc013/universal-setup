---
type: "Engineering Specification"
title: "Archive validation, path projection and metadata fidelity"
description: "Treat archives as hostile carriers and preserve native semantics through explicit profiles."
tags: ["universal-setup","io"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-ARCHIVE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-STREAM","USK-S-CAPS"]}
---

# Archive validation, path projection and metadata fidelity

## Carrier is not package semantics
Directory, ZIP, TAR and future formats implement one bounded entry-manifest/stream interface. Begin with existing stored/Deflate ZIP/ZIP64; add other codecs only with independent qualification and licensing/provenance records. Reject unsupported methods rather than treating opaque compressed bytes as payload.

## Archive checks
Validate headers, central/local consistency, exact compressed and expanded boundaries, overlap, duplicate entries, checksums, limits, truncation and unsupported flags. Enforce per-entry and total expansion budgets, file count, path depth and processing time. Encrypted or multipart forms require an explicit capability and otherwise refuse.

## Path rules
Parse logical relative paths before any native join. Reject absolute paths, drive/device/UNC prefixes in the portable profile, traversal, NUL/control ambiguity, reserved names and target-projected collisions. Match Windows case/reserved/trailing-dot rules and macOS normalization equivalence through the selected target profile. Never globally lowercase or normalize identity. Reparse/symlink/hardlink entries are either prohibited or handled by an explicitly qualified type-specific provider; never followed incidentally.

## Native metadata
Modes, ACLs, ownership, xattrs, resource forks, symlinks, sparse extents and alternate streams have typed declarations. Unsupported critical metadata refuses before apply. Optional metadata loss is disclosed in the plan. Cross-platform export reports fidelity loss instead of pretending every filesystem is interchangeable.

## Verifiable requirements

### USK-R-ARCHIVE-001 — Reject dangerous paths

**Requirement.** Materialization MUST refuse traversal, absolute/device paths and target-equivalent collisions before creating payload objects.

**Rationale.** Archive names are attacker input.

**Acceptance.** `USK-AT-ARCHIVE-001` in the acceptance catalogue.

### USK-R-ARCHIVE-002 — Exact compressed boundaries

**Requirement.** Archive streaming MUST verify compressed boundaries, expanded length and required hashes/checksums before entry completion.

**Rationale.** Parser disagreement may admit hidden bytes.

**Acceptance.** `USK-AT-ARCHIVE-002` in the acceptance catalogue.

### USK-R-ARCHIVE-003 — Metadata fidelity

**Requirement.** Unsupported mandatory native metadata MUST cause refusal or an explicitly authorized transformation, never silent loss.

**Rationale.** Executable and access semantics depend on metadata.

**Acceptance.** `USK-AT-ARCHIVE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
