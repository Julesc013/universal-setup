---
type: "Engineering Specification"
title: "Identity, encoding and canonical records"
description: "Make logical, native, content and execution identities distinct and unambiguous."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-ID","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-MODULES"]}
---

# Identity, encoding and canonical records

## Identity families
Publisher, product family, release, channel, package, component, installation instance, generation, source object, operation, attempt and effect have distinct IDs. A product may have multiple versions, architectures, scopes and channels installed concurrently. Paths and UI row numbers are locators, not stable identities.

A content reference contains algorithm, digest and byte length. A source reference additionally binds provider, source type and stable native identity when available. An installation reference binds installation ID, scope, target identity and expected state revision. A generation reference identifies exact immutable payload and metadata. Product version comparison uses an explicit scheme; product versions need not be SemVer merely because the USK package uses it.

## Encoding
Textual public records use UTF-8 with strict rejection of invalid sequences, duplicate JSON keys, unpaired surrogates, non-finite numbers and trailing data. Large byte counts, sequence counters and timestamps use canonical decimal strings when crossing JSON interfaces that may be consumed by binary64-only clients. No leading plus or unnecessary leading zero is permitted. Internal arithmetic is checked before allocation, offset addition or multiplication.

The proposed signed/hashable record profile excludes floating point. Object keys sort by Unicode scalar-value order, arrays retain semantic order, strings remain exact UTF-8 without silent normalization, and insignificant JSON whitespace is omitted. This project-specific canonical profile is not called RFC 8785/JCS. Every external signature or ecosystem adapter uses its mandated encoding explicitly. A domain/version prefix and byte-length framing precede hash inputs to prevent cross-record confusion.

## Native fidelity
Portable package paths and OS-native paths are different types. Unix names that are not valid UTF-8 may be represented as opaque native observations but are not silently admitted to the portable package profile. Case, normalization and reserved-name equivalence are resolved by the selected target policy, never by mutating the stored logical name globally.

Identity manifests contain no credentials. Display names and slugs are renameable; stable product/installation IDs do not derive from them.

## Verifiable requirements

### USK-R-ID-001 — Locator is not ownership

**Requirement.** No path, discovery record or product display name MAY establish installation ownership without an explicit installation identity and ownership record.

**Rationale.** Renames and external files are common.

**Acceptance.** `USK-AT-ID-001` in the acceptance catalogue.

### USK-R-ID-002 — Lossless public numbers

**Requirement.** Public counts and offsets MUST round-trip without precision loss across supported clients.

**Rationale.** Large archives exceed safe binary64 integers.

**Acceptance.** `USK-AT-ID-002` in the acceptance catalogue.

### USK-R-ID-003 — Canonical hash profile

**Requirement.** Every digest-bound record MUST name its canonicalization and domain/version rules.

**Rationale.** A digest over unspecified encoding is not portable.

**Acceptance.** `USK-AT-ID-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^USR-DISKED], [^USR-SYSPANE].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
