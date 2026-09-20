---
type: "Engineering Specification"
title: "C ABI, owned operations and language bindings"
description: "Expose stable memory, concurrency and progress semantics across native and managed consumers."
tags: ["universal-setup","interfaces"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-API","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-TXN"]}
---

# C ABI, owned operations and language bindings

## Preserve ABI 1.0
Retain existing context/create/execute/version/destroy signatures and borrowed-response lifetime. Add rather than silently alter struct layout, integer widths, calling convention or allocator pairing. The current ABI is an integration baseline, not a guarantee of arbitrary future binary compatibility.

## New operation/client surface
Provide owned-response copy/release plus begin, inspect/poll, request-cancel, take-result and release operations. Use opaque handles, explicit sized UTF-8 byte views, fixed-width status/flag fields and size/version prefixes. No exceptions or STL/toolkit objects cross the boundary. Return required size or an owning bounded buffer rather than writing beyond caller capacity.

A context is externally serialized unless the documented profile says otherwise. Independent contexts may operate concurrently subject to installation coordination. Callbacks cannot reenter the same context by default. Callback lifetime and user-data ownership extend only to the declared operation lifetime. Cancellation acceptance does not establish cancellation completion.

## Progress
Events identify operation, attempt, monotonically increasing sequence, semantic phase, known/unknown totals, current component/entry, completed units and cancellation disposition. Progress may coalesce, but critical transitions and terminal result must not disappear. Never invent a percentage when total work is unknown.

## Bindings
C++ RAII, C# P/Invoke, Rust and Objective-C/Swift wrappers should translate ownership and errors, not implement setup semantics. Shared-library boundaries isolate C++ runtime ABI; static consumers still require compatible linker/runtime closure. Run installed-package tests, allocator-failure tests and old-header/new-library tests per supported target.

## Verifiable requirements

### USK-R-API-001 — Borrowed ownership

**Requirement.** Adapters retaining results beyond the next context call MUST copy into owned storage with explicit release.

**Rationale.** GUI async state outlives scratch buffers.

**Acceptance.** `USK-AT-API-001` in the acceptance catalogue.

### USK-R-API-002 — Cancellation truth

**Requirement.** Cancellation APIs MUST distinguish request acceptance from terminal cancellation and preserve committed outcomes.

**Rationale.** Commit may race cancellation.

**Acceptance.** `USK-AT-API-002` in the acceptance catalogue.

### USK-R-API-003 — ABI evolution

**Requirement.** Public ABI changes MUST be additive within the supported major and validated against exported symbols, layouts and older consumers.

**Rationale.** C headers alone do not ensure binary compatibility.

**Acceptance.** `USK-AT-API-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^USR-DISKED], [^USR-SYSPANE], [^CONVERSATION].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
