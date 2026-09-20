---
type: "Engineering Specification"
title: "Bounded streaming across the whole lifecycle"
description: "Bound payload, metadata, handles, journals and reports independently of package size."
tags: ["universal-setup","io"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-STREAM","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-ID","USK-S-TXN"]}
---

# Bounded streaming across the whole lifecycle

## Source/target contracts
A source handle exposes immutable identity, length when known, sequential or range-read capabilities, exact read semantics, close and cancellation. A target sink exposes create-staging, bounded write, flush, metadata application, finalize-entry and abort/retain disposition. Short I/O is normal and must be handled; EOF before expected length is an integrity failure.

The planner carries entry metadata and source bindings, not file-sized byte arrays. The same rule applies to the installed preimage: compare old file digests/identities using bounded reads or on-disk indexes rather than retaining the whole old tree. The reviewed archive stream path uses fixed buffers; this does not prove every lifecycle path is bounded.

## Resource model
Separate maximum compressed/expanded bytes, per-entry size, total entries, path depth/length, metadata/index memory, open descriptors, active codecs, worker count, temporary disk, journal growth and output/report size. Compute overflow-safe limits before allocation. Large inventories can spill to a setup-owned bounded temporary index with integrity and cleanup rules.

Parallel work uses backpressure and a global budget allocator. Cancellation checkpoints occur between bounded chunks and at durable transaction boundaries. A per-stream buffer budget does not justify unbounded stream count. Performance reports include input shape, compression ratio, storage, peak resident memory, temporary space and cancellation latency.

## Verifiable requirements

### USK-R-STREAM-001 — Bound complete lifecycle memory

**Requirement.** Inspect, plan, install, verify, repair, move, update and recovery MUST obey aggregate memory budgets including old-tree inventories.

**Rationale.** Streaming extraction alone does not remove whole-tree retention.

**Acceptance.** `USK-AT-STREAM-001` in the acceptance catalogue.

### USK-R-STREAM-002 — Correct short I/O

**Requirement.** Readers and writers MUST handle partial reads/writes and reject premature EOF or overflow before commit.

**Rationale.** Real I/O is not guaranteed all-at-once.

**Acceptance.** `USK-AT-STREAM-002` in the acceptance catalogue.

### USK-R-STREAM-003 — Bound concurrency

**Requirement.** Concurrent streams MUST reserve from one aggregate operation budget and release reservations on every terminal path.

**Rationale.** Per-file limits otherwise multiply.

**Acceptance.** `USK-AT-STREAM-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^CONVERSATION].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
