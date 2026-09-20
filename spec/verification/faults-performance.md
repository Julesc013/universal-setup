---
type: "Engineering Specification"
title: "Fault campaigns and measurable performance budgets"
description: "Measure worst-case resource use and recovery instead of advertising literal perfection."
tags: ["universal-setup","verification"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-FAULT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-TEST","USK-S-STREAM","USK-S-REC"]}
---

# Fault campaigns and measurable performance budgets

## Fault plan
Instrument every durable transition: before/after intent append, flush, entry create/write/finalize, staging verification, publish, integration, state commit, audit, cleanup and recovery. Inject short I/O, ENOSPC, access loss, handle exhaustion, source mutation, target substitution, process death, disk/mount loss, clock changes and stale lease. Run deterministic seeds and retain minimal reproductions.

Simulated process termination is not abrupt power-loss proof. Power-loss campaigns identify storage device, filesystem, mount/options, OS image and flush assumptions. Verify actual post-restart observations independently. Ambiguous results retain material and block the corresponding stronger guarantee.

## Proposed initial performance budgets
These are engineering defaults to measure and tune, not supported universal promises: fixed per-stream chunk budget; maximum configured concurrent streams; disk-capacity reservation for staging+rollback+journal; bounded metadata index or spill; bounded event queues; responsive cancellation at declared safe points. Each target chooses quantitative limits and records benchmark corpus/hardware.

Measure startup/read-only latency, planning time, steady-state RSS, handles, throughput, temporary disk amplification, small-file metadata cost, cancellation latency, restart recovery time and UI input responsiveness. Benchmark tiny CLI, large asset archive and millions-of-entry metadata shapes separately. A speed improvement must not remove identity revalidation or retention.

## Verifiable requirements

### USK-R-FAULT-001 — Fault every durable boundary

**Requirement.** Critical lifecycle implementations MUST be exercised with interruption at each declared durable transition.

**Rationale.** Rare partial states cause destructive recovery bugs.

**Acceptance.** `USK-AT-FAULT-001` in the acceptance catalogue.

### USK-R-FAULT-002 — Measured resource budgets

**Requirement.** Each supported profile MUST publish measured memory, disk and cancellation bounds for its declared corpus class.

**Rationale.** Optimality needs observable criteria.

**Acceptance.** `USK-AT-FAULT-002` in the acceptance catalogue.

### USK-R-FAULT-003 — Power-loss honesty

**Requirement.** Power-loss-qualified claims MUST require actual abrupt-power evidence on the named storage profile.

**Rationale.** Exceptions and kill signals do not test storage durability.

**Acceptance.** `USK-AT-FAULT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
