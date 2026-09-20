---
type: "Engineering Specification"
title: "Installation leases, revisions and stale-worker fencing"
description: "Prevent parallel installers and recovered workers from committing incompatible transitions."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-LEASE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PUB"]}
---

# Installation leases, revisions and stale-worker fencing

## Lock scopes
Define distinct coordination for installation state, generation activation, shared verified cache, native shared prerequisite and authoring output. Avoid a global machine-wide lock unless a native backend demands it. Locks protect invariants, not every read-only observation.

Per-install operation ownership binds install ID, native state-root identity, operation/attempt, expected state revision and holder identity. Use OS-supported exclusive locking and a monotonically advancing ownership/fencing generation where the target can enforce it. A PID alone is insufficient because PIDs are reused.

## Acquisition and handoff
Acquire in documented total order to prevent deadlock. Recheck state after acquisition. Persist ownership before effects. On restart, classify holder status and recover outstanding intent before admitting a replacement worker. A timed-out lease is not permission to race an old live worker; stale-worker commit must be rejected by the publisher/state service or the profile must declare weaker guarantees and prohibit automatic takeover.

ULK can supply running-session/generation references, but USK owns its installation lock and does not require ULK for simple standalone installs. Product quiescence is a bounded protocol, not kill-by-name. A lease for deleting old generations differs from mutation authorization.

## Verifiable requirements

### USK-R-LEASE-001 — Reject stale worker

**Requirement.** After authority transfers, an earlier worker MUST be unable to commit under an obsolete lease/revision in a profile claiming automatic takeover.

**Rationale.** Timeout alone does not fence writes.

**Acceptance.** `USK-AT-LEASE-001` in the acceptance catalogue.

### USK-R-LEASE-002 — Bound lock contention

**Requirement.** Lock acquisition MUST have a cancellation/deadline path and a structured conflicting-operation result.

**Rationale.** Hanging is not safe coordination.

**Acceptance.** `USK-AT-LEASE-002` in the acceptance catalogue.

### USK-R-LEASE-003 — State after locking

**Requirement.** A worker MUST revalidate expected installed state after acquiring the lease and before first effects.

**Rationale.** Observation may predate another completed operation.

**Acceptance.** `USK-AT-LEASE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
