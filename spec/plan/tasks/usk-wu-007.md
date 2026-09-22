---
type: "WorkUnit Definition"
title: "Add per-install leases and stale-worker fencing"
description: "Proposed M1 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-007","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-LEASE","USK-S-POLICY"]}
usk_task: {"id": "USK-WU-007","title": "Add per-install leases and stale-worker fencing","phase": "M1","status": "proposed","depends_on": ["USK-WU-006"],"spec_ids": ["USK-S-LEASE","USK-S-POLICY"],"requirement_ids": ["USK-R-POLICY-001","USK-R-POLICY-002","USK-R-POLICY-003","USK-R-LEASE-001","USK-R-LEASE-002","USK-R-LEASE-003"],"acceptance_ids": ["USK-AT-POLICY-001","USK-AT-POLICY-002","USK-AT-POLICY-003","USK-AT-LEASE-001","USK-AT-LEASE-002","USK-AT-LEASE-003"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["runtime/setup/transaction/**","runtime/setup/state/**","runtime/platform/**","tests/**"],"read_only_paths": ["contracts/**","release/**","docs/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Define lock order, holder identity and state revision.","Implement target-specific locking and takeover/fencing behavior.","Revalidate after lock acquisition.","Test paused old worker, reused PID and conflicting installers."],"deliverables": ["Lease protocol and implementation","Contention/cancellation tests","Recovery takeover evidence"],"risks": ["Timeout alone must not allow old worker commit."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Add per-install leases and stale-worker fencing

## Goal
Add per-install leases and stale-worker fencing.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Define lock order, holder identity and state revision.
2. Implement target-specific locking and takeover/fencing behavior.
3. Revalidate after lock acquisition.
4. Test paused old worker, reused PID and conflicting installers.

## Deliverables
- Lease protocol and implementation
- Contention/cancellation tests
- Recovery takeover evidence

## Risks and review
- Timeout alone must not allow old worker commit.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
