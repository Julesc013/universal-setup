---
type: "WorkUnit Definition"
title: "Bound preimage inventory and full lifecycle memory"
description: "Proposed M1 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-005","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-STREAM","USK-S-ARCHIVE"]}
usk_task: {"id": "USK-WU-005","title": "Bound preimage inventory and full lifecycle memory","phase": "M1","status": "proposed","depends_on": ["USK-WU-002"],"spec_ids": ["USK-S-STREAM","USK-S-ARCHIVE"],"requirement_ids": ["USK-R-STREAM-001","USK-R-STREAM-002","USK-R-STREAM-003","USK-R-ARCHIVE-001","USK-R-ARCHIVE-002","USK-R-ARCHIVE-003"],"acceptance_ids": ["USK-AT-STREAM-001","USK-AT-STREAM-002","USK-AT-STREAM-003","USK-AT-ARCHIVE-001","USK-AT-ARCHIVE-002","USK-AT-ARCHIVE-003"],"allowed_paths": ["runtime/setup/lifecycle/**","runtime/base/**","runtime/setup/streaming/**","tests/**","docs/testing/**"],"read_only_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Characterize read_complete_tree and every file-sized payload retention path.","Replace old-tree byte storage with bounded metadata/digest observations.","Add spill/index budgets where metadata volume requires them.","Measure install/verify/repair/move/update/recovery separately."],"deliverables": ["Bounded old-tree representation","Memory/resource tests","Compatibility comparison"],"risks": ["Do not remove identity revalidation for speed."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Bound preimage inventory and full lifecycle memory

## Goal
Bound preimage inventory and full lifecycle memory.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Characterize read_complete_tree and every file-sized payload retention path.
2. Replace old-tree byte storage with bounded metadata/digest observations.
3. Add spill/index budgets where metadata volume requires them.
4. Measure install/verify/repair/move/update/recovery separately.

## Deliverables
- Bounded old-tree representation
- Memory/resource tests
- Compatibility comparison

## Risks and review
- Do not remove identity revalidation for speed.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
