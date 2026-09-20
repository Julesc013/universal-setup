---
type: "WorkUnit Definition"
title: "Build first native prefab and interface laboratory"
description: "Proposed M3 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-018","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-GUI","USK-S-PREFAB"]}
usk_task: {"id": "USK-WU-018","title": "Build first native prefab and interface laboratory","phase": "M3","status": "proposed","depends_on": ["USK-WU-014","USK-WU-016"],"spec_ids": ["USK-S-GUI","USK-S-PREFAB"],"requirement_ids": ["USK-R-GUI-001","USK-R-GUI-002","USK-R-GUI-003","USK-R-PREFAB-001","USK-R-PREFAB-002","USK-R-PREFAB-003"],"acceptance_ids": ["USK-AT-GUI-001","USK-AT-GUI-002","USK-AT-GUI-003","USK-AT-PREFAB-001","USK-AT-PREFAB-002","USK-AT-PREFAB-003"],"allowed_paths": ["apps/gui/**","contracts/schema/setup/**","tests/**","tools/**"],"read_only_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Admit one toolkit subdirectory through a separate policy review.","Implement System Native and bounded OEM+ branding.","Create native component gallery and accessibility harness.","Qualify install/maintenance/recovery alongside CLI/TUI."],"deliverables": ["First native setup shell","Component gallery","Exact interface evidence packet"],"risks": ["Existing apps/gui policy must be amended, not bypassed."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Build first native prefab and interface laboratory

## Goal
Build first native prefab and interface laboratory.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Admit one toolkit subdirectory through a separate policy review.
2. Implement System Native and bounded OEM+ branding.
3. Create native component gallery and accessibility harness.
4. Qualify install/maintenance/recovery alongside CLI/TUI.

## Deliverables
- First native setup shell
- Component gallery
- Exact interface evidence packet

## Risks and review
- Existing apps/gui policy must be amended, not bypassed.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
