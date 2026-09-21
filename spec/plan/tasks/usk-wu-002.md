---
type: "WorkUnit Definition"
title: "Reconcile source and contracts against the proposed baseline"
description: "Proposed M0 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-002","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-ADOPT","USK-S-RECON","USK-S-MAINT"]}
usk_task: {"id": "USK-WU-002","title": "Reconcile source and contracts against the proposed baseline","phase": "M0","status": "proposed","depends_on": ["USK-WU-001"],"spec_ids": ["USK-S-ADOPT","USK-S-RECON","USK-S-MAINT"],"requirement_ids": ["USK-R-MAINT-001","USK-R-MAINT-002","USK-R-ADOPT-001","USK-R-ADOPT-002"],"acceptance_ids": ["USK-AT-MAINT-001","USK-AT-MAINT-002","USK-AT-ADOPT-001","USK-AT-ADOPT-002"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["spec/**","docs/architecture/**","tests/**"],"read_only_paths": ["contracts/**","release/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Inventory current public ABI, schemas, descriptors and retained security tests.","Classify each proposed requirement implemented, partial, absent or unverified using exact source.","Record conflicts and source observations separately from requirements.","Generate brownfield mapping; do not rewrite existing code."],"deliverables": ["Baseline compatibility map","Open decision/risk records","Characterization test plan"],"risks": ["Historical attachments disagree; never overwrite newer proved behavior."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Reconcile source and contracts against the proposed baseline

## Goal
Reconcile source and contracts against the proposed baseline.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Inventory current public ABI, schemas, descriptors and retained security tests.
2. Classify each proposed requirement implemented, partial, absent or unverified using exact source.
3. Record conflicts and source observations separately from requirements.
4. Generate brownfield mapping; do not rewrite existing code.

## Deliverables
- Baseline compatibility map
- Open decision/risk records
- Characterization test plan

## Risks and review
- Historical attachments disagree; never overwrite newer proved behavior.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
