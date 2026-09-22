---
type: "WorkUnit Definition"
title: "Deliver independent local lifecycle qualification"
description: "Proposed M1 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-011","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-TEST","USK-S-FAULT","USK-S-OPS"]}
usk_task: {"id": "USK-WU-011","title": "Deliver independent local lifecycle qualification","phase": "M1","status": "proposed","depends_on": ["USK-WU-009","USK-WU-010"],"spec_ids": ["USK-S-TEST","USK-S-FAULT","USK-S-OPS"],"requirement_ids": ["USK-R-OPS-001","USK-R-OPS-002","USK-R-OPS-003","USK-R-TEST-001","USK-R-TEST-002","USK-R-TEST-003","USK-R-FAULT-001","USK-R-FAULT-002","USK-R-FAULT-003"],"acceptance_ids": ["USK-AT-OPS-001","USK-AT-OPS-002","USK-AT-OPS-003","USK-AT-TEST-001","USK-AT-TEST-002","USK-AT-TEST-003","USK-AT-FAULT-001","USK-AT-FAULT-002","USK-AT-FAULT-003"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["tests/**","tools/**","docs/testing/**","release/index/**"],"read_only_paths": ["contracts/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Run tiny and large local product fixtures on named Windows/POSIX profiles.","Use independent post-state oracles.","Exercise fault, cancellation, low-space, preservation and recovery matrix.","Record only guarantees actually executed."],"deliverables": ["Local lifecycle evidence packet","Precise support candidate","Remaining target blockers"],"risks": ["Native or destructive tests require admitted lab; no substitute PASS."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_binding": "active USK-SPEC-TO-RELEASE-01 campaign authority plus an exact task binding; exact target/environment receipt additionally required for endpoint or user-state effects","authorizes_implementation": false,"base_binding": "derive exact accepted source commit/tree, task-definition digest, current spec aggregate, non-widened scope and predecessor receipts","stop_conditions": ["required source/spec inputs changed","active campaign authority or exact task binding unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent technical review under active campaign policy; document count is insufficient"}
---

# Deliver independent local lifecycle qualification

## Goal
Deliver independent local lifecycle qualification.

## Preconditions
Pair this definition with an exact campaign task binding for the actual repository commit/tree, current spec manifest, non-widened scope and accepted predecessor receipts. This file is not a live AIDE task and cannot mint its own binding.

## Implementation steps
1. Run tiny and large local product fixtures on named Windows/POSIX profiles.
2. Use independent post-state oracles.
3. Exercise fault, cancellation, low-space, preservation and recovery matrix.
4. Record only guarantees actually executed.

## Deliverables
- Local lifecycle evidence packet
- Precise support candidate
- Remaining target blockers

## Risks and review
- Native or destructive tests require admitted lab; no substitute PASS.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task, binding identity and any binding expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
