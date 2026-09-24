---
type: "WorkUnit Definition"
title: "Correct lifecycle schema and command compatibility"
description: "Proposed M1 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile":"usk-engineering/0.1.0-draft.1","id":"USK-S-TASK-010","revision":"3","status":"proposed","authority":"engineering-intent-only-after-adoption","owner":"universal-setup","layer":"plan","depends_on":["USK-S-ID","USK-S-PLAN","USK-S-OPS"]}
usk_task: {"id":"USK-WU-010","title":"Correct lifecycle schema and command compatibility","phase":"M1","status":"proposed","depends_on":["USK-WU-002"],"spec_ids":["USK-S-ID","USK-S-PLAN","USK-S-OPS"],"requirement_ids":["USK-R-ID-001","USK-R-ID-002","USK-R-ID-003","USK-R-PLAN-001","USK-R-PLAN-002","USK-R-PLAN-003","USK-R-OPS-001","USK-R-OPS-002","USK-R-OPS-003"],"acceptance_ids":["USK-AT-ID-001","USK-AT-ID-002","USK-AT-ID-003","USK-AT-PLAN-001","USK-AT-PLAN-002","USK-AT-PLAN-003","USK-AT-OPS-001","USK-AT-OPS-002","USK-AT-OPS-003"],"context_paths":["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths":["contracts/**","runtime/setup/kernel/**","runtime/setup/lifecycle/**","tests/**","docs/architecture/specification_implementation_inventory.v1.json"],"read_only_paths":["release/**","spec/**"],"forbidden_paths":["README.md",".git/**","external/**"],"forbidden_operations":["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps":["Inventory schema/command operation vocabulary including move.","Design additive versioned contract mapping and aliases.","Preserve published v1 IDs and readers.","Add schema/runtime descriptor conformance tests."],"deliverables":["Versioned contract proposal","Compatibility converter/fixtures","Descriptor parity checks"],"risks":["Do not silently enlarge a closed v1 contract."],"checks":[{"argv":["python","spec/tools/specctl.py","validate"],"status":"NOT_RUN","scope":"specification-integrity-only"},{"argv":["python","tools/structure_policy_check.py"],"status":"NOT_RUN","scope":"existing-repository-policy"},{"argv":["python","-m","unittest","discover","-s","tests","-v"],"status":"NOT_RUN","scope":"existing-repository-tests; qualify relevance and dependencies before execution"}],"required_binding":"active USK-SPEC-TO-RELEASE-01 campaign authority plus an exact task binding; exact target/environment receipt additionally required for endpoint or user-state effects","authorizes_implementation":false,"base_binding":"derive exact accepted source commit/tree, task-definition digest, current spec aggregate, non-widened scope and predecessor receipts","stop_conditions":["required source/spec inputs changed","active campaign authority or exact task binding unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion":"implementation plus specified evidence and independent technical review under active campaign policy; document count is insufficient"}
---

# Correct lifecycle schema and command compatibility

## Goal
Correct lifecycle schema and command compatibility.

## Preconditions
Pair this definition with an exact campaign task binding for the actual repository commit/tree, current spec manifest, non-widened scope and accepted predecessor receipts. This file is not a live AIDE task and cannot mint its own binding.

## Implementation steps
1. Inventory schema/command operation vocabulary including move.
2. Design additive versioned contract mapping and aliases.
3. Preserve published v1 IDs and readers.
4. Add schema/runtime descriptor conformance tests.

## Deliverables
- Versioned contract proposal
- Compatibility converter/fixtures
- Descriptor parity checks

## Risks and review
- Do not silently enlarge a closed v1 contract.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task, binding identity and any binding expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
