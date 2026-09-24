---
type: "WorkUnit Definition"
title: "Implement the qualified staged-child publisher"
description: "Proposed M1 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile":"usk-engineering/0.1.0-draft.1","id":"USK-S-TASK-006","revision":"5","status":"proposed","authority":"engineering-intent-only-after-adoption","owner":"universal-setup","layer":"plan","depends_on":["USK-S-PUB","USK-S-PLAT"]}
usk_task: {"id":"USK-WU-006","title":"Implement the qualified staged-child publisher","phase":"M1","status":"proposed","depends_on":["USK-WU-004","USK-WU-005"],"spec_ids":["USK-S-PUB","USK-S-PLAT"],"requirement_ids":["USK-R-PUB-001","USK-R-PUB-002","USK-R-PUB-003","USK-R-PLAT-001","USK-R-PLAT-002","USK-R-PLAT-003"],"acceptance_ids":["USK-AT-PUB-001","USK-AT-PUB-002","USK-AT-PUB-003","USK-AT-PLAT-001","USK-AT-PLAT-002","USK-AT-PLAT-003"],"context_paths":["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths":[".github/workflows/ci.yml","CMakeLists.txt","cmake/**","apps/daemon/**","runtime/base/**","runtime/setup/kernel/**","runtime/setup/lifecycle/**","runtime/setup/policy/**","runtime/setup/transaction/**","runtime/platform/**","tests/**","docs/security/windows_ntfs_publication_profile.md","docs/architecture/staged_child_commit_authority.md","docs/architecture/specification_implementation_inventory.v1.json"],"read_only_paths":["contracts/**","release/**","spec/**"],"forbidden_paths":["README.md",".git/**","external/**"],"forbidden_operations":["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps":["Implement the accepted handle/namespace publication protocol.","Bind closure and native visible identity into receipts.","Preserve refused behavior on providers lacking the guarantee.","Exercise substitutions and metadata failure after publication."],"deliverables":["One qualified publisher profile","Security negative tests","Updated capability observation"],"risks":["This is high-risk code requiring independent technical review and lab authority."],"checks":[{"argv":["python","spec/tools/specctl.py","validate"],"status":"NOT_RUN","scope":"specification-integrity-only"},{"argv":["python","tools/structure_policy_check.py"],"status":"NOT_RUN","scope":"existing-repository-policy"},{"argv":["python","-m","unittest","discover","-s","tests","-v"],"status":"NOT_RUN","scope":"existing-repository-tests; qualify relevance and dependencies before execution"}],"required_binding":"active USK-SPEC-TO-RELEASE-01 campaign authority plus an exact task binding; exact target/environment receipt additionally required for endpoint or user-state effects","authorizes_implementation":false,"base_binding":"derive exact accepted source commit/tree, task-definition digest, current spec aggregate, non-widened scope and predecessor receipts","stop_conditions":["required source/spec inputs changed","active campaign authority or exact task binding unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion":"implementation plus specified evidence and independent technical review under active campaign policy; document count is insufficient"}
---

# Implement the qualified staged-child publisher

## Goal
Implement the qualified staged-child publisher.

## Preconditions
Pair this definition with an exact campaign task binding for the actual repository commit/tree, current spec manifest, non-widened scope and accepted predecessor receipts. This file is not a live AIDE task and cannot mint its own binding.

The scoped service application and build files are needed to compile and exercise the dedicated publisher, while lifecycle, kernel and policy files carry its strict capability gate. The exact CI workflow file is admitted only to invoke disposable Windows lab probes on an ephemeral runner; the probe must create and identify its own test resources before use. The listed security and architecture documents may record target observations; contracts, release records and the remaining specification stay read-only. This scope change grants no publisher availability or endpoint effect.

## Implementation steps
1. Implement the accepted handle/namespace publication protocol.
2. Bind closure and native visible identity into receipts.
3. Preserve refused behavior on providers lacking the guarantee.
4. Exercise substitutions and metadata failure after publication.

## Deliverables
- One qualified publisher profile
- Security negative tests
- Updated capability observation

## Risks and review
- This is high-risk code requiring independent technical review and lab authority.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task, binding identity and any binding expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
