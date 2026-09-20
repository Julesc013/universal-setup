---
type: "WorkUnit Definition"
title: "Build trust provider and offline trust closure"
description: "Proposed M6 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-024","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-TRUST","USK-S-SUPPLY"]}
usk_task: {"id": "USK-WU-024","title": "Build trust provider and offline trust closure","phase": "M6","status": "proposed","depends_on": ["USK-WU-011","USK-WU-014"],"spec_ids": ["USK-S-TRUST","USK-S-SUPPLY"],"requirement_ids": ["USK-R-TRUST-001","USK-R-TRUST-002","USK-R-TRUST-003","USK-R-SUPPLY-001","USK-R-SUPPLY-002","USK-R-SUPPLY-003"],"acceptance_ids": ["USK-AT-TRUST-001","USK-AT-TRUST-002","USK-AT-TRUST-003","USK-AT-SUPPLY-001","USK-AT-SUPPLY-002","USK-AT-SUPPLY-003"],"allowed_paths": ["runtime/setup/policy/**","runtime/platform/**","runtime/setup/fetch/**","contracts/**","tests/**"],"read_only_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Select vetted crypto/platform implementation via decision review.","Bind publisher/trust-policy generations and artifact signatures.","Test key rotation, revoked cache artifacts and offline expiry policy.","Distinguish authenticity from integrity everywhere."],"deliverables": ["Trust contract/provider","Revocation/rotation fixtures","Offline media trust profile"],"risks": ["No custom crypto or implicit trust from checksum."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Build trust provider and offline trust closure

## Goal
Build trust provider and offline trust closure.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Select vetted crypto/platform implementation via decision review.
2. Bind publisher/trust-policy generations and artifact signatures.
3. Test key rotation, revoked cache artifacts and offline expiry policy.
4. Distinguish authenticity from integrity everywhere.

## Deliverables
- Trust contract/provider
- Revocation/rotation fixtures
- Offline media trust profile

## Risks and review
- No custom crypto or implicit trust from checksum.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
