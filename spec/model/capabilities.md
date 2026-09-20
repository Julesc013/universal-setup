---
type: "Engineering Specification"
title: "Targets, capabilities, guarantees and support claims"
description: "Select concrete implementations without conflating representation, permission, proof and support."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CAPS","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-ID"]}
---

# Targets, capabilities, guarantees and support claims

## Target profile
A target profile binds OS family/minimum, architecture, instruction baseline, ABI, runtime libraries, executable form, filesystem assumptions, chosen frontend, delivery model and security assumptions. Build-host tools have a separate profile. A cross-build is not a target execution result.

## Capability record
Represent independently: known semantics, implementation state, realization mode, provider identity, current availability, required privilege, permission, qualification scope, support state and recovery ceiling. A record can be implemented but unauthorized, represented but unavailable, or qualified on NTFS but unqualified on removable exFAT.

Resolution intersects requirement, target constraints, provider capabilities, guarantee floor, trust policy, administrator/deployment/product policy and current observations. Explicit preferences break ties only among eligible providers. An unresolved tie refuses. Never select by directory enumeration, PATH or module load order.

A selected-provider result records rejected candidates and reasons, effective constraints, relevant evidence references, exact implementation digest and plan invalidation inputs. Runtime revalidation may refuse a stale selection; it must not silently choose a materially different provider after plan review.

## Guarantee profile
Use independent dimensions: publication visibility, identity protection, restart recovery, durability, concurrent-reader behavior, rollback/compensation, cross-volume behavior and external-owner delegation. T0/T1/T2/T3 may be UI summaries, not substitutes for those dimensions. T3 requires actual abrupt-power-loss evidence on the named storage profile. Do not define all guarantees as a single sortable integer: they form a constrained compatibility relation.

Historical targets may inspect modern records without implementing modern mutation. A modern helper or remote gateway is an explicitly selected different topology with its own trust boundary, not a hidden downlevel implementation.

## Verifiable requirements

### USK-R-CAPS-001 — No support Boolean

**Requirement.** Capability discovery MUST expose implementation, authority, qualification and support separately.

**Rationale.** Avoids claims inferred from enum existence.

**Acceptance.** `USK-AT-CAPS-001` in the acceptance catalogue.

### USK-R-CAPS-002 — Deterministic selection

**Requirement.** Equal eligible provider candidates without an explicit tie-break policy MUST produce ambiguity refusal before effects.

**Rationale.** Selection order is not policy.

**Acceptance.** `USK-AT-CAPS-002` in the acceptance catalogue.

### USK-R-CAPS-003 — Qualified guarantees

**Requirement.** An operation MUST refuse when any required guarantee is not supplied by the selected profile.

**Rationale.** No silent security downgrade.

**Acceptance.** `USK-AT-CAPS-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
