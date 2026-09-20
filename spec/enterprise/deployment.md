---
type: "Engineering Specification"
title: "Enterprise endpoint deployment and prerequisite orchestration"
description: "Be deployable by management systems without embedding an enterprise control plane."
tags: ["universal-setup","enterprise"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-ENT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-OPS","USK-S-PLAT"]}
---

# Enterprise endpoint deployment and prerequisite orchestration

## Product boundaries
Authoring creates setup products. Endpoint runtime installs/maintains one product under local/deployment policy. Fleet systems schedule, enroll, inventory and aggregate. Universal Setup owns the first two and exports adapters for the third; it does not require a fleet service for ordinary installation.

## Detection and eligibility
Expose absent, present-healthy, damaged, partial, different-version, different-scope, externally-managed, uncertain-owner and recovery-required observations. Detection is read-only and stable machine output. Eligibility evaluates OS/architecture/runtime, free space, scope, selected components and prerequisites separately.

A prerequisite descriptor contains detection rule, version scheme/range, owner, acceptable source, dependency order, install/delegation action, verification, restart consequence and removal policy. Prefer application-private runtimes where feasible. Shared dependencies are not removed merely because one consumer uninstalls. Vendor executable installers are bounded delegated effects with explicit return-code/restart and rollback limitations.

## Unattended deployment
Response-file defaults and validation are shared with the GUI; wizard controls cannot contain hidden defaults. Run under actual user/system service contexts, with no interactive desktop, empty PATH, read-only media, proxies/offline policy and restart/resume. Secrets use protected credential references, not command-line tokens or response-file plaintext.

## Reboot
Separate restart required, permitted, scheduled and performed. Default to no surprise restart. Persist authenticated resume context and generation before restart. Upon boot, revalidate exact source, state, policy and operation identity. Repeated resume is safe. Native return codes are mapped into semantic results, not globally interpreted as success/failure integers.

## Verifiable requirements

### USK-R-ENT-001 — Reliable detection

**Requirement.** Detection MUST distinguish healthy, damaged, partial, foreign-owned and absent states without mutation.

**Rationale.** Endpoint managers need dependable decisions.

**Acceptance.** `USK-AT-ENT-001` in the acceptance catalogue.

### USK-R-ENT-002 — Prerequisite ownership

**Requirement.** Prerequisite servicing MUST respect shared/external ownership and declared removal policy.

**Rationale.** One app must not break others.

**Acceptance.** `USK-AT-ENT-002` in the acceptance catalogue.

### USK-R-ENT-003 — No surprise reboot

**Requirement.** Setup MUST NOT reboot solely because a silent or vendor prerequisite path requests it.

**Rationale.** Unattended must remain policy-controlled.

**Acceptance.** `USK-AT-ENT-003` in the acceptance catalogue.

### USK-R-ENT-004 — Response-file parity

**Requirement.** GUI and unattended choices MUST use the same typed defaults, validation and constraints.

**Rationale.** Hidden panel defaults diverge deployments.

**Acceptance.** `USK-AT-ENT-004` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
