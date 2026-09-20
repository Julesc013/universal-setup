---
type: "Engineering Specification"
title: "Privilege separation and maintenance handoff"
description: "Minimize elevated code and bind privileged effects to exact authenticated plans."
tags: ["universal-setup","security"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-BROKER","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-THREAT","USK-S-WIRE"]}
---

# Privilege separation and maintenance handoff

## Roles
The normal frontend/planner remains at the user's current level. A worker manages the long operation and journal. A minimal privileged broker performs only the sealed, admitted effect subset. The roles may be modes of one verified executable or separate verified binaries; packaging topology is not a security boundary by itself.

The broker accepts exact plan, target, policy, provider and operation identities through authenticated IPC. It independently validates current state and requested effects. It does not load product themes, telemetry plugins, arbitrary environment overrides, user search paths, GUI resources or network update feeds. A broker is not a general command shell.

## Elevation and de-elevation
User scope should not request elevation unnecessarily. Machine scope requests it only after effect review. A normal application launched after elevated setup must use an explicitly qualified user-session launch path rather than inheriting the elevated token accidentally. `asInvoker` means inheriting the parent level, not automatically becoming unelevated.

## Self-maintenance
Copy/reopen a verified maintenance worker outside the target root, authenticate the handoff, bind expected parent/operation, wait for applicable processes to quiesce, revalidate and operate. Keep recovery available if the frontend or product executable is missing. Cleanup removes only worker-owned temporary material after the operation is durably terminal and no recovery lease needs it.

Driver/kernel-extension installation is outside the initial generic profile. Admit native-signed package delegation with separate privileges and platform rules rather than adding raw driver writes.

## Verifiable requirements

### USK-R-BROKER-001 — Broker minimality

**Requirement.** The privileged broker MUST reject effects outside the exact plan and MUST ignore frontend-controlled plugins, themes and ambient search paths.

**Rationale.** Elevation must not grant the whole application authority.

**Acceptance.** `USK-AT-BROKER-001` in the acceptance catalogue.

### USK-R-BROKER-002 — Safe post-install launch

**Requirement.** Post-install product launch MUST NOT unintentionally inherit setup elevation.

**Rationale.** Desktop products should not run as admin by accident.

**Acceptance.** `USK-AT-BROKER-002` in the acceptance catalogue.

### USK-R-BROKER-003 — Bounded self-maintenance

**Requirement.** Self-repair/uninstall MUST execute from intact verified material outside the target being removed.

**Rationale.** Running binaries cannot be assumed replaceable.

**Acceptance.** `USK-AT-BROKER-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-DISKED], [^USR-SYSPANE], [^CONVERSATION].

[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
