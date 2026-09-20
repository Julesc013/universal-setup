---
type: "Engineering Specification"
title: "Platform services and native ownership adapters"
description: "Define portable semantics and platform-specific mechanisms with explicit qualified differences."
tags: ["universal-setup","providers"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PLAT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-HOST","USK-S-OWN","USK-S-BROKER"]}
---

# Platform services and native ownership adapters

## Filesystem services
Provide stable object identity, no-follow open, relative-to-bound-root access, enumerate, bounded read/write, flush, metadata, no-replace publication, directory replacement where qualified, capacity and native error classification. A pathname normalization library cannot substitute for handle-relative access and revalidation.

Windows profiles separately qualify NTFS/reparse/ACL behavior, case projection, native-registration scope and x86/x64 registry views. POSIX profiles separately qualify directory fsync, rename semantics, mount changes, ownership/modes and symlink traversal. macOS signed bundles, HFS+/APFS differences and resource metadata need explicit treatment. Network and removable filesystems are independent profiles.

## Native effects
Desktop entries, shortcuts, application associations, services, launch agents, environment entries and uninstall registrations are typed effects with ownership, verification and compensation. Shared values use compare-and-change semantics; another product's modification becomes a conflict. A service install cannot blindly overwrite a same-named service owned by someone else.

## External package ownership
Native package adapters generate/select the manager's package, plan delegation, execute through its supported interface and observe receipts. USK stores references to external ownership rather than manufacturing per-file control. Per-user vs machine, architecture and channel remain explicit.

No implicit privilege escalation, package manager invocation or product launch occurs because the platform supports it. Capabilities, authorization and selection all remain required.

## Verifiable requirements

### USK-R-PLAT-001 — Native object ownership

**Requirement.** Native integration effects MUST verify the exact pre-state and current owner before replacing or deleting a resource.

**Rationale.** Shortcuts/services/registry entries can be externally changed.

**Acceptance.** `USK-AT-PLAT-001` in the acceptance catalogue.

### USK-R-PLAT-002 — Filesystem qualification

**Requirement.** Durability/publication guarantees MUST be qualified per named filesystem/profile, not inferred from OS family.

**Rationale.** Filesystems differ within one OS.

**Acceptance.** `USK-AT-PLAT-002` in the acceptance catalogue.

### USK-R-PLAT-003 — No cross-owner repair

**Requirement.** Native-package-managed payload MUST be serviced through its admitted owner adapter.

**Rationale.** USK must not fight native servicing.

**Acceptance.** `USK-AT-PLAT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
