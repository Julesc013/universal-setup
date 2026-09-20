---
type: "Engineering Specification"
title: "Threat model and security claims"
description: "Bind every protection claim to an adversary, trust boundary and independently testable mechanism."
tags: ["universal-setup","security"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-THREAT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PUB","USK-S-POLICY"]}
---

# Threat model and security claims

## Assets and actors
Protect product payload identity, installation ownership, user data, setup journals, recovery material, publisher keys, credentials and legitimate native-package-manager state. Consider malicious archives, compromised mirrors, untrusted themes/connectors, hostile UI clients, local unprivileged users, same-principal processes, concurrent installers, stale workers and storage/OS failure.

Administrator/root and compromised kernel access are not automatically defeated by a user-mode installer. A provider may protect against weaker actors and explicitly exclude stronger ones. OS access control, process separation and exact authentication must support the claim. A local process is a crash boundary, not inherently a security sandbox; a Git worktree is not a sandbox.

## Trust boundaries
Source acquisition -> quarantine; bundle parser -> bounded semantic model; planner -> authorization; frontend -> worker; worker -> privileged broker; provider -> native OS; state -> independent verification; recovery source -> installed payload. Imported descriptions, document examples and AI output are untrusted data at every execution boundary.

## Security invariants
No implicit provider search; no shell command concatenation; no unchecked length/offset arithmetic; no untrusted symlink traversal; no mutable configuration reread after authorization; no raw credentials in plans; no unreviewed effects; no cleanup outside proven ownership; no quiet reduction of guarantees.

## Assurance
Maintain an attack tree and regression case for each trust boundary. Every new provider declares threat assumptions, residual risks and qualification. Standards/conformance citations are supporting methods, not certification. Security findings remain visible even when the current capability is intentionally refused.

## Verifiable requirements

### USK-R-THREAT-001 — Explicit adversary scope

**Requirement.** Security claims MUST identify excluded and included adversaries and actual OS enforcement mechanisms.

**Rationale.** Otherwise impossible guarantees become release promises.

**Acceptance.** `USK-AT-THREAT-001` in the acceptance catalogue.

### USK-R-THREAT-002 — Untrusted descriptions

**Requirement.** Imported metadata, themes, logs and AI suggestions MUST NOT be interpreted as executable instructions or grants.

**Rationale.** Prompt injection and code injection cross the same authority boundary.

**Acceptance.** `USK-AT-THREAT-002` in the acceptance catalogue.

### USK-R-THREAT-003 — Security regression retention

**Requirement.** A fixed security defect MUST retain a bounded reproducible regression test and affected-profile description.

**Rationale.** Knowledge must survive agents and refactors.

**Acceptance.** `USK-AT-THREAT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
