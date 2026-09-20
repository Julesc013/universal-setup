---
type: "Engineering Specification"
title: "Protected staging and publication authority"
description: "Prevent staged-object substitution across the verification-to-publication interval."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PUB","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-TXN","USK-S-CAPS"]}
---

# Protected staging and publication authority

## Threat model first
Name adversaries separately: unrelated unprivileged principal, malicious process under the same principal, administrator/root, privileged kernel actor, compromised storage and concurrent cooperative installers. A platform cannot honestly defeat every actor. A publisher profile specifies exactly which namespace/object changes it excludes and by what OS mechanism.

The prior staged-child substitution finding is a retained regression. Rehashing once or observing the parent again does not by itself protect verified descendants until publication. The strong `staged_child_bound_v1` promise needs a qualified platform implementation, not a trust Boolean.

## Protocol obligations
Create staging beneath an authorized protected parent; bind native handles/identities and access policy; materialize with no-follow semantics; prevent or detect prohibited descendant insertion/replacement; verify full selected closure; publish into an independently bound destination namespace; confirm the visible object matches the verified object; durably record publication. A target-specific sequence must document residual race windows and reader visibility.

For same-principal adversaries, explicit sandbox/broker separation or a weaker documented assumption may be required. A path string, same-binary process mode or worktree does not create isolation. If no available provider satisfies the recipe's guarantee, refuse; do not fall back silently.

## Recovery boundaries
Keep enough metadata to distinguish not published, published but state incomplete, and ambiguous. Never delete a visible object whose ownership cannot be proved from the original plan and current identity. Recovery can retain-for-operator rather than claiming an unsafe automated undo.

## Verifiable requirements

### USK-R-PUB-001 — Bind descendants through publish

**Requirement.** A publisher claiming protected staged-child authority MUST exclude or detect unauthorized substitution of every verified published descendant throughout its claimed protection interval.

**Rationale.** Parent identity and one hash are insufficient.

**Acceptance.** `USK-AT-PUB-001` in the acceptance catalogue.

### USK-R-PUB-002 — Unmet publisher refuses

**Requirement.** Unavailable publication protection MUST remain an explicit no-effect refusal for profiles requiring it.

**Rationale.** No feature demo may widen guarantees.

**Acceptance.** `USK-AT-PUB-002` in the acceptance catalogue.

### USK-R-PUB-003 — Publication evidence

**Requirement.** Publication receipts MUST bind the verified closure and actual visible target identity, including incomplete metadata disposition.

**Rationale.** Metadata can fail after commit.

**Acceptance.** `USK-AT-PUB-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-SYSPANE], [^USR-DISKED], [^CONVERSATION].

[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
