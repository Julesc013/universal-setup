---
type: "Engineering Specification"
title: "Publisher trust, update metadata and revocation"
description: "Separate integrity, authenticity, eligibility and authorization throughout servicing."
tags: ["universal-setup","security"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TRUST","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CACHE","USK-S-THREAT"]}
---

# Publisher trust, update metadata and revocation

## Trust states
Integrity means matching an expected content identity. Authenticity means a valid publisher assertion under an admitted root and policy. Eligibility means the target meets requirements. Authorization means the principal may perform effects. A signed artifact can be incompatible; a hash-matching artifact can be unauthenticated.

## Update system
Use vetted cryptographic/platform providers. Pin algorithms and trust metadata versions. A TUF-style adapter can verify root/targets/snapshot/timestamp metadata, expiry, rollback/freeze resistance, mirrors and delegation. Do not implement a new cryptosystem. Endpoint validation must tolerate offline operation only under an explicit offline trust policy; lack of a clock or expired metadata is not silent permission.

Publisher keys and code-signing identities are distinct from Git commit authorship and CI provenance. Plan bindings include package/manifest authenticity results and policy generation. Signature/key rotation and revocation have testable transition rules. Revoked package material is never auto-admitted merely because it remains cached.

## Downgrade and emergency response
Unauthorized metadata rollback is an attack; an explicit downgrade to an artifact still allowed by trust policy is a lifecycle operation. A recovery button must not disable trust. A release can be withdrawn without mutating historical assets. Publish affected IDs/digests, safe response and replacement information.

The setup engine does not enforce a product's DRM/licensing model. A product may provide a verified eligibility/entitlement receipt; USK applies only the permitted package/effects and does not gain business-policy semantics.

## Verifiable requirements

### USK-R-TRUST-001 — Separate integrity/authenticity

**Requirement.** Reports MUST distinguish checksum verification from publisher authentication.

**Rationale.** Editable hash files do not prove who published.

**Acceptance.** `USK-AT-TRUST-001` in the acceptance catalogue.

### USK-R-TRUST-002 — Revocation enforced

**Requirement.** Revoked or policy-expired artifacts MUST NOT be silently re-admitted from local cache.

**Rationale.** Cache is not a trust authority.

**Acceptance.** `USK-AT-TRUST-002` in the acceptance catalogue.

### USK-R-TRUST-003 — Downgrade distinction

**Requirement.** Authorized downgrade MUST retain trust checks and explicit data-compatibility analysis.

**Rationale.** Safe rollback is not anti-rollback bypass.

**Acceptance.** `USK-AT-TRUST-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
