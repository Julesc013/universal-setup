---
type: "Engineering Specification"
title: "Release provenance, licences and publication controls"
description: "Bind source and build products while keeping provenance distinct from runtime safety and publisher trust."
tags: ["universal-setup","release"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-SUPPLY","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-REL"]}
---

# Release provenance, licences and publication controls

## Artifact manifest
A release inventory binds product/provider release, source commit/tree, toolchain identity, target profile, dependency digests, generated inputs, licences, symbols, contracts, tests and every distributed artifact digest. A package-specific SBOM includes static and vendored dependencies, not only manifest dependencies seen by a hosting site.

## Build and publish separation
Untrusted pull-request builds have no signing or publication credentials. Build exact candidate in controlled CI, compare required independent reconstructions, produce provenance/SBOM, create a draft release, attach complete assets, verify inventory, then publish under the channel's admitted authority. Pin workflow actions/dependencies to reviewed immutable identities and use minimal permissions. A spec or test passing must not turn on publication credentials.

## Reproducibility
Declare which artifacts are byte-reproducible before signing. Record signing/notarization as separate transformations with exact hashes, tool/service identity and receipt. Never require an external contributor to recreate private signing timestamps. Build provenance describes origin/process; it is not certification of correctness or permission to install.

## Incident response
Maintain key-custody roles, rotation/revocation, loss/recovery, artifact withdrawal and support notices. Do not embed production secrets in example configurations or archived evidence. Keep notices for every redistributed codec/toolkit component and mark legal-policy decisions as human review obligations, not facts inferred by an agent from a SPDX string.

## Verifiable requirements

### USK-R-SUPPLY-001 — Distribution closure

**Requirement.** Every distributed artifact MUST appear in one verified inventory with licences, dependencies and provenance references.

**Rationale.** Sidecars and static dependencies are easy to omit.

**Acceptance.** `USK-AT-SUPPLY-001` in the acceptance catalogue.

### USK-R-SUPPLY-002 — Signing isolation

**Requirement.** Production signing and publication credentials MUST be unavailable to untrusted PR jobs and ordinary spec tooling.

**Rationale.** Build content is not authority.

**Acceptance.** `USK-AT-SUPPLY-002` in the acceptance catalogue.

### USK-R-SUPPLY-003 — Reproducibility scope

**Requirement.** Reproducibility claims MUST state whether they cover unsigned payloads, final packages or signing transformations.

**Rationale.** Timestamped signatures change bytes.

**Acceptance.** `USK-AT-SUPPLY-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
