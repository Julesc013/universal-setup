---
type: "Engineering Specification"
title: "Greenfield construction and existing-repository adoption"
description: "Build from the desired design while preserving proved behavior and explicitly reconciling legacy contracts."
tags: ["universal-setup","architecture"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-ADOPT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-MODULES"]}
---

# Greenfield construction and existing-repository adoption

## Brownfield default
Before code movement, inventory existing public headers, command descriptors, schemas, refusal codes, native tests, SDK tests and retained security regressions. Pin a source tree; capture behavior with independent fixtures. The current repository is not an empty scaffold and must not lose its fail-closed paths while being reorganized.

Preserve C ABI 1.0 and command compatibility during an additive client/API migration. New behavior gets a new admitted capability or versioned contract. Installed-state and recovery readers outlive their writers. Keep a deviation register for legacy behavior that cannot match the new contract without migration.

## Greenfield reference path
Implement canonical codecs, pure planner and in-memory effect target first. Run the same acceptance designs against the reference model and the hosted implementation. A reference implementation can identify ambiguity and generate test vectors; it is not an alternate installed-state authority in a shipped product.

## Refactoring sequence
1. Characterize codecs, operations and security refusal behavior.
2. Extract public decoding/routing from lifecycle services without changing results.
3. Replace byte-retaining preimage inventories with bounded metadata/source references.
4. Implement qualified publication and concurrency/recovery as a behavior change with explicit proof.
5. Add owned operations and a process client.
6. Add authoring and presentation over the same engine.

Do not raise the old payload ceiling in place of bounding the implementation. Do not reset version/state histories. Do not move all generic-looking product code upstream before a consumer-neutral contract and equivalence fixture exist.

## Verifiable requirements

### USK-R-ADOPT-001 — Preserve refusal regressions

**Requirement.** A refactor MUST retain existing negative/security tests and MUST NOT weaken refused publication guarantees to obtain a passing demonstration.

**Rationale.** A denied operation can be the correct implemented behavior.

**Acceptance.** `USK-AT-ADOPT-001` in the acceptance catalogue.

### USK-R-ADOPT-002 — Separate refactor from semantics

**Requirement.** Behavior-preserving decomposition MUST have equivalent normalized results before new behavior is enabled.

**Rationale.** Combining movement and semantic changes hides regressions.

**Acceptance.** `USK-AT-ADOPT-002` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^USR-SYSPANE], [^CONVERSATION].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
