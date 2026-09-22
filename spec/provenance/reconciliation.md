---
type: "Decision Register"
title: "Conflicts, superseded proposals and open decisions"
description: "Preserve disagreements explicitly rather than silently selecting convenient historical claims."
tags: ["universal-setup","provenance"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "OWNER-DECISION-20260922","resource": "urn:sha256:ed6bab5a72716c8f03e58248c97ff1d69e600e4a14808e3192d7c0b4f92ec9bb","title": "Owner selection of initial platform, compatibility policy and 1.1 release train"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-EUREKA","resource": "urn:sha256:d466fef4c8c06adb4a64c1069ba098e623bee0bdce1af13baddf4c0b30c7097b","title": "User-supplied Eureka setup integration review"},{"id": "USR-REVIEW","resource": "urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa","title": "User-supplied June provider architecture review; historical"},{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-RECON","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-BASE"]}
---

# Conflicts, superseded proposals and open decisions

## Reconciled issues
| Issue | Inputs disagree | Proposed disposition |
|---|---|---|
| Current source | Old audits pin 4c766... | Use observed 0ca648... for import context; old code observations remain scoped |
| Archive streaming | Old reports say stored-only/full-payload | Current README has stored/Deflate streaming; full-lifecycle memory still needs audit |
| GUI ownership | Old rule says no universal GUI wizard | Kernel stays UI-neutral; optional product-neutral prefab kit is a reviewed policy proposal |
| DiskEd delivery | Separate setup envelope vs embedded maintenance | Both target-profile options; identical portable payload and independent recovery mandatory |
| FacMan release scope | Older Windows-only 0.1 vs September local multi-platform train | Preserve latest supplied corrected 0.1–0.4 allocation as consumer context, not USK authority |
| Provider versioning | Numerous suggested minor/alpha allocations | Version axes are normative intent; future numbers require actual release decision |
| Legacy platforms | Immediate all-target parity vs defer all | Early read-only feasibility canaries, separately qualified mutation profiles |
| AIDE runtime | README pre-runtime vs reviewed worker commit/schemas | Record exact observations; do not infer live scheduling or permission |
| Root placement | User requests spec/; checker forbids new roots | Separate minimal root-admission patch, no silent policy bypass |
| Contract representation | OKF prose vs machine schemas | spec intent references contracts; prototypes remain explicitly unpromoted |

## Selected development direction
The owner selected Windows NT x64, local NTFS and a first WinForms OEM+ shell as the first complete native product direction; additive compatibility preserving existing ABI 1.0 consumers and admitted behavior; and the Universal Setup 1.1 train targeting `1.1.0 — Local Setup Foundation`.[^OWNER-DECISION-20260922]

These selections are recorded in `plan/release-selection.json`. They do not close the compound parent decisions: exact endpoint/lab qualification remains outstanding for OD-002, each actual ABI/schema migration remains outstanding for OD-003, and signing identity, key custody, trust and publication approval remain outstanding for OD-008. All three retain `status: open` with selected direction and explicit obligations.

## Open technical decisions
OD-001: exact platform mechanism and adversary ceiling for protected staged-child publication. OD-002: selected development profile but exact endpoint/runtime/filesystem configuration and lab qualification remain open. OD-003: additive policy selected but each promoted schema/ABI migration remains open. OD-004: trust/signature provider and offline expiry policy. OD-005: exact AIDE runtime adapter admission. OD-006: independent human reviewer and lab resources. OD-007: quantitative performance budgets per target. OD-008: 1.1/1.1.0 direction selected but signing identity, custody, trust and publication authorization remain open.

Each decision needs owner, alternatives, evidence, chosen scope and revisit trigger. None is resolved by a model declaring the architecture optimal. Safety-sensitive implementations stop at the affected open decision; independent authoring or mock-interface work can continue.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^OWNER-DECISION-20260922], [^USR-DISKED], [^USR-SYSPANE], [^USR-EUREKA], [^USR-REVIEW], [^USR-FACMAN], [^REPO-README], [^REPO-ROOT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](sources.json); identity `urn:usk:input:current-conversation-design`.
[^OWNER-DECISION-20260922]: Owner selection of initial platform, compatibility policy and 1.1 release train. [Source registry](sources.json); identity `urn:sha256:ed6bab5a72716c8f03e58248c97ff1d69e600e4a14808e3192d7c0b4f92ec9bb`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-EUREKA]: User-supplied Eureka setup integration review. [Source registry](sources.json); identity `urn:sha256:d466fef4c8c06adb4a64c1069ba098e623bee0bdce1af13baddf4c0b30c7097b`.
[^USR-REVIEW]: User-supplied June provider architecture review; historical. [Source registry](sources.json); identity `urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa`.
[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
