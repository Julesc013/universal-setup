---
type: "Source Review"
title: "Source baseline, coverage and observations"
description: "Record what was actually inspected, what came from attachments and what remains unverified."
tags: ["universal-setup","provenance"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"},{"id": "AIDE-CONTEXT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json","title": "Pinned AIDE ContextPack v2 schema"},{"id": "OKF","resource": "https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md","title": "Open Knowledge Format 0.2, exact August 21 revision"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-BASE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "observation","depends_on": []}
---

# Source baseline, coverage and observations

## Repository snapshot
Universal Setup main was inspected at `0ca648a2c4fa8a37bb78a22639578093aecf6254` (tree `7f8b11a85ad9a4704fdb891763de00ec467bb314`). The September 18 merge updates the README; preserve that file rather than replacing it with another status report. No `spec/` root exists in the inspected root listing; the structure validator does not allow it.

The pinned README records package1.0.0/C ABI1.0, implemented public SDK targets, fixture-qualified product/recipe contracts, stored/Deflate ZIP/ZIP64 streaming and constrained acceptance authority. Runtime capability claims in older attachments are historical. This package did not execute a new native USK build, product lifecycle, desktop acceptance or security qualification.

## Input coverage
Seven mounted Markdown files were read, representing five unique contents: DiskEd, SysPane, Eureka, June provider review and September 6 FacMan/native interface programme. Duplicate aliases are recorded by exact hash. Earlier context excerpts and the current conversation's enterprise synthesis contributed design requirements, but no complete export of every historical project chat was available. Source timestamps, old branch statuses and unsupported current claims are not promoted into live truth.

## AIDE and OKF
AIDE main is pinned at `aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3`, with WorkUnit and ContextPack v2 schemas inspected. Its promoted commit records a reviewed worker foundation with disabled activation and remaining isolation/broker work. The README's older planned-surface wording is not treated as proof that every listed schema is absent or runtime complete.

OKF 0.2 is pinned at `ad30107c31c06aec8a7d5636e0d1058118604e6f`. The local engineering extension is a proposal for this bundle, not an upstream schema registration or a claim that AIDE has adopted it.

## Coverage limits
The spec is a substantive proposed baseline, not an exhaustive proof that every historical idea is recovered or that every design is correct. Outstanding technical decisions and validation tasks are explicit. Review the source registry and reconciliation ledger before promoting any capability or public contract.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^REPO-ROOT], [^AIDE-WORKUNIT], [^AIDE-CONTEXT], [^OKF].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
[^AIDE-CONTEXT]: [Pinned AIDE ContextPack v2 schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json).
[^OKF]: [Open Knowledge Format 0.2, exact August 21 revision](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md).
