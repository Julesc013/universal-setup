---
type: "Operating Guide"
title: "Start here: specification operating manual"
description: "Read, validate, adopt and resume the Universal Setup specification without relying on chat memory."
tags: ["universal-setup","start-here"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"},{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "AIDE-CONTEXT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json","title": "Pinned AIDE ContextPack v2 schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-START","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": []}
---

# Start here: specification operating manual

## Purpose
This package is a proposed engineering baseline for Universal Setup: an embeddable lifecycle engine, declarative authoring system, and optional prefabricated native setup application. It is not a release of that application. The specification version is independent of the current USK package/ABI version. All new requirements are proposed until adopted through existing repository governance.

## Five-minute entry path
1. Read this page and [authority](governance/authority.md).
2. Read [baseline and provenance](provenance/baseline.md) and [decisions and conflicts](provenance/reconciliation.md).
3. Run `python spec/tools/specctl.py validate` from the extracted archive or repository root.
4. Run `python spec/tools/specctl.py status`, then `python spec/tools/specctl.py next`.
5. Select one WorkUnit, inspect its dependencies, and build a focused context pack with `context`.

The tools inspect specification data and create requested local outputs. They do not install software, call models, enqueue AIDE work, apply patches, authorize workers, or write protected Git references.

## Adoption is separate from unpacking
The pinned repository root validator does not admit `spec/`. Review `integration/root-admission.patch` before adding the folder to an integration branch. The patch adds only the root name; it does not approve the proposed architecture or grant operations. Preserve the newly revised root README. Optional agent-instruction and CI templates are inert files, not automatically installed workflows.

## Two implementation paths
**Existing repository:** characterize current behavior, retain its ABI and negative tests, inventory the gaps, then replace one subsystem behind conformance tests. Archive streaming already exists in the reviewed baseline; do not implement it again merely because an older report says otherwise.

**Greenfield implementation:** use the same requirements and tests but create a fresh implementation in an authorized workspace. Start with the reference model and an in-memory target. It gains no compatibility/support claim until the relevant external tests pass. This is an implementation strategy, not permission to discard the existing repository.

## Fresh-session handoff
Give any worker the repository locator, exact source commit, specification manifest digest, one task ID, and a context-pack digest. The worker reopens those artifacts and reports missing inputs. It must not infer that the previous chat's latest HEAD, CI result or permission is still current.

## Reading routes
- Product/architecture: `architecture/vision.md` then `architecture/modules.md`.
- Kernel implementation: `model/identity.md`, `model/plans.md`, then the selected lifecycle module.
- Application: `interfaces/presentation.md`, `interfaces/cli-tui.md`, `interfaces/native-shells.md`.
- Agent/maintainer: `execution/workflow.md`, `execution/aide.md`, `execution/context.md`.
- Qualification: `verification/strategy.md`, the acceptance catalogue and exact task.

A full read is useful for review. Routine tasks should load dependency-selected pages, not every historical input.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^REPO-ROOT], [^REPO-README], [^AIDE-CONTEXT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^AIDE-CONTEXT]: [Pinned AIDE ContextPack v2 schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json).
