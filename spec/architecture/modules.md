---
type: "Engineering Specification"
title: "Module responsibilities and dependency direction"
description: "Decompose around sources of authority and replacement boundaries, not file extensions or language versions."
tags: ["universal-setup","architecture"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"},{"id": "USR-REVIEW","resource": "urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa","title": "User-supplied June provider architecture review; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-MODULES","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-VISION"]}
---

# Module responsibilities and dependency direction

## Layer graph
```text
consumer / prefab shell
        -> setup application / client
        -> USK model / planner / operations
        -> explicit USU service interfaces
        -> filesystem / codec / native-manager implementations
```
Authoring uses the shared semantic model but does not execute endpoint effects. The planner accepts immutable observations and produces a plan or refusal. The executor revalidates the plan and uses admitted effect providers. Verification uses independent observations rather than trusting executor return codes alone.

## Ownership table
| Module | Owns | Excludes |
|---|---|---|
| model/codec | IDs, bounded values, formats, canonical encodings | GUI/OS calls |
| resolver/planner | exact selections, dependency order, effects | ambient network/mutation |
| operation/transaction | durable transitions and effect sequencing | native widget state |
| state/ownership | installations, generations, effect receipts | product data interpretation |
| host/provider | lifetimes, capabilities, OS implementations | product policy |
| application/presentation | semantic actions and views | direct file replacement |
| authoring/bundle | allowed deployment space and payload identity | arbitrary customer-machine decisions |
| native shell | layout, focus, menus, input and accessibility | readiness or mutation authority |

## Physical repository
Preserve `include/`, `runtime/`, `apps/`, `contracts/`, `content/`, `release/`, `docs/`, `tests/`, `tools/`, `cmake/`, `external/`, `archive/`. Admit `spec/` separately. Use domain-based private subdirectories where the actual root grammar permits them; additional module-root changes require reviewed validator changes. This is not an instruction to add empty directories.

Use opaque handles and bounded records at ABI/process boundaries. Internal C++17 is permitted; C ABI callers must not receive STL objects, C++ exceptions, native handles without declared ownership or toolkit objects. Platform-native languages may implement shells without changing kernel law.

## Verifiable requirements

### USK-R-MODULES-001 — Dependency firewall

**Requirement.** The portable model and planner MUST NOT include platform GUI APIs or perform host mutation.

**Rationale.** Enables testable pure planning and alternate targets.

**Acceptance.** `USK-AT-MODULES-001` in the acceptance catalogue.

### USK-R-MODULES-002 — One effect owner

**Requirement.** Frontends and product bindings MUST route installed-software changes through the admitted USK operation interface.

**Rationale.** No second installer hidden in a UI.

**Acceptance.** `USK-AT-MODULES-002` in the acceptance catalogue.

### USK-R-MODULES-003 — No mandatory launcher

**Requirement.** Basic setup MUST remain usable without Universal Launcher or AIDE installed.

**Rationale.** These are optional integration/control-plane consumers.

**Acceptance.** `USK-AT-MODULES-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-ROOT], [^USR-REVIEW], [^CONVERSATION].

[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
[^USR-REVIEW]: User-supplied June provider architecture review; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
