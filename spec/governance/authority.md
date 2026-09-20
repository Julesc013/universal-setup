---
type: "Engineering Specification"
title: "Authority, adoption and source-of-truth boundaries"
description: "Define what each repository surface may decide and prohibit accidental grants from prose."
tags: ["universal-setup","governance"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"},{"id": "AIDE-README","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md","title": "AIDE README; inspect contracts and source when implementation claims conflict"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-AUTH","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": []}
---

# Authority, adoption and source-of-truth boundaries

## Authority map
| Surface | Canonical responsibility | Must not become |
|---|---|---|
| Existing repository governance/policy | Permitted work, branches, publication, lab roots | A generated summary |
| `spec/` after adoption | Intended semantics, requirements, decisions, acceptance definitions | Runtime permission or test evidence |
| `contracts/` | Executable published ABI, schemas and wire contracts | Independently rewritten prose copy |
| `runtime/`, `apps/`, `include/` | Implementation and public code surface | Proof of support by existence |
| `tests/` | Executable verification | Its own authority to approve effects |
| `release/` | Actual versions, packages, qualification and release claims | Speculative future status |
| AIDE queue/protocol/evidence | Admitted tasks, attempts, grants and receipts | A shadow copy of product state |
| `docs/` | User/developer explanations, tutorials and publication | A second normative definition |
| Derived indexes/context packs | Retrieval, summaries, routing | Permission, acceptance or current repository truth |

Conflicts are recorded and resolved by an explicit decision. A later timestamp alone does not overrule policy, source evidence or an adopted contract. The newest user product objective can propose a policy change; it cannot retrospectively make old test evidence support it.

## Adoption record
An adoption record identifies this specification version/digest, reviewed changes, accepted decisions, exceptions, repository base, approving principal and scope. Separate architectural adoption from implementation delegation, disposable-lab effects, protected integration and public release approval.

## Requirements language
MUST and MUST NOT describe proposed normative obligations. SHOULD requires a documented justified exception. MAY means optional behavior that is still constrained by the owning profile. No sentence in this archive authorizes operating on real user state.

## Change control
Semantic changes require affected IDs, rationale, source/decision references, compatibility impact and test-impact selection. Stable IDs are never reused with different meaning. Generated views are rebuilt rather than hand-edited. Superseded decisions remain discoverable. A specification can be accepted while many implementations remain absent.

## Verifiable requirements

### USK-R-AUTH-001 — No implicit activation

**Requirement.** Importing or validating this specification MUST NOT enable mutation, protected merges, signing or publication.

**Rationale.** Presence is not authority.

**Acceptance.** `USK-AT-AUTH-001` in the acceptance catalogue.

### USK-R-AUTH-002 — Single machine-contract owner

**Requirement.** Adopted runtime schemas MUST reside in contracts/; draft schemas in this archive MUST be promoted, not independently copied and evolved.

**Rationale.** Two masters drift.

**Acceptance.** `USK-AT-AUTH-002` in the acceptance catalogue.

### USK-R-AUTH-003 — Independent evidence

**Requirement.** Specification validity MUST remain separate from runtime, security, accessibility and release qualification.

**Rationale.** A readable requirement is not an executed test.

**Acceptance.** `USK-AT-AUTH-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^REPO-ROOT], [^AIDE-README], [^CONVERSATION].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
[^AIDE-README]: [AIDE README; inspect contracts and source when implementation claims conflict](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
