---
type: "Adoption Guide"
title: "Import procedure and optional repository adapters"
description: "Add the specification without overwriting implementation, README, contracts or grants."
tags: ["universal-setup","integration"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-ROOT","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py","title": "Universal Setup pinned root/structure validator"},{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "CODEX","resource": "https://developers.openai.com/codex/guides/agents-md","title": "Official Codex repository instruction guidance, retrieved 2026-09-20"},{"id": "CLAUDE","resource": "https://code.claude.com/docs/en/memory","title": "Official Claude Code project instruction guidance, retrieved 2026-09-20"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-IMPORT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTH","USK-S-AGENT"]}
---

# Import procedure and optional repository adapters

## Review before import
The primary ZIP extracts only `spec/`. If the repository already has `spec/`, merge in a task worktree; do not overwrite it. Verify archive checksum and inspect its file list. Preserve current branch policy and external build-root conventions.

At the pinned source, `tools/structure_policy_check.py` rejects the new root. `integration/root-admission.patch` adds only `spec` to the allowlist. Run `git apply --check spec/integration/root-admission.patch` before applying; if context changed, review/adapt it instead of forcing. The patch does not modify branch permissions, retired roots, native authority or README.

Create a separate architecture/adoption record under an already admitted docs path, naming this spec version/digest, decisions accepted, remaining exceptions and reviewer. Existing policy and contracts remain controlling until their own reviewed changes land.

## Optional adapters
`AGENTS.md.txt`, `CLAUDE.md.txt` and `ci-snippet.yml.txt` are inert templates. Root AGENTS/CLAUDE files are not admitted by the pinned root validator, so installing them requires a separate precise allowlist change. Merge with existing instructions; do not replace them. CI snippets require integration into the actual workflow and toolchain; this archive does not activate CI.

## First commands
```text
python spec/tools/specctl.py validate
python spec/tools/specctl.py index --check
python -B -m unittest discover -s spec/tools/tests -v
python spec/tools/specctl.py status
python spec/tools/specctl.py next
```
Generate a context pack or rendered docs into an external owned output directory. AIDE exports remain inactive until imported with the actual AIDE adapter and grant policy. Do not use the prototype machine-plan examples for live installation.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-ROOT], [^REPO-README], [^CODEX], [^CLAUDE], [^CONVERSATION].

[^REPO-ROOT]: [Universal Setup pinned root/structure validator](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/tools/structure_policy_check.py).
[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^CODEX]: [Official Codex repository instruction guidance, retrieved 2026-09-20](https://developers.openai.com/codex/guides/agents-md).
[^CLAUDE]: [Official Claude Code project instruction guidance, retrieved 2026-09-20](https://code.claude.com/docs/en/memory).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
