# Existing Tool Adapter Compiler v0

Q24 adds a deterministic AIDE Lite compiler for guidance files used by existing
coding tools. It is intentionally a template compiler, not a tool runtime,
Gateway, provider adapter, IDE extension, MCP server, or automation loop.

## Why It Exists

AIDE saves tokens fastest when existing tools use compact task packets,
evidence packets, verifier output, and review gates instead of long chat
history. Most users already use tools such as Codex, Claude Code, Aider, Cline,
Continue, Cursor, and Windsurf, so Q24 generates small guidance surfaces for
those tools from the repo-local AIDE contract.

Q24 comes after Q21 export/import because target repos need safe local AIDE Lite
packs before they generate local tool guidance. At original Q24 implementation
time the real Eureka/Dominium pilot evidence was not present, so Q24 used AIDE
substrate and Q21 fixture evidence and recorded that limitation. A later
post-pilot refresh inspected the sibling target repos read-only and found
Eureka and Dominium import pilots present and awaiting review, with estimated
task-packet reductions of about 98.6 percent and 99.0 percent respectively.
Those pilots strengthen the portability case, but they still do not prove every
generated tool adapter output has been used by its target tool.

## Source Records

- Policy: `.aide/policies/adapters.yaml`
- Targets: `.aide/adapters/targets.yaml`
- Templates: `.aide/adapters/templates/**`
- Generated previews: `.aide/generated/adapters/**`
- Manifest: `.aide/generated/adapters/manifest.json`
- Drift report: `.aide/generated/adapters/drift-report.md`

Generated adapter outputs are downstream guidance. They are not canonical truth;
the `.aide/` Profile/Contract, policies, queue, prompts, and evidence remain
authoritative.

## Targets

- Codex: `AGENTS.md`, safe managed section.
- Claude Code: `.aide/generated/adapters/CLAUDE.md`, preview only.
- Aider: `.aide/generated/adapters/aider.conf.yml`, preview only.
- Cline: `.aide/generated/adapters/clinerules`, preview only.
- Continue: `.aide/generated/adapters/continue-checks/aide-token-survival.md`, preview only.
- Cursor: `.aide/generated/adapters/cursor-rules/aide-token-survival.mdc`, preview only.
- Windsurf: `.aide/generated/adapters/windsurf-rules/aide-token-survival.md`, preview only.

Q24 records VS Code as optional but does not generate `.vscode/tasks.json`.

## Commands

```text
py -3 .aide/scripts/aide_lite.py adapter list
py -3 .aide/scripts/aide_lite.py adapter render
py -3 .aide/scripts/aide_lite.py adapter preview
py -3 .aide/scripts/aide_lite.py adapter validate
py -3 .aide/scripts/aide_lite.py adapter drift
py -3 .aide/scripts/aide_lite.py adapter generate
py -3 .aide/scripts/aide_lite.py adapt
```

`adapter render` writes generated previews and manifest/drift artifacts under
`.aide/generated/adapters/`.

`adapter generate` writes only safe managed-section targets. In Q24 that means
`AGENTS.md`; it does not write `CLAUDE.md`, `.aider.conf.yml`, `.clinerules`,
`.continue/**`, `.cursor/**`, `.windsurf/**`, or `.vscode/**`.

`adapt` remains a backward-compatible shortcut for refreshing the safe AGENTS
managed section.

## Safety Boundary

Q24 does not:

- call providers, models, tools, networks, or Gateway forwarding;
- create IDE extensions or runtime integrations;
- store raw prompts, raw responses, provider keys, or local traces;
- commit `.aide.local/` contents;
- make generated adapter outputs canonical;
- overwrite manual tool guidance outside managed sections.

## Portable Pack

The Q21 portable pack now includes adapter policy, targets, and templates so
target repos can generate their own adapter previews after import. The pack does
not include source repo generated adapter outputs as target truth.

## Review Notes

Adapter templates are intentionally compact. They should point tools toward
`.aide/context/latest-task-packet.md`, validation commands, evidence packets,
and review gates, not duplicate the full AIDE doctrine.
