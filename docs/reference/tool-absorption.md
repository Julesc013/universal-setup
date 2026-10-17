# Existing Tool Absorption

Q41 adds AIDE's first deterministic Existing Tool Absorption layer. It
discovers candidate repo-specific tools, classifies likely capabilities and
risks, records preservation-first fates, and writes no-execution wrap plans.

Q41 does not execute unknown tools, delete tools, rename tools, migrate tools,
replace old systems, mutate target repositories, call providers/models/network
services, or apply wrappers.

## Why It Exists

Real target repositories already have management systems. Dominium may have
XStack, AuditX, RepoX, TestX, FAST/STRICT/FULL validators, and command
matrices. Eureka may have architecture checks, repo health reports, source
validators, and AIDE-local evidence.

AIDE must preserve those systems until evidence shows how to wrap, adapt,
extract, convert, shim, or retire them. Old names and paths can be awkward, but
old logic and evidence may still be valuable.

## Commands

- `py -3 .aide/scripts/aide_lite.py tools inventory`
- `py -3 .aide/scripts/aide_lite.py tools classify`
- `py -3 .aide/scripts/aide_lite.py tools wrap-plan`
- `py -3 .aide/scripts/aide_lite.py tools validate`
- `py -3 .aide/scripts/aide_lite.py tools status`
- `py -3 .aide/scripts/aide_lite.py tools capabilities`
- `py -3 .aide/scripts/aide_lite.py tools explain-tool <path-or-id>`

`inventory`, `classify`, and `wrap-plan` write generated advisory outputs under
`.aide/tools/`. They do not execute discovered tools.

## Generated Outputs

- `.aide/tools/latest-tool-inventory.json`
- `.aide/tools/latest-tool-inventory.md`
- `.aide/tools/latest-tool-classification.json`
- `.aide/tools/latest-tool-classification.md`
- `.aide/tools/latest-tool-wrap-plan.json`
- `.aide/tools/latest-tool-wrap-plan.md`
- `.aide/tools/latest-tool-adapter-map.json`
- `.aide/tools/latest-tool-adapter-map.md`
- `.aide/tools/tool-risk-summary.md`

These outputs are source-repo evidence only. Target repositories must generate
their own tool inventories and wrap plans after importing portable Q41 support.

## Capability Families

Q41 maps deterministic path/name/shebang hints to capability families:
`validate`, `test`, `build`, `audit`, `lint`, `format`, `generate`, `migrate`,
`release`, `package`, `install`, `docs`, `security`, `repo_policy`, `context`,
and `unknown`.

Capability mapping is advisory. It does not prove semantics and does not make a
tool safe to execute.

## Tool Fates

Q41 uses candidate-only fates: `keep`, `wrap`, `adapt`, `extract`, `convert`,
`archive`, `drop_candidate`, `shim`, and `unknown`.

`drop_candidate` is not deletion approval. `wrap` is not active execution.
`adapt` is not migration. `archive` is not an applied move. Every mutating
future fate requires review, evidence, validation, rollback notes, and an
apply-capable queue item.

## Target Use

Dominium can later map XStack as likely `wrap` or `adapt`, AuditX as `audit`,
RepoX as `repo_policy`, TestX as `test`, and FAST/STRICT/FULL validators as
`validate` profiles. Eureka can map architecture checks as
`repo_policy`/`validate`, repo health reports as `audit`, and source validators
as validation surfaces.

Those examples are guidance only. Target repos must run their own inventories.

## Export Boundary

The export pack carries portable Q41 policies, schemas, tests, golden tasks,
and this reference doc. It excludes source-generated `.aide/tools/latest-*` and
`tool-risk-summary.md` outputs as target truth.

## Q42 Handoff

Q42 Move Map / Salvage Map / Path Alias v0 is next because future absorption and
root cleanup need reviewed path mappings before any structural move, salvage,
alias, wrapper execution, or migration can be considered.

Q42 now consumes Q41 wrap-plan evidence to create candidate salvage entries for
tool capabilities. Those entries preserve source tools in place, keep
`execution_allowed` and `apply_allowed` false, and do not rename, migrate,
execute, wrap, or retire the source tools.
