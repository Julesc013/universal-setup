# AIDE Lite

## Purpose

AIDE Lite is the repo-local, no-install token-survival, context, verifier, review, token-ledger, golden-task, outcome-controller, router, cache-boundary, Gateway-status, provider-metadata, cross-repo pack, commit/changelog/task recovery, Git workflow, and Git helper surface introduced across Q09-Q29. It prepares compact task packets, deterministic context snapshots, repo maps, test maps, context indexes, approximate token estimates, verifier reports, review packets, metadata-only token ledger records, savings summaries, golden-task reports, outcome reports, advisory recommendations, route-decision reports, cache-key metadata, local/report-only Gateway status, offline provider metadata, portable AIDE Lite Packs, managed agent guidance, structured commit checks, changelog previews, WorkUnit recovery reports, local Git workflow detection reports, dry-run Git helper plans, and selftests without calling models, providers, network services, Gateway forwarding, Runtime, Service, Commander, hosts, local model managers, GitHub APIs, or live branch mutation by default.

## Command Surface

Run commands from the repository root:

```bash
py -3 .aide/scripts/aide_lite.py doctor
py -3 .aide/scripts/aide_lite.py validate
py -3 .aide/scripts/aide_lite.py snapshot
py -3 .aide/scripts/aide_lite.py index
py -3 .aide/scripts/aide_lite.py context
py -3 .aide/scripts/aide_lite.py pack --task "Implement Q15 Golden Tasks v0"
py -3 .aide/scripts/aide_lite.py estimate --file .aide/context/latest-task-packet.md
py -3 .aide/scripts/aide_lite.py verify
py -3 .aide/scripts/aide_lite.py verify --task-packet .aide/context/latest-task-packet.md
py -3 .aide/scripts/aide_lite.py verify --review-packet .aide/context/latest-review-packet.md
py -3 .aide/scripts/aide_lite.py verify --changed-files
py -3 .aide/scripts/aide_lite.py review-pack
py -3 .aide/scripts/aide_lite.py ledger scan
py -3 .aide/scripts/aide_lite.py ledger report
py -3 .aide/scripts/aide_lite.py ledger compare --baseline root_history_baseline --file .aide/context/latest-task-packet.md
py -3 .aide/scripts/aide_lite.py eval list
py -3 .aide/scripts/aide_lite.py eval run
py -3 .aide/scripts/aide_lite.py eval report
py -3 .aide/scripts/aide_lite.py outcome report
py -3 .aide/scripts/aide_lite.py outcome add --phase Q16 --source validation --result PASS --failure-class unknown --severity info
py -3 .aide/scripts/aide_lite.py optimize suggest
py -3 .aide/scripts/aide_lite.py route list
py -3 .aide/scripts/aide_lite.py route validate
py -3 .aide/scripts/aide_lite.py route explain
py -3 .aide/scripts/aide_lite.py cache status
py -3 .aide/scripts/aide_lite.py cache report
py -3 .aide/scripts/aide_lite.py gateway status
py -3 .aide/scripts/aide_lite.py gateway smoke
py -3 .aide/scripts/aide_lite.py provider list
py -3 .aide/scripts/aide_lite.py provider status
py -3 .aide/scripts/aide_lite.py provider validate
py -3 .aide/scripts/aide_lite.py provider probe --offline
py -3 .aide/scripts/aide_lite.py export-pack --name aide-lite-pack-v0
py -3 .aide/scripts/aide_lite.py pack-status
py -3 .aide/scripts/aide_lite.py import-pack --pack .aide/export/aide-lite-pack-v0 --target <target> --dry-run
py -3 .aide/scripts/aide_lite.py import-pack --pack .aide/export/aide-lite-pack-v0 --target <target>
py -3 .aide/scripts/aide_lite.py commit check --latest
py -3 .aide/scripts/aide_lite.py changelog preview
py -3 .aide/scripts/aide_lite.py task inspect
py -3 .aide/scripts/aide_lite.py git detect
py -3 .aide/scripts/aide_lite.py git doctor
py -3 .aide/scripts/aide_lite.py git status
py -3 .aide/scripts/aide_lite.py git plan
py -3 .aide/scripts/aide_lite.py git sync --dry-run
py -3 .aide/scripts/aide_lite.py git land --dry-run --target dev
py -3 .aide/scripts/aide_lite.py git promote --dry-run --from dev --to main
py -3 .aide/scripts/aide_lite.py git prune --dry-run
py -3 .aide/scripts/aide_lite.py git roles
py -3 .aide/scripts/aide_lite.py git policy
py -3 .aide/scripts/aide_lite.py adapt
py -3 .aide/scripts/aide_lite.py test
py -3 .aide/scripts/aide_lite.py selftest
```

Use `python` instead of `py -3` only when the Windows launcher is unavailable.

## Determinism Rules

- Generated text uses stable newlines and repo-relative paths.
- Snapshot records are sorted and include hashes, sizes, mtimes, extensions, coarse types, and summary counts, but no raw file contents.
- Repo-map and test-map records are sorted and contain metadata/refs only.
- `pack` writes `.aide/context/latest-task-packet.md` with context references and budget status instead of whole files.
- `verify` inspects packet shape, file refs, line refs, changed-file scope, adapter drift, context shape, token warnings, and obvious secret risks without raw file contents.
- `review-pack` writes `.aide/context/latest-review-packet.md` with task/context/verification/evidence refs, changed-file summaries, validation summaries, token summaries, risks, and decision instructions without full diffs or source dumps.
- `ledger scan` and `ledger report` write metadata-only estimated token records and compact savings summaries without raw prompts or raw responses.
- `eval list`, `eval run`, and `eval report` run Q15 deterministic local golden tasks and write metadata-only PASS/WARN/FAIL reports.
- `outcome report` writes `.aide/controller/latest-outcome-report.md` and `.aide/controller/outcome-ledger.jsonl` from deterministic local token, verifier, review, context, eval, and adapter signals.
- `optimize suggest` writes `.aide/controller/latest-recommendations.md` with evidence sources, expected benefits, risk levels, next actions, rollback conditions, and `applies_automatically: false`.
- `route list` prints advisory route classes, task profiles, and hard floors without provider calls.
- `route validate` checks Q17 routing policy/model files, hard floors, route-decision shape, and live-call-disabled posture.
- `route explain` writes `.aide/routing/latest-route-decision.json` and `.aide/routing/latest-route-decision.md` with task class, risk class, route class, hard floor, quality gates, evidence sources, and advisory-only safety status.
- `cache status` and `cache report` validate the `.aide.local/` boundary and write deterministic cache-key metadata without raw content.
- `gateway status` and `gateway smoke` expose local/report-only Gateway skeleton metadata without provider forwarding.
- `provider list`, `provider status`, `provider validate`, and `provider probe --offline` report offline provider-adapter metadata without credentials, probes, model calls, or network calls.
- `export-pack` writes `.aide/export/aide-lite-pack-v0/` with portable scripts, policies, prompts, templates, starter evals, docs, checksums, and install instructions.
- `pack-status` validates the committed pack checksums and forbidden-content boundary.
- `import-pack --dry-run` validates a pack and reports target copy operations without writing.
- `import-pack` copies portable files into a target repository, creates target-specific placeholders when absent, preserves manual `AGENTS.md` content, and keeps `.aide.local/` ignored.
- `commit`, `changelog`, and `task` commands enforce Q27 structured commits and repo-state-first WorkUnit recovery.
- `git detect`, `git doctor`, `git status`, `git workflow`, `git roles`, and `git policy` report Q28 branch workflow state without fetch, merge, prune, push, delete, branch creation, GitHub API calls, provider calls, or network calls.
- `git plan`, `git sync`, `git land`, `git promote`, and `git prune` add Q29 dry-run-first helper planning. `git plan` writes `.aide/git/latest-helper-plan.*`; land/promote/prune `--apply` paths are tested only in temporary fixture repositories in Q29 and must not be run on live AIDE branches during this phase.
- `adapt` preserves manual `AGENTS.md` content outside managed markers and can run twice without changing the file.
- Managed-section drift is reported by `doctor` or `validate` and repaired by `adapt` because the section is generated.

## Validation And Tests

Use the QFIX-02 canonical AIDE Lite test command for routine validation:

```bash
py -3 .aide/scripts/aide_lite.py test
```

`selftest` remains a compatibility alias over the same internal checks:

```bash
py -3 .aide/scripts/aide_lite.py selftest
```

Use raw unittest discovery when you need the AIDE Lite unit suite:

```bash
py -3 -m unittest discover -s .aide/scripts/tests
py -3 -m unittest discover -s core/harness/tests -t .
```

The direct `.aide/scripts/tests` discovery form is the supported raw unittest
shape. Do not use `py -3 -m unittest discover -s .aide/scripts/tests -t .` for
AIDE Lite tests: Python requires the start directory to be importable under the
repo-root top-level package rule, and `.aide/` is a hidden repo contract
directory rather than a Python package namespace. QFIX-02 records that exact old
command as invalid/non-canonical and replaces it with `aide_lite.py test`.

See [aide-lite-test-runner.md](aide-lite-test-runner.md) for the QFIX-02
diagnosis and runner contract.

## Deferred Work

AIDE Lite does not implement exact tokenization, provider billing integration, real API usage accounting, automatic GPT review calls, live routing, route execution, cache sharing, Gateway forwarding, provider adapter execution, provider probes, Runtime, Service, Commander, UI, Mobile, MCP/A2A, host behavior, embeddings, vector search, semantic cache, LLM-as-judge, automatic repair, autonomous loops, GitHub protection mutation, live branch mutation, remote push, CI activation, release publishing, or automatic prompt/policy/route mutation.
