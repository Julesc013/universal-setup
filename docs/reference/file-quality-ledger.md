# File Quality Ledger v0

## Purpose

Q38 adds AIDE's first deterministic File Quality Ledger. It consumes Q37 repo
intelligence outputs and reports advisory quality evidence for file ownership,
kind/status, generated and evidence boundaries, documentation, tests,
validators, stale doc links, orphan candidates, module size, mixed-purpose
hints, and reuse/modularity candidates.

The ledger is repo-local and no-call. It does not call models, providers,
outbound network services, GitHub APIs, target repositories, branch mutation
commands, or product runtime code. It does not move, delete, rewrite, refactor,
migrate, or auto-fix files.

## Command Surface

```powershell
py -3 .aide/scripts/aide_lite.py repo inventory
py -3 .aide/scripts/aide_lite.py quality ledger
py -3 .aide/scripts/aide_lite.py quality validate
py -3 .aide/scripts/aide_lite.py quality status
py -3 .aide/scripts/aide_lite.py quality explain-file .aide/scripts/aide_lite.py
py -3 .aide/scripts/aide_lite.py quality docs
py -3 .aide/scripts/aide_lite.py quality tests
py -3 .aide/scripts/aide_lite.py quality modules
py -3 .aide/scripts/aide_lite.py quality reuse
```

`quality ledger` reads:

- `.aide/repo/file-inventory.json`
- `.aide/repo/ownership-map.json`
- `.aide/repo/dependency-map.json`
- `.aide/repo/test-map.json`
- `.aide/repo/doc-link-map.json`
- `.aide/repo/generated-map.json`
- `.aide/repo/orphan-candidates.json`

It writes:

- `.aide/reports/file-quality-ledger.json`
- `.aide/reports/file-quality-summary.md`
- `.aide/reports/module-quality-report.md`
- `.aide/reports/docs-consistency-report.md`
- `.aide/reports/test-coverage-map.md`
- `.aide/reports/reuse-modularity-report.md`

## Levels

- `pass`: known owner/kind/status and no current Q38 warnings.
- `warn`: unknown owner/kind/status, missing docs/tests/validators, stale doc
  refs, orphan candidates, large or mixed-purpose module candidates, or reuse
  candidates.
- `fail`: tracked local-state or secret-like paths, invalid records, or
  policy-forbidden state.
- `exempt`: generated, evidence-only, template, archive, or documentation
  cases where active docs/tests are not required.
- `unknown`: insufficient data.

The ledger does not compute a hidden numeric score.

## Candidate Language

Q38 uses warning and candidate wording by design:

- `missing_doc_candidate`
- `missing_test_or_validator_candidate`
- `stale_doc_reference_candidate`
- `orphan_candidate`
- `large_module_candidate`
- `mixed_purpose_candidate`
- `reuse_candidate`

Those labels mean "inspect before acting." They do not mean a file is dead,
safe to delete, safe to move, or low value. Deletion and root movement belong
to later reviewed refactor and root-recycling phases.

## How WorkUnits Should Use It

Future WorkUnits should cite compact refs instead of copying large reports:

- `.aide/reports/file-quality-summary.md`
- `.aide/reports/file-quality-ledger.json`
- `.aide/reports/module-quality-report.md`
- `.aide/reports/docs-consistency-report.md`
- `.aide/reports/test-coverage-map.md`
- `.aide/reports/reuse-modularity-report.md`

Before changing a file, inspect the Q37 inventory record and the Q38 quality
record. Resolve warnings through focused future WorkUnits, not broad cleanup
prompts.

## Export Boundary

The export pack carries portable Q38 policies, schemas, docs, tests, golden
tasks, and command support. It does not export this source repo's generated
quality reports as target truth. After import, a target repository must run
`repo inventory` and `quality ledger` locally.

## Limits

Q38 is deterministic heuristics only. Missing docs/tests, stale links, orphan
candidates, reuse candidates, and mixed-purpose hints can be incomplete. Q39
Refactor Control Plane v0 consumes these warnings as dry-run planning evidence,
and Q40 Root Recycling Framework v0 specializes them into root-level risk and
fate candidates. Neither phase applies refactors directly.
