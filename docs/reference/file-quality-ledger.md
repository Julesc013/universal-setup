# File Quality Ledger v0

## Finding recorded owners, helpers and checks

`quality explain-file <path>` shows a compact advisory view of the recorded owner,
documentation, likely tests, local references and reuse candidates. Add `--json`
for a deterministic machine-readable projection. The command reads only the
existing quality ledger (maximum 16 MiB), does not scan source or regenerate
reports, and limits each relation/candidate/peer list to 20 with omitted counts.
Both formats also have a 64 KiB UTF-8 output ceiling. An explanation exceeding it
returns `INVALID` without emitting a partial explanation or changing the report.

Each relation explains its selection reason. Repeated helper names, matching
content hashes and similar filenames are investigation leads; they do not prove
shared meaning or authorize merging implementations. Test links are heuristic,
not executed checks or a sufficient basis for narrowing validation.

Freshness is explicitly `unverified`: the recorded source commit attributes the
report but does not verify current bytes or dependencies. An empty recorded list
means `not_found`; a missing file record or older ledger without reuse data means
`unindexed`. Neither means known absent. Inspect relevant source and broaden
checks when coverage is uncertain. `PASS` means the projection succeeded, not
that the file passed quality or runtime checks.

New `quality ledger` output retains its already-computed `reuse_report` as an
optional object. Existing v0 ledgers remain valid. Lookup exit codes are 0 for a
found record, 1 for a missing report/record, and 2 for invalid or oversized input.
Report-generation commands remain separate explicit operations.

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

### Fresh Python symbol inspection

Use `quality inspect-symbol NAME --path FILE [--path FILE] [--json]` to
inspect an existing helper before writing another implementation. Unlike the
recorded-only `quality explain-file` view, this command reads explicitly selected
source now. It does not rebuild the ledger or execute project code.

- **Fresh evidence:** definitions with lexical names, kind, parameter names and
  kinds, locations and exact file hashes; matching calls and import declarations.
  Each parsed file names the Python parser/runtime used.
- **Limits:** one normalized Python identifier and one to eight ordinary relative
  files; 4 MiB per file, 8 MiB selected source, 16 MiB existing ledger, 64 KiB
  output. Python `.py` and `.pyi` files require UTF-8. Up to 20 matches per
  category per file and 32 parameters per definition are shown with omitted counts.
- **Coverage:** calls match syntax, not a resolved runtime target. Aliases,
  decorators, dynamic dispatch and complete evaluation scopes remain unresolved.
  Parsed/not-found differs from missing, unsupported or unindexed syntax.
  Unselected files are outside coverage; missing matches cannot justify narrower
  validation alone. No function bodies, literal/default values or docstrings
  are copied into the result.
- **Recorded context:** existing owner, documentation and likely tests retain
  their advisory, freshness-unverified status. A missing or malformed ledger
  does not hide fresh syntax facts. Its digest identifies the inspected record.
- **Read-only behavior:** no recursive scan, report/cache writes, imports from
  the selected project, model calls or apply. Ordinary-file checks reject linked,
  private, traversal and oversized inputs. Sequential byte rechecks detect observed
  source/ledger changes; this is not an atomic snapshot or an OS access boundary.

Exit 0 means all selected source was parsed; it does not establish code quality
or runtime correctness. Exit 1 retains partial coverage; exit 2 refuses unsafe,
changing, ambiguous or oversized observations. JSON is ASCII-safe. Human output
leads with status and locations, with uncertainty and a concrete next step.

For example, inspect `portable_cli_text` in `.aide/scripts/aide_lite.py`
before comparing an exported CLI with source. Its existing projection rewrites
the effort-helper binding intentionally; raw byte equality is the wrong oracle.
`inspect-symbol` helps locate that implementation and references. Independent
checks must still establish the projection's actual behavior.
