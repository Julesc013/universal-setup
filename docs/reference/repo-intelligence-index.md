# Repo Intelligence Index v0

## Purpose

Q37 adds AIDE's first deterministic repo intelligence layer. It answers what
tracked files exist, how they are classified, which owners they appear to
belong to, which imports and path references are visible, which tests likely
cover which paths, which docs link to repo files, and which files are generated,
evidence-only, template-only, unknown, or conservative orphan candidates.

The index is repo-local and no-call. It does not call models, providers,
outbound network services, GitHub APIs, target repositories, branch mutation
commands, or product runtime code. It does not move, delete, rewrite, refactor,
migrate, or declare files dead.

## Command Surface

```powershell
py -3 .aide/scripts/aide_lite.py repo inventory
py -3 .aide/scripts/aide_lite.py repo classify
py -3 .aide/scripts/aide_lite.py repo validate
py -3 .aide/scripts/aide_lite.py repo status
py -3 .aide/scripts/aide_lite.py repo explain-file .aide/scripts/aide_lite.py
py -3 .aide/scripts/aide_lite.py repo docs
py -3 .aide/scripts/aide_lite.py repo tests
py -3 .aide/scripts/aide_lite.py repo deps
```

`repo inventory` enumerates git-tracked files when Git is available. If Git is
not available, it uses a deterministic filesystem walk that excludes `.git`,
`.aide.local/`, caches, and local runtime state. It writes:

- `.aide/repo/file-inventory.json`
- `.aide/repo/ownership-map.json`
- `.aide/repo/dependency-map.json`
- `.aide/repo/test-map.json`
- `.aide/repo/doc-link-map.json`
- `.aide/repo/generated-map.json`
- `.aide/repo/orphan-candidates.json`
- `.aide/repo/latest-repo-intelligence.md`

`repo classify PATH` prints one deterministic classification. Without a path it
runs the inventory pipeline. `repo validate` checks policies, schemas, latest
outputs, local-state exclusions, and unknown-file warnings. `repo status`
summarizes counts by kind, status, and owner. `repo explain-file PATH` prints
one inventory record plus known dependency, test, and documentation references.

## Policies And Schemas

Classification is governed by:

- `.aide/policies/repo-intelligence.yaml`
- `.aide/policies/file-classification.yaml`
- `.aide/policies/ownership-map.yaml`
- `.aide/policies/dependency-map.yaml`
- `.aide/policies/test-map.yaml`
- `.aide/policies/doc-link-map.yaml`

The JSON outputs are checked by schemas under `.aide/repo/*.schema.json`.
Records include path, kind, status, owner, extension, size, hash, generated and
evidence flags, exportability hints, risk hints, reasons, reference counts, test
counts, and documentation counts.

## How WorkUnits Should Use It

Future WorkUnits should cite compact refs instead of copying large file trees:

- `.aide/repo/latest-repo-intelligence.md`
- `.aide/repo/file-inventory.json`
- `.aide/repo/ownership-map.json`
- `.aide/repo/dependency-map.json`
- `.aide/repo/test-map.json`
- `.aide/repo/doc-link-map.json`

These outputs are evidence. They are not canonical product contracts and do not
authorize implementation by themselves. Before changing a file, inspect the
inventory record, owner, docs, tests, dependency references, generated/evidence
status, allowed paths, and queue policy.

## Conservative Candidates

Q37 uses candidate language by design:

- `orphan_candidate`
- `unreferenced_candidate`
- `unknown_owner`
- `missing_doc_candidate`
- `missing_test_candidate`

Those labels mean "inspect before acting." They do not mean the file is dead,
safe to delete, safe to move, or low value. Deletion and root movement belong to
future reviewed refactor and root-recycling phases.

## Export Boundary

The export pack carries portable repo-intelligence policies, schemas, docs,
tests, golden tasks, and command support. It does not export this source repo's
generated `.aide/repo/*.json` or `latest-repo-intelligence.md` as target truth.
After import, a target repository must run `repo inventory`, `repo validate`,
and `repo status` locally.

## Limits

Q37 is deterministic heuristics only. Python imports, path references,
Markdown links, test targets, owners, generated status, and orphan candidates
can be incomplete. Q38 File Quality Ledger v0 consumes these indexes as
advisory measurement input. Q39 Refactor Control Plane v0 consumes Q37 and Q38
outputs as dry-run planning evidence while still forbidding moves, deletes, and
reference rewrites. Q40 Root Recycling Framework v0 consumes the same indexes
for root-level inventory, risk, and fate classification without moving or
deleting files.
