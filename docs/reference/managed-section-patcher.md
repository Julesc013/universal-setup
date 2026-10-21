# Managed Section Patcher

AIDE-APPLY-01 implements the first reusable managed-section patcher layer.

The patcher updates generated content only when explicit markers bound the
section:

```text
<!-- AIDE-GENERATED:BEGIN section=<section-name> ... -->
generated content
<!-- AIDE-GENERATED:END section=<section-name> -->
```

The marker line must be unambiguous, must name a stable section, and must match
the canonical `AIDE-GENERATED` marker family. Manual text before the begin marker
and after the end marker is user-owned and must be preserved exactly.

## Behavior

- Missing start or end markers block patching.
- Duplicate start or end markers block patching.
- Nested markers block patching.
- Malformed markers block patching.
- Existing section hash mismatches block patching.
- Binary or unsupported-encoding files are rejected by file-level helpers.
- Section, manual prefix, manual suffix, preimage, and postimage hashes are
  recorded for fixture proof.

## Command Surface

`py -3 .aide/scripts/aide_lite.py managed-section status` writes
`.aide/reports/managed-section-status.md`.

`py -3 .aide/scripts/aide_lite.py managed-section validate` validates policies,
schemas, examples, reports, core functions, golden task registration, and the
no-real-apply command boundary.

`py -3 .aide/scripts/aide_lite.py managed-section fixture-plan` writes
deterministic fixture-only plan and conflict reports under `.aide/reports/`.

`py -3 .aide/scripts/aide_lite.py managed-section fixture-verify` patches only
temporary fixture files or in-memory text and writes fixture validation evidence.

No command patches `AGENTS.md`, `CLAUDE.md`, generated adapters, or any active
repository file as a managed-section apply operation.

## Transaction Relation

The fixture plan emits transaction-compatible records:

- `update_managed_section` file operation;
- managed-section operation record;
- staged-change record;
- preimage and postimage hashes;
- rollback-compatible evidence record;
- conflict records.

Rollback records are evidence only. They do not execute rollback behavior.

## Boundary

AIDE-APPLY-01 does not implement real install apply, upgrade apply, repair apply,
rollback apply, uninstall apply, active repository apply, target mutation,
branch/worktree automation, merge/push/promotion, release publication, GitHub
API mutation, provider/model calls, network calls, or Gateway forwarding.

Future install or upgrade apply phases must pass through review and must consume
ownership, preimage, postimage, rollback, conflict, and safety-gate evidence
before any active file mutation is considered.
