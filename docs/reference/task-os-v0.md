# AIDE Task OS v0

AIDE Task OS v0 is the repo-native vocabulary for work that can be inspected, resumed, repaired, reviewed, checkpointed, and eventually promoted with evidence.

X-OS-00 is report-only. It defines schemas, policies, examples, docs, tests, golden tasks, and validation hooks. It does not implement scheduling, branch creation, merge, push, promotion, checkpoint apply, transactional apply, repair apply, release publication, provider/model calls, network calls, Gateway forwarding, target sync, or target-repo mutation.

X-OS-01 builds on this policy layer by adding local report-only `task`, `blocker`, `wave`, and `checkpoint` inspection/planning commands. Those commands write `.aide/reports/task-os-*` evidence but still do not execute tasks, repairs, branches, promotions, provider/model calls, network calls, releases, or target-repo mutations.

X-OS-02 adds local report-only `capability` commands. Those commands write `.aide/reports/capability-*` observations, ledgers, overclaim reports, and validation summaries while preserving the same no-apply, no-target, no-branch, no-release, no-provider/model, and no-network boundary.

## Why This Exists

AIDE has a growing set of report-first systems: prompt normalization, WorkUnit drafts, repo intelligence, file quality, refactor planning, install/repair/upgrade/rollback/uninstall planning, release bundle drafts, GitHub release drafts, and validation tiers. Those systems need a shared task vocabulary so blocked or partial work becomes typed and reviewable instead of being hidden or falsely completed.

Task OS v0 makes these concepts first-class:

- WorkUnit
- TaskAttempt
- Blocker
- RepairTask
- Wave
- Checkpoint
- BranchProvenance
- CapabilityReality
- append-only-style task, blocker, capability, branch, and checkpoint ledgers

## Dev/Main Doctrine

`dev` is the progress surface. It may carry classified non-fatal warnings and integration candidates.

`main` is the evidence-backed truth surface. Main promotion requires evidence, validation, warning disposition, blocker disposition, and capability reality checks.

X-OS-00 records this doctrine in policy only. It does not create, merge, push, or promote branches.

## Capability Reality

Capability reality prevents overclaiming. Documentation, fixtures, report-only commands, dry-runs, no-call provider metadata, release drafts, and status files are evidence, but they are not the same as live implementation or apply behavior.

The capability states are `planned`, `specified`, `stubbed`, `implemented`, `tested`, `exposed`, `documented`, `deprecated`, `removed`, and `unknown`.

X-OS-02 records state through `.aide/capabilities/capability-seeds.yaml` and generated `.aide/reports/capability-*` files. The generated ledger is source-side report evidence, not proof that target repositories, releases, providers, models, Runtime, or host surfaces are live.

## Explicit Non-Implementation

X-OS-00 does not implement:

- active scheduler
- apply-capable Task OS commands beyond X-OS-01 report-only inspection/planning
- repair execution
- branch/worktree automation
- checkpoint apply
- merge, push, or promotion
- transactional apply
- install/repair/upgrade/rollback/uninstall apply
- Gateway/provider runtime
- target sync or target tests
