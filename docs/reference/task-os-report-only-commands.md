# Task OS Report-Only Commands

X-OS-01 adds local, report-only inspection and planning commands for AIDE Task OS records. These commands read the AIDE source repository's queue, status, evidence, and generated report files, then write deterministic reports under `.aide/reports/task-os-*`.

The commands do not execute tasks, apply repair plans, requeue work, resume target work, create branches, merge, push, promote, publish releases, call providers or models, call the network, or mutate target repositories.

## Command Surface

- `py -3 .aide/scripts/aide_lite.py task status`
- `py -3 .aide/scripts/aide_lite.py task classify`
- `py -3 .aide/scripts/aide_lite.py task repair-plan`
- `py -3 .aide/scripts/aide_lite.py task requeue-plan`
- `py -3 .aide/scripts/aide_lite.py task resume-plan`
- `py -3 .aide/scripts/aide_lite.py blocker status`
- `py -3 .aide/scripts/aide_lite.py blocker classify`
- `py -3 .aide/scripts/aide_lite.py wave status`
- `py -3 .aide/scripts/aide_lite.py wave plan`
- `py -3 .aide/scripts/aide_lite.py checkpoint status`
- `py -3 .aide/scripts/aide_lite.py checkpoint plan`

## Generated Reports

- `.aide/reports/task-os-command-status.md`
- `.aide/reports/task-os-task-status.md`
- `.aide/reports/task-os-task-classification.json`
- `.aide/reports/task-os-task-classification.md`
- `.aide/reports/task-os-repair-plan.md`
- `.aide/reports/task-os-requeue-plan.md`
- `.aide/reports/task-os-resume-plan.md`
- `.aide/reports/task-os-blocker-status.md`
- `.aide/reports/task-os-blocker-classification.json`
- `.aide/reports/task-os-blocker-classification.md`
- `.aide/reports/task-os-wave-status.md`
- `.aide/reports/task-os-wave-plan.md`
- `.aide/reports/task-os-checkpoint-status.md`
- `.aide/reports/task-os-checkpoint-plan.md`
- `.aide/reports/task-os-next-plan.md`

## Interpretation

`task status` summarizes known queue items and writes the task status report. `task classify` classifies the latest task packet into the X-OS-00 lifecycle vocabulary and records blockers or warnings as report data.

In a newly imported target with no queue WorkUnits, `task status` reports zero
tasks, `latest_task_id: none`, and `No queued WorkUnit selected`. It continues
to exit 1 for an empty queue. A generated packet's contextual references do
not create task identity; an explicit packet `task_id` or a leading PHASE/GOAL
identity is required. New work must be admitted through the target's own
intake and queue before these reports can name a next WorkUnit.

After the target admits project-owned WorkUnits, `task status` and `task
next-plan` direct the operator to inspect that target queue's status and
evidence. A target profile takes precedence even if a queue ID happens to
match an AIDE source phase. Target next-plan reports omit AIDE source
readiness fields and do not authorize task execution. The AIDE self-hosting
profile retains its existing X-OS phase routing. Legacy fixtures without a
profile use exact source queue IDs to retain their historical routing.

`blocker status` and `blocker classify` convert visible blocked, review-gated, or deferred state into typed report records. A repairable marker means "candidate for a future reviewed repair WorkUnit"; it is not proof that a repair was executed.

`task repair-plan`, `task requeue-plan`, and `task resume-plan` are planning aids. They may name suggested repair or resume paths, but they always record that no queue mutation, repair execution, target resume, or target mutation was applied.

`wave status`, `wave plan`, `checkpoint status`, and `checkpoint plan` describe the current AIDE-only Task OS foundation wave and the planned X-OS-02 / AIDE-CHECK-OS-01 sequence. They do not create checkpoint branches or promote work to `main`.

X-OS-02 adds a separate `capability` command group for capability reality scans, ledgers, overclaim reports, and validation. Those commands write `.aide/reports/capability-*` outputs and preserve the same report-only boundary.

## Boundary

Every generated Markdown report includes these boundary markers:

- `mode: report_only`
- `task_execution: false`
- `repair_execution: false`
- `branch_mutation: false`
- `target_mutation: false`
- `provider_or_model_calls: none`
- `network_calls: none`

JSON classification reports include the same boundary under `no_apply_boundary`.

## Validation

X-OS-01 is covered by:

- `.aide/scripts/tests/test_x_os_01_task_os_commands.py`
- `.aide/scripts/tests/test_x_os_02_capability_reality.py` for the X-OS-02 capability surface
- `validate_task_os_command_files` inside `.aide/scripts/aide_lite.py`
- `validate_capability_files` inside `.aide/scripts/aide_lite.py`
- six `task_os_*` golden tasks added for command surface, status/classification, repair/requeue/resume planning, blocker classification, wave/checkpoint planning, and no-apply boundaries
- six `capability_*` golden tasks added for seed coverage, command surface, ledger generation, overclaim reporting, no-apply boundaries, and export-pack inclusion

The command reports are source-repository evidence only. Target repositories must generate their own status, blocker, wave, checkpoint, and capability-reality evidence after import.
