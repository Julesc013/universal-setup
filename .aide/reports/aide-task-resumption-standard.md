# AIDE Task Resumption Standard

## Resumption Rule

Agents must resume from repo-local queue state before relying on chat order.
The primary surfaces are `.aide/queue/index.yaml`, task `status.yaml`, task
evidence, and `.aide/context/latest-task-packet.md`.

## Repeated Prompt

If a repeated prompt requests already-complete work, inspect evidence and
validation first. If acceptance surfaces already exist, report
`noop_already_complete` and avoid mutations.

## Out-of-Order Prompt

If a later task arrives before prerequisites are accepted, inspect the queue
index and dependency evidence. Complete bounded prerequisite metadata only when
safe; otherwise record the blocker.

## Incomplete Previous Task

If the previous task is partial, inspect changed files, status, validation, and
remaining risks. Resume in scope when possible and preserve unrelated changes.

## Evidence Before Escalation

Ask the user only after repo-local evidence cannot resolve the state safely.
Missing credentials, destructive ambiguity, and unresolved manual-content
conflicts stop the task.

## Validation Gates

Use `git status --short`, `git diff --check`, AIDE doctor/validate/eval, and
task-specific tests before reporting a substantive task complete.
