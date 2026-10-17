# AIDE WorkUnit Recovery Standard

Q27 defines a WorkUnit as a bounded queue task with a stable id, allowed paths,
acceptance criteria, validation evidence, and completion predicates.

## Idempotency

The idempotency key combines task id, allowed-path scope, and acceptance
criteria. Replaying the same prompt should either continue partial work or
return `noop_already_complete`; it should not duplicate accepted work.

## States

- planned
- ready
- running
- partial
- needs_review
- passed
- passed_with_notes
- blocked
- superseded
- noop_already_complete
- reopened

## Recovery Profiles

Recovery starts from repository state. Duplicate tasks, out-of-order tasks,
partial tasks, dirty trees, stale statuses, failed validation, manual content
conflicts, missing dependencies, missing external secrets, and destructive
ambiguity each have explicit inspection steps and stop conditions in
`.aide/policies/recovery.yaml`.

## Limits

Recovery is report-first. Q27 does not authorize product implementation,
branch mutation, release publishing, provider calls, model calls, or network
calls.
