# WorkUnit Lifecycle

The WorkUnit lifecycle policy is defined in `.aide/policies/task-lifecycle.yaml`.

Lifecycle states:

- `proposed`
- `ready`
- `running`
- `done_local`
- `partial`
- `blocked_repairable`
- `blocked_missing_prereq`
- `blocked_needs_decision`
- `blocked_unsafe`
- `repair_queued`
- `resume_ready`
- `merge_candidate`
- `merged_to_dev`
- `checkpoint_candidate`
- `promoted_to_main`
- `quarantined`
- `superseded`

`partial` is not failure. It means useful work or evidence exists but the WorkUnit has not reached a reviewable local completion state.

Blocked is not deletion. A blocked WorkUnit should emit a typed blocker and, when safe, a future RepairTask plan. Unsafe blockers quarantine instead of applying repairs.

Promotion-eligible does not mean promoted. In X-OS-00, state changes are record semantics only and do not mutate files, branches, remotes, or checkpoints.

## Evidence Expectations

A WorkUnit should reference:

- allowed and forbidden paths
- attempts
- blockers
- repair records
- validation results
- evidence files
- branch provenance when branch work exists
- capability reality records when claims depend on implementation state

## Boundary

No lifecycle transition in X-OS-00 applies file changes, creates branches, merges, pushes, promotes, repairs, installs, upgrades, rolls back, uninstalls, publishes releases, calls providers/models, uses network, or mutates target repositories.
