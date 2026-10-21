# Checkpoint And Promotion Model

The wave policy is defined in `.aide/policies/waves.yaml`. The checkpoint policy is defined in `.aide/policies/checkpoints.yaml`. The dev/main promotion policy is defined in `.aide/policies/dev-main-promotion.yaml`.

A Wave groups related WorkUnits with a dependency graph, parallelism policy, branch policy, validation policy, checkpoint policy, repair pass limits, and evidence refs.

A Checkpoint evaluates candidate WorkUnits for integration or promotion. It records base, integration, and promotion branch names as provenance fields, but X-OS-00 does not mutate branches.

Promotion decisions:

- `promote`
- `promote_with_classified_warnings`
- `repair_required`
- `quarantine_required`
- `defer`
- `blocked`
- `unknown`

Result semantics:

- `PASS`: evidence supports the gate.
- `PASS_WITH_WARNINGS`: evidence supports the gate with classified warnings.
- `FAIL_REPAIRABLE`: repair or split is required before promotion.
- `FAIL_UNSAFE`: quarantine and human decision are required.
- `FAIL_UNKNOWN`: classify before continuation or promotion.

## Validation

Normal post-task work uses T0/T1 by default. Checkpoint, promotion, and release gates require T0, T1, relevant T2, and T3 when the X-TEST-00 validation policy says promotion evidence is needed.

## Boundary

X-OS-00 records promotion rules and checkpoint records only. It does not merge, push, promote, create worktrees, create branches, apply checkpoints, publish releases, call GitHub APIs, or mutate target repositories.
