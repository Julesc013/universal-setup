# Transaction Model

AIDE transactions are typed records for planning file operations before any future apply-capable phase exists. A transaction groups operations, preimages, predicted postimages, staged changes, safety gates, conflicts, rollback records, verification results, and evidence.

In AIDE-APPLY-00 the model is limited to report-only and fixture-only behavior. `transaction status` and `transaction validate` report contract state. `transaction fixture-plan` writes a deterministic fixture transaction plan under `.aide/reports/`. `transaction fixture-verify` verifies that fixture plan without applying it to the active repository.

## Required Boundary

- real_repo_apply_allowed: false
- target_mutation: false
- branch_mutation: false
- worktree_mutation: false
- provider_or_model_calls: none
- network_calls: none
- github_api_mutation: false
- release_publication: false

Rollback records are evidence records and inverse-operation plans. They are not executable rollback behavior in this phase.

## AIDE-APPLY-01 Integration

AIDE-APPLY-01 adds a managed-section patcher that produces
transaction-compatible fixture records for `update_managed_section` operations.
The fixture plan records a managed-section operation, staged change, preimage,
postimage, rollback-compatible evidence, conflicts, and no-real-apply boundary
fields.

This integration remains fixture-only. It does not create an active repository
transaction apply command and does not authorize install, upgrade, repair,
rollback, or uninstall apply.
