# AIDE Transaction Model

`.aide/apply/` contains schemas for transaction planning records. The schemas define how future file-operation apply behavior must record observations, plans, staged changes, safety gates, verification, rollback records, conflicts, ownership boundaries, and evidence.

AIDE-APPLY-00 does not enable real repository apply behavior. The only command outputs are report-only status and validation reports plus fixture-only transaction plan and verification reports under `.aide/reports/`.

Real apply, target mutation, branch or worktree mutation, install/repair/upgrade/rollback/uninstall apply, provider/model/network calls, GitHub API mutation, Gateway forwarding, and release publication remain future review-gated work.
