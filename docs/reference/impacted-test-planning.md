# Impacted Test Planning

Impacted-test planning is report-only. It reads changed paths, maps them to likely test roots and tiers, and emits commands to run manually or through a future reviewed runner.

The plan is not proof. Unknown mappings are warnings and require conservative validation. `.aide/**` changes map to AIDE Lite tests and golden tasks; `core/harness/**`, `core/compat/**`, `core/gateway/**`, and `core/providers/**` map to their component tests; `docs/**` maps to documentation validation.

Target-specific manifests are preserved and must not be overwritten by source AIDE.


## Incomplete observations

The JSON, Markdown and CLI distinguish `changed_path_observation: available`
from `incomplete`. Available means the requested Git observations returned
successfully; it is not an atomic filesystem snapshot or semantic dependency
proof. `mapping_coverage` remains `heuristic_incomplete` in both cases.

A missing base or failed working, staged or untracked-path observation retains
known paths, reports the failure and recommends at least the existing T2 fallback.
It never labels that result `no_changed_paths_detected`. If merge-base comparison
fails but endpoint comparison succeeds, the fallback and original failure remain
explicit. Reconcile the missing observation before selecting narrower checks.

The command returns `result: WARN` for incomplete observation and still exits
zero when it successfully writes the advisory report. `next_action` explains what
to resolve. A genuinely successful empty observation can retain T0 advice; project
validation and promotion obligations still apply. The planner never admits or
runs the listed commands, and this update does not replace target-owned manifests.
