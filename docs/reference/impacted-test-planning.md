# Impacted Test Planning

Impacted-test planning is report-only. It reads changed paths, maps them to likely test roots and tiers, and emits commands to run manually or through a future reviewed runner.

The plan is not proof. Unknown mappings are warnings and require conservative validation. `.aide/**` changes map to AIDE Lite tests and golden tasks; `core/harness/**`, `core/compat/**`, `core/gateway/**`, and `core/providers/**` map to their component tests; `docs/**` maps to documentation validation.

Target-specific manifests are preserved and must not be overwritten by source AIDE.

