# Validation Tier Model

AIDE validation uses a portable T0/T1/T2/T3 ladder.

| Tier | Purpose | Default Use |
| --- | --- | --- |
| T0 | Smoke, syntax, policy, architecture, and no-call checks | normal post-task |
| T1 | Impacted tests selected from changed paths | normal post-task |
| T2 | Component or integration suites relevant to larger changes | larger tasks and pre-push review |
| T3 | Full discovery and promotion suite | checkpoint, promotion, and release gates |

Full suites are preserved. They are not deleted, skipped, or hidden to make work appear green. T3 is deliberately not the normal post-task default because long discovery should produce compact telemetry for review instead of forcing every task to babysit raw logs.

Target repositories adopt this model through target-local manifests and evidence. AIDE source policy must not overwrite Eureka, Dominium, or other target validators.

