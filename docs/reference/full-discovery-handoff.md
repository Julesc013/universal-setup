# Full-Discovery Handoff

Full discovery belongs to T3 and promotion lanes. AIDE Lite can generate a handoff with status `WAITING_FOR_EXTERNAL_FULL_DISCOVERY`, the command an external runner or operator should execute, expected compact summary path, raw-log artifact paths, stale-summary rules, and resume instructions.

The handoff command is no-run and report-only. It must not execute full suites, mutate target repositories, install CI, call providers, call models, call GitHub APIs, or publish release artifacts.

