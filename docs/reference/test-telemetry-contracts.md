# Test Telemetry Contracts

AIDE compact test summaries record repo identity, commit, branch, dirty state, command, tier, timing, exit code, status, totals, failure families, artifact paths, warnings, stale checks, and generator identity.

Raw logs remain external artifacts. Compact summaries must not embed full stdout, stderr, raw logs, provider credentials, or secret-like values. AI review should use summaries, failure families, deltas, and short selected traceback excerpts.

Timeouts, stale summaries, and failure families must be explicit. A stale summary cannot satisfy promotion evidence.

