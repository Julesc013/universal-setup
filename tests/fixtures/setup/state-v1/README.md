# Setup State v1 Compatibility Corpus

These canonical one-line records are a permanent reader-compatibility corpus
for `usk.ownership_manifest.v1`, `usk.installed_state.v1`, and
`usk.audit_event.v1`. Their embedded digests bind the canonical payloads.

Tests copy them into disposable repository layouts and require the current
native readers to accept and cross-bind them without rewriting the fixtures.
