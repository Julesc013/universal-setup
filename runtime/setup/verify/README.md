# Verification

Read-only package verification lives in `usk_package_verify.cpp`.

The bounded verifier checks manifest identity, component roles and sizes,
SHA-256 file integrity, complete hash closure, workspace-lock revision
alignment, and caller-requested target/linkage identity. It reports unsigned
integrity separately from authenticity and never mutates the inspected root.

`package.verify` and `package.audit` use the same authority. Audit returns the
same structured findings rather than a second implementation that could drift.
