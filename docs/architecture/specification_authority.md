# Universal Setup specification adoption record

Date: 2026-09-20

WorkUnit: `USK-WU-001`

Specification: `usk-engineering/0.1.0-draft.1`

## Decision

The repository admits `spec/` as the authoritative home for intended
engineering behaviour, rationale, requirements, decisions, and acceptance
obligations. This adoption does not turn specification prose, proposed
WorkUnits, generated indexes, or context packs into execution authority or
runtime evidence.

Existing authorities remain unchanged:

- `contracts/` owns admitted executable and compatibility contracts;
- implementation remains in `runtime/`, `apps/`, and `include/`;
- repository and AIDE governance own work admission, grants, and status;
- `tests/` and evidence records report what was actually executed;
- `release/` owns actual artifact, qualification, and support claims; and
- `docs/` explains the accepted project state to readers.

The individual concepts and requirements retain the status recorded in their
source files. Admission of the package is not blanket acceptance of every
proposal and does not resolve the eight open decision gates.

## Bound identity

- Repository: `Julesc013/universal-setup`
- Adoption base commit: `0ca648a2c4fa8a37bb78a22639578093aecf6254`
- Adoption base tree: `7f8b11a85ad9a4704fdb891763de00ec467bb314`
- Delivered specification aggregate SHA-256:
  `996d2c313a3f90d5059c68e0ae837165d8aecfa74ee8f826a3a088ec9597d888`
- Repository-adapted specification aggregate SHA-256:
  `425723300e08278acd2b0871d74fbc2114065549d821226d4d46b462aa746762`

The repository-adapted digest differs only because admission added the
repository-required SPDX headers, corrected the Windows-reserved `nul` test
fixture name, preserved the authoritative `spec/build/` section against the
repository's generic build-output ignore rule, and regenerated
`spec/integrity.json`. The specification's normative product requirements were
not changed.

## Reviewed scope

- Added the 158-file `spec/` tree without replacing the root README,
  implementation, contracts, workflows, release state, or AIDE state.
- Added `spec` to the existing top-level structure allowlist without weakening
  any other structure rule.
- Added this authority record under the existing documentation root.
- Preserved all 144 product acceptance designs as `not_run` and all 33
  WorkUnits as inactive proposals.

The approving principal is the repository owner through the explicit adoption
instruction issued on 2026-09-20. Codex performed the integration and
mechanical checks; this is not an independent expert architecture review.

## Verification and limits

The adopted tree passed specification validation, generated-index checking,
integrity checking, all 66 specification-tool self-tests, full JSON Schema
validation of 98 instances, the repository structure check, and all 63
repository Python tests. The schema validation covers proposed schema syntax
and shape, not runtime conformance.

No native lifecycle qualification, privileged mutation, power-loss testing,
native GUI or human accessibility acceptance, AIDE queue activation, signing,
or release publication was performed by this adoption.
