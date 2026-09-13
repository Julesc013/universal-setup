# Staged child commit authority

The September 7 disposable-fixture regression demonstrated a new, actual publication defect: after `mark_verified()`, a staged payload was moved outside staging and a different file with identical bytes was put at its old name. Legacy `commit()` published the replacement and reported `completed`, while its stream journal still recorded the original native identity. The original source, executable, journal bytes, identities and exit 151 are preserved in the external WorkUnit evidence. Earlier cleanup and replay tests did not exercise this commit boundary.

## Bounded observation and retained refusal

Verification now observes the complete recorded file and ancestor-directory closure. Commit preparation repeats that bounded observation and compares all observed native identities with the verified observation. Streamed files must also match their original output-handle identity. Missing, extra, linked, changed-byte or already-substituted children and directories refuse publication. The walker admits at most 200,000 files plus directories and 128 path components; it stops immediately at unknown entries and hashes known files with the existing bounded-buffer stable reader.

Before commit preparation examines children, it durably latches `commit_cleanup_policy: retain_only` and withholds serialized `staging_identity`. A refusal leaves the transaction `recovery_required` and retains every child. Live and reopened automatic rollback refuse. Older readers that ignore the new marker still encounter the deliberately null rollback identity. Successful legacy publication and visible-target finalization remain available under their existing limits. Failed commit preparation does not create deletion authority.

These are observations, not atomic ownership. Closed handles and numeric IDs can be reused. Another writer can substitute a child or add a descendant after the final observation, including through the deterministic `after_commit_preparation_observation` fault point. No claim of staged-child authority through the actual rename is made for the legacy path. Staging creation, cleanup, generation/stale-owner leases, ambiguous target completion and consumer adoption remain separate open qualification work.

## Explicit stronger requirement

`install_local.plan` accepts the optional member:

```json
{"required_commit_authority":"staged_child_bound_v1"}
```

Omission preserves legacy request shape, plan digest and valid successful behavior. An explicit requirement is included in the native plan digest, source context and transaction journal. Apply takes it only from the original `plan_request`; removing it invalidates the reviewed digest. Unknown values and extra capability flags are not accepted. The C ABI remains 1.0 with unchanged structs and exports; internal C++ aggregate fields and the final plan argument are defaulted.

A strict plan reports `commit_authority_available: false`. Public apply refuses with `commit_authority_unavailable` before setup initialization, audit creation or transaction effects. Native lifecycle apply performs its own pre-effect check. A directly staged native transaction with the strict requirement durably retains and throws `CommitAuthorityUnavailable`; it cannot fall back to observed legacy commit, rollback, replay or finalization. Reopening requires the same requirement and cannot mint a live capability from journal observations.

There is no qualified success publisher for this requirement on current hosts. Caller booleans, caller ACL assertions, ordinary same-user directory permissions, held child handles, matching bytes, or journal IDs cannot enable it. A future implementation needs independently enforced namespace protection from original creation through publication, including every descendant addition and the destination parent, with a proven object-bound no-replace publication protocol. The controlled Windows experiment retained evidence that open descendants blocked root rename, closing them enabled the control rename, and adding a new child remained possible even with existing handles held. No equivalent success protocol has been qualified on Linux or macOS.

## Validation and remaining gates

`usk_commit_authority_smoke` covers the preserved original oracle, valid streamed and buffered legacy commits, identical-byte and changed-byte file substitutions, directory substitution, extra files/directories, structural bounds, typed strict refusal before the observation hook, and live/reopened retention including malformed and erased metadata. `usk_zip_restart_smoke commit-authority` covers stored/Deflate public and native strict planning, digest/source binding, exact no-effect snapshots, downgrade refusal and omitted-requirement success. The original RED remains historical evidence; it is not relabeled as a passing host qualification.

Independent source review, clean-source static/shared/combined SDK gates and fresh hosted platform checks bind separate exact candidate receipts. This source document does not assert those gates passed, qualify stronger publication success, close generation/cleanup work or adopt a consumer pin.
