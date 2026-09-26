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

Whole-root `update.apply` makes this requirement mandatory. Its reviewed plan binds the complete old root and candidate archive, but apply returns `replacement_commit_authority_unavailable` before journal, staging, root, state, or audit effects. `ReplacementSession` qualifies only the append-only journal, retained-root exchange, and interruption classifier through an explicitly legacy native fixture lane; it cannot mint strict publication authority.

## Validation and remaining gates

`usk_commit_authority_smoke` covers the preserved original oracle, valid streamed and buffered legacy commits, identical-byte and changed-byte file substitutions, directory substitution, extra files/directories, structural bounds, typed strict refusal before the observation hook, and live/reopened retention including malformed and erased metadata. `usk_zip_restart_smoke commit-authority` covers stored/Deflate public and native strict planning, digest/source binding, exact no-effect snapshots, downgrade refusal and omitted-requirement success. The original RED remains historical evidence; it is not relabeled as a passing host qualification.

Independent source review, clean-source static/shared/combined SDK gates and fresh hosted platform checks bind separate exact candidate receipts. This source document does not assert those gates passed, qualify stronger publication success, close generation/cleanup work or adopt a consumer pin.

## Restricted-service metadata candidate

The internal Windows publisher now takes the selected readers from the exact reviewed native plan, including its archive prefix and source validator. It does not reinspect the ZIP with a second selection policy. The private finalizer binds the transaction, timestamp, source digests and actual visible root identity before writing shared ownership, installed-state and audit records.

`PublisherMetadataSession` provides a scoped record backend for that internal service composition. It checks the accepted SYSTEM-owned, protected SYSTEM/service-SID descriptor on the held volume boundary and existing metadata tree. New directories and files receive the descriptor at creation. Initialization builds the marker and repository layout under a private root before parent-bound no-replace root publication. Records are written and flushed under `pending/`, then renamed without replacement through their retained destination parent. Unfinished pending records are retained outside installed-state and audit enumeration. Backend failures do not fall back to ordinary path writes.

This remains an implementation candidate. Focused native builds, record-backend refusal tests and the synthetic readback-oracle regressions ran locally. Exact-head hosted run `36230204335` passed at commit `b3da3b934dec6ea17e3931f8dd16139bc9f261ea`, tree `b844221446ebba6b9bba596f59f03c34123179df`, on Windows `10.0.20348.0`. Its selected-metadata receipt reports successful restricted-service publication, independent SYSTEM readback of payload and ownership/installed/audit records, protected SYSTEM/service-SID descriptors, and confirmed service/observer/VHD cleanup. The retained receipt SHA-256 is `b15545de8e7a6be25a3ebfd650a4caddd2178f2aa06a9a58979695488df7fe5f`. Earlier unsuccessful local VM transport attempts and older successful VM receipts remain bound to their original source and environment. This observation does not establish current-binary crash-window or hostile-rights qualification, an ordinary production adapter, leases or OD-001 closure.

The existing hosted Windows disposable-VHD harness also has a selected-metadata execution case. It observes the actual VM registry identity, creates an own-process restricted service, uses public authoring and selection tools to make a two-file stored source with a nonempty prefix and multi-buffer payloads, reviews the native plan, and independently reads protected payload and metadata as SYSTEM. The pure readback oracle accepts the observed drive alias and refuses a substituted alias. The successful hosted receipt above establishes this execution case; it does not qualify the general production profile. The existing prepublication and hostile-rights probe remains required and unchanged.

## Shared candidate apply execution

The restricted-service implementation is extracted into the private lifecycle
engine. Its admitted service context invokes the normal `install_local.apply`
parser and immediate native plan validation, then the concrete protected engine
consumes those source-bound readers. Caller transaction ID and timestamp are
persisted in the existing reviewed snapshot and installed state; they are not
replaced by laboratory-generated operation identities. The context has no public
constructor, callback registration, JSON activation or SDK capability token.
The lab host provisions its disposable volume descriptor before execution;
ordinary apply does not replace a volume ACL. Existing durable prepared/visible
records, handle-relative no-replace publication, exact closure checks and protected
metadata finalization remain shared with recovery.

The hosted scenario sends the identical request to an ordinary machine process
and to the admitted restricted service. It requires refusal before ordinary
mutation, a verified installed result inside the service, and independent SYSTEM
readback of caller identities and protected records. These are candidate tests;
this source change does not assert they have executed. General SDK/client
transport, consumer read policy, per-install leases, complete hostile/crash
qualification and production enablement remain incomplete.
