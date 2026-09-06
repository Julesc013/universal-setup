# Transaction

The WU4 transaction session is an internal, fixture-backed mutation primitive.
It consumes a digest-bound transaction specification, validates disjoint
existing root authorities, creates one exclusive setup-owned staging root,
writes staged files without clobbering, verifies their stable hash closure,
and performs a same-volume directory commit with an operating-system
no-replace primitive.

Every state transition is atomically journaled before the related visible
effect. Recovery inspection distinguishes a retained stage, a visible target,
and the crash window after rename but before the committed journal record.
Rollback removes only recorded staged files and empty derived directories;
unexpected content is retained and leaves the transaction recovery-required.

M2-WU2 connects this library to public install, repair, move, and uninstall
handlers only after target-policy acceptance and immediate reviewed-plan
revalidation. Recovery inspection also validates the exact transaction, plan,
operation, four root authorities, transition chain, and journal digest.

M2-WU5 added legacy non-streaming staged rollback using persisted directory
identity and path/size/hash closure. Its pathname cleanup does not establish
atomic object ownership across substitution races. Streamed transactions
therefore retain a durable refusal latch and withhold serialized rollback
identity; live and reopened rollback cannot regain deletion authority.

The entry-journal slice records intent/writing/complete observations and checks
completion identity captured on the original output handle. Explicit private
source replay uses a new transaction ID and exact prior journal snapshot,
leaving every old staging object retained. Its lineage and retain-only policy
are durable in the first new journal before staging creation. Prior committing
history always refuses replay, including target disappearance after a commit
window. See the [streaming contract](../streaming/README.md#explicit-entry-replay)
for source binding, scope and process-boundary proof.

Visible-target finalization still requires the exact original operation
context. Automatic leases, retained-child cleanup and cross-volume
copy/verify/commit remain separate work.

The optional stream `source_context` is a bounded canonical versioned document
whose SHA256 must equal `source_digest`. Lifecycle ZIP replay uses it to bind
archive, entry-set, original plan/policy and observed native setup/root identities.
The full expected journal snapshot binds these observations before replay. Older
journals without this context remain readable, but cannot support the new public
ZIP replay admission. Readers that reject the added optional metadata retain
state; no fallback grants rollback authority. These digests detect corruption and
bind an explicitly reviewed snapshot; they are not authentication credentials or
proof of a live generation lease.
