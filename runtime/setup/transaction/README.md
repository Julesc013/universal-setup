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

Restart-safe staged rollback is not yet public because the journal does not yet
persist enough per-file staging ownership to delete post-crash content safely.
`recovery.apply` therefore remains unavailable until M2-WU5. Cross-volume
copy/verify/commit also remains later work.
