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

This library is not connected to public command dispatch. It does not grant
install, repair, move, uninstall, or recovery apply authority. Cross-volume
copy/verify/commit and durable recovery execution remain later work.
