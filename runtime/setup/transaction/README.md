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

M2-WU5 adds restart-safe staged rollback. The journal persists the staging-root
identity and exact path, size, and digest closure after each durable staged
write. Recovery reopens that closure only when it is still exact, preflights the
whole tree before deletion, and retains every byte when foreign or changed
content is present. Public `recovery.apply` consumes the exact reviewed recovery
plan and can apply this bounded rollback. Visible-target finalization still
refuses without the exact original operation context. Cross-volume
copy/verify/commit also remains later work.
