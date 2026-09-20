# Lifecycle

[Bundle index](../index.md)

- [Installation leases, revisions and stale-worker fencing](concurrency.md) — `USK-S-LEASE`. Prevent parallel installers and recovered workers from committing incompatible transitions.
- [Generations, retention and garbage collection](generations.md) — `USK-S-GEN`. Maintain immutable payload generations with explicit activation and safe reclamation.
- [Journals, recovery and independent maintenance](journal-recovery.md) — `USK-S-REC`. Recover exact operations without turning inspection into mutation or losing uncertainty.
- [State and application-data migration](migrations.md) — `USK-S-MIG`. Version readers, writers and transformation edges without conflating payload and user-data rollback.
- [Lifecycle operation semantics and idempotence](operations.md) — `USK-S-OPS`. Define every install and maintenance verb with distinct preconditions, effects and recovery.
- [Protected staging and publication authority](publication.md) — `USK-S-PUB`. Prevent staged-object substitution across the verification-to-publication interval.
- [Operation and transaction state machines](state-machine.md) — `USK-S-TXN`. Define durable boundaries, partial completion and truthful outcomes before implementing effectful code.
