# M1 Setup Schema Spine

The authoritative M1 contracts are `recipe`, `source`, `install_plan`,
`operation_plan`, `installed_state`, `ownership_manifest`,
`transaction_journal`, `audit_event`, `verification_report`, `repair_report`,
`move_report`, `uninstall_report`, `recovery_report`, and `refusal`.

All are product-neutral JSON Schema Draft 2020-12 documents. Digests are
lowercase SHA-256 hex over the later canonical serialization profile. Runtime
implementations must not claim one of these schemas unless their payload is
valid against it.

WU3 adds `archive_inspect_request` and `archive_inspection` as read-only command
contracts. Their normalization policy is deliberately
`ascii_case_insensitive_v1`; non-ASCII archive paths are refused until a
portable Unicode-normalization profile has independent adversarial proof.

Package verification and the older policy, ownership, transaction, rollback,
verify-report, audit-log, and setup-manifest files are retained compatibility
contracts. They do not grant lifecycle mutation authority.

M2 adds `live_target_evidence_packet` as the immutable acceptance envelope. It
binds exact repository and contract revisions, source/recipe/target/filesystem
identities, the reviewed plan, actual committed closure, installed-state,
ownership, audit, snapshots, recovery, and automated findings. The operator
verdict is deliberately either pending or a separately supplied human `Pass`,
`Fail`, or `Inconclusive`; automated findings cannot populate that verdict.
