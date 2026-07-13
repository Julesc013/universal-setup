# M1 Setup Schema Spine

The authoritative M1 contracts are `recipe`, `source`, `install_plan`,
`operation_plan`, `installed_state`, `ownership_manifest`,
`transaction_journal`, `audit_event`, `verification_report`, `repair_report`,
`move_report`, `uninstall_report`, `recovery_report`, and `refusal`.

All are product-neutral JSON Schema Draft 2020-12 documents. Digests are
lowercase SHA-256 hex over the later canonical serialization profile. Runtime
implementations must not claim one of these schemas unless their payload is
valid against it.

Package verification and the older policy, ownership, transaction, rollback,
verify-report, audit-log, and setup-manifest files are retained compatibility
contracts. They do not grant lifecycle mutation authority.
