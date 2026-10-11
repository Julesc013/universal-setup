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

The retained `transaction.v1` and `transaction_plan.v1` operation lists remain
closed to `install_local`, `verify`, `repair`, `uninstall`, `adopt`, and `audit`.
Their additive v2 contracts also name `update`, `move`, and `recovery`. The
reference adapter in `tests/transaction_compat_reference.py` upgrades a
schema-validated v1 document by changing only its schema tag and preserves all
existing fields. Downgrading a v2 document with a new operation is refused;
the adapter never maps it to a different v1 operation. The fixtures in
`tests/fixtures/setup/transaction-compat` exercise both directions. These
adapter is a test/reference implementation and requires schema validation by
its caller. The compatibility schemas do not activate a transaction executor:
actual managed
lifecycle operations continue to use their reviewed plan and journal contracts.

`command_graph.inspect_v2` retains the v1 command response envelope and
projects an `usk.command_graph.v2` payload directly from the dispatch table.
Each descriptor has a canonical operation category, or `null` for evidence
commands that are not lifecycle operations. Its `legacy_v1_operations` array
records the old transaction vocabulary; it does not imply that every legacy
operation has a current executable command. `command_graph.inspect` retains
the v1 payload shape for existing readers. A retained static command that
always returns an unavailable/error response, such as `verify.report`, has
`executable: false` even though its compatibility route still exists.
The native smoke test checks descriptor mapping. Given a built
`usk_command_graph_smoke` executable, `tests/native/validate_lifecycle_contract_schemas.py`
uses Draft 2020-12 validation against the actual emitted v2 graph and the
transaction compatibility fixtures.

M2 adds `live_target_evidence_packet` as the immutable acceptance envelope. It
binds exact repository and contract revisions, source/recipe/target/filesystem
identities, the reviewed plan, actual committed closure, installed-state,
ownership, audit, snapshots, recovery, and automated findings. The operator
verdict is deliberately either pending or a separately supplied human `Pass`,
`Fail`, or `Inconclusive`; automated findings cannot populate that verdict.
