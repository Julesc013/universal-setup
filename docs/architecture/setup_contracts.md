# Setup Contracts

M1-WU2 freezes the product-neutral contract spine before filesystem mutation is
implemented. Every authoritative document is strict JSON Schema Draft 2020-12,
has a stable `usk.*.v1` identity, rejects unknown top-level properties, and is
serialized deterministically before its digest is computed.

The authoritative M1 v1 spine is:

- `recipe`: declarative product/source/layout requirements with no executable hooks;
- `source`: stable local-archive identity and inspection budgets;
- `install_plan`: digest-bound local portable install effects;
- `operation_plan`: repair, move, uninstall, or recovery effects;
- `installed_state`: canonical managed-install identity;
- `ownership_manifest`: exact owned files, directories, sizes, and hashes;
- `transaction_journal`: durable lifecycle transitions and recovery choices;
- `audit_event`: digest-chained operation evidence;
- `verification_report`: owned-state and unknown-path results;
- `repair_report`: before/after verification and retained foreign content;
- `move_report`: new-root verification and deferred old-root removal;
- `uninstall_report`: deleted owned state and retained changed/unknown state;
- `recovery_report`: inspected journal, allowed action, effects, and result;
- `refusal`: explicit plan drift, unsafe input, policy, and recovery refusal.

Retained bootstrap contracts (`policy`, `ownership`, `transaction`, `rollback`,
`verify_report`, `audit_log`, and package verification request/report) remain
versioned compatibility surfaces. New lifecycle implementations use the
authoritative M1 spine.

Every apply consumes an immutable plan identity. Source, recipe, target,
installed state, ownership manifest, policy, and provider revisions are
revalidated as applicable immediately before mutation. Drift invalidates the
plan; it is never silently replanned during apply.

The recipe is data only. It may declare local archive format, strip-prefix
policy, paths, components, entrypoints, structural checks, and non-executing
capability probes. It cannot carry shell, PowerShell, batch, executable hook,
network URL, credential, registry, or installer behavior.

Unknown and user-created files are observations, not setup property. Repair,
move, and uninstall contracts therefore record retained unknown paths. The
source archive is never setup-owned and uninstall reports must state
`source_archive_deleted: false`.
