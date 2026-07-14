# Command Graph

Universal Setup's command graph is descriptor-authoritative. One built-in
descriptor table drives both command lookup and `command_graph.inspect`; a
command cannot be advertised by introspection without also having an exact
dispatch entry. Graph JSON is projected deterministically on request under a
64 KiB allocation budget rather than being maintained as a second literal
command list.

Native entrypoint:

```c
usk_command_execute_v1(context, request, response)
```

Canonical setup commands:

- `command_graph.inspect`
- `policy.inspect`
- `package.verify`
- `package.audit`
- `install_local.inspect`
- `install_local.plan`
- `install_local.apply`
- `installed.inspect`
- `installed.verify`
- `repair.plan`
- `repair.apply`
- `move.plan`
- `move.apply`
- `uninstall.plan`
- `uninstall.apply`
- `recovery.inspect`
- `recovery.plan`
- `live_evidence.capture`
- `live_evidence.verdict.record`
- `recovery.apply`
- `audit.list`
- `audit.inspect`
- `audit.export`

Compatibility commands retained during contract migration:

- `verify.report`
- `audit.log`
- `diagnostics.report`

Every descriptor binds the request and response schemas, effects, dry-run
behavior, availability, owner, binding, and mutation classification to its
handler. `available` commands may execute their current bounded behavior;
`compatibility` commands preserve the bootstrap ABI; `planned` commands are
introspectable but have `executable: false` and return a structured
`planned_command_unavailable` result.

M2-WU2 availability is deliberately split:

- available read-only: package verify/audit, archive inspect, all lifecycle
  plan commands, installed inspect/verify, recovery inspect/plan;
- available mutation behind exact context policy: install, repair, move,
  uninstall apply, and exact staged-closure recovery rollback;
- planned and non-executable: audit list/inspect/export. Visible-target recovery
  finalization remains unavailable without the original operation context.

Public mutation additionally requires an exact reviewed plan, `APPLY`
confirmation, immediate input revalidation, and an authorized target class.
`operator_acceptance_candidate` cannot mutate `managed_portable` targets.

`install_local.inspect` is the first real M1 setup command. It reads one
operator-supplied classic ZIP through a stable no-follow handle and emits a
bounded deterministic `usk.archive_inspection.v1` result. It performs no
extraction or target access.

The old static install and uninstall preview payloads were retired when the M1
contract spine landed. M2-WU2 now produces schema-shaped digest-bound lifecycle
plans from stable sources, target evidence, ownership state, and configured
policy. `package.verify` and `package.audit` remain the built-package readers.
They distinguish integrity, authenticity, compatibility,
completeness, and requested target/linkage match. Unsigned integrity is
reported as a warning, never publisher authenticity. The compatibility
`verify.report` command remains truthfully unavailable.

Package verification reads `manifest/package.v1.toml`,
`manifest/components.v1.json`, `manifest/hashes.sha256`, the declared workspace
lock, and all hashed files. It refuses linked/reparse-crossing or escaping
paths, malformed metadata, and resource-budget violations. It does not install,
repair, uninstall, roll back, elevate, mutate the registry, call a package
manager, or write to the package.

Response views are borrowed until the next command on the same context or
context destruction. `usk_config_v1` preserves its original prefix and M1
allocator layout, then adds the optional setup-state root, acceptance root, and
target-policy activation used by M2 public lifecycle commands. Allocation
failure returns a fail-closed diagnostic; it never falls back to incomplete
configuration or an incomplete graph.

The registry remains internal and closed. There is no dynamic registration or
generic operation escape hatch. Product repositories provide declarative
recipes through later contracts, not executable command handlers.
