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

Canonical M1 commands:

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
`planned_command_unavailable` result. In particular, no M1 apply command has
mutation authority yet.

`install_local.plan` and `uninstall.plan` retain their bootstrap dry-run plan
responses until the contract spine and real planner replace them.
`package.verify` and `package.audit` remain the only commands backed by a real
local package reader. They distinguish integrity, authenticity, compatibility,
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
context destruction. The optional v1 allocator extension lets embedded callers
own graph allocations while callers compiled against the original
`usk_config_v1` prefix remain ABI-compatible. Allocation failure returns a
static fail-closed diagnostic; it never falls back to an incomplete graph.

The registry is internal and closed in M1. There is no dynamic registration or
generic operation escape hatch. Product repositories provide declarative
recipes through later contracts, not executable command handlers.
