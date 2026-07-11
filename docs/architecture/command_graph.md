# Command Graph

The first Universal Setup command graph is contract-first and dry-run-only. It
exposes the setup authority without performing install, repair, uninstall,
rollback, network, registry, or package-manager mutation.

Native entrypoint:

```c
usk_command_execute_v1(context, request, response)
```

Initial commands:

- `command_graph.inspect`
- `policy.inspect`
- `install_local.plan`
- `package.verify`
- `package.audit`
- `verify.report`
- `uninstall.plan`
- `audit.log`
- `diagnostics.report`

`install_local.plan` and `uninstall.plan` return install-plan contracts with
`dry_run: true`. `audit.log` returns a report contract. `package.verify` and
`package.audit` read a bounded local package root and distinguish integrity,
authenticity, compatibility, completeness, and requested target/linkage match.
Unsigned integrity is reported as a warning, never publisher authenticity.
The compatibility `verify.report` command remains truthfully unavailable.

Package verification reads `manifest/package.v1.toml`,
`manifest/components.v1.json`, `manifest/hashes.sha256`, the declared workspace
lock, and all hashed files. It refuses linked/reparse-crossing or escaping
paths, malformed metadata, and resource-budget violations. It does not install,
repair, uninstall, roll back, elevate, mutate the registry, call a package
manager, or write to the package.

The command graph is not a setup engine yet. It is the ABI and contract proof
that later setup work must pass through before touching installed software
state.
