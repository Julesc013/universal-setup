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
- `verify.report`
- `uninstall.plan`
- `audit.log`
- `diagnostics.report`

`install_local.plan` and `uninstall.plan` return install-plan contracts with
`dry_run: true`. `audit.log` returns a report contract. `verify.report`
currently returns `verification_not_implemented`; it must not report pass until
it receives and checks a package path, manifest identity, and hashes. The
minimal diagnostics report explicitly marks mutation execution as not
implemented.

The command graph is not a setup engine yet. It is the ABI and contract proof
that later setup work must pass through before touching installed software
state.
