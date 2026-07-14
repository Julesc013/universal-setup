# Directory Structure

```text
universal-setup/
  include/    public `usk` kernel and `usu` utility/platform C ABI headers
  runtime/    setup kernel, command service, diagnostics, platform adapters,
              base helpers
  apps/       optional CLI, TUI, daemon, and reference app shells
  contracts/  ABI, command, schema, result, diagnostic, refusal, policy
  content/    universal setup templates and policy
  release/    package manifests and release profiles
  docs/       human documentation
  tests/      proof, fixtures, and golden outputs
  tools/      validators and repo automation
  cmake/      native build policy
  archive/    retained planning/prototype material
```

`source/` and `src/` are retired. Do not create implementation bucket
directories. Implementation belongs under `runtime/` or app entrypoint roots.

Universal Setup must not contain product-specific behavior. In particular, it
must not contain Factorio discovery, mods, saves, servers, Mod Portal behavior,
launcher profiles, or launch-plan semantics.

## App Shells

```text
apps/
  cli/
  tui/
  daemon/
  gui/
```

Universal Setup keeps GUI ownership to product-neutral reference policy.
Concrete product GUI stacks live in product repos and call setup command
contracts without owning mutation logic.

## Setup Runtime Modules

```text
runtime/setup/
  kernel/
  manifest/
  resolver/
  plan/
  fetch/
  verify/
  transaction/
  rollback/
  state/
  ownership/
  policy/
  audit/
  evidence/
  package/
```

Setup is transaction-first: manifests resolve into plans, plans fetch and stage
payloads, verification gates commit, rollback/state/audit preserve repair
truth, and evidence records bind acceptance observations without granting
additional setup authority.
