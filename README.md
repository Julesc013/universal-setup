# Universal Setup

Universal Setup is the product-agnostic setup authority for install, verify,
repair, uninstall, rollback, installed-state manifests, and setup audit.

It is not a GUI wizard, store, DRM system, background updater, launcher
orchestrator, or product-specific installer. Product repositories supply
identity, payloads, policy, recipes, branding, and user-facing text. Universal
Setup supplies deterministic setup transaction machinery and thin platform
adapters.

## Ownership

```text
universal-setup     install / repair / uninstall / rollback authority
universal-launcher  cross-product orchestration and launch plans
factorio-launcher   FacMan product binding and app frontends
```

Universal Setup must not contain Factorio, Dominium, Eureka, or AIDE product
semantics. It knows products, components, payloads, install plans,
installed-state records, transactions, platform capabilities, and audit.

## Proof Role

```text
Factorio proves the universal launcher through FacMan.
Dominium proves the universal setup.
FacMan ships as the first serious Factorio product binding.
```

Universal Setup should learn from Dominium's real setup requirements without
becoming Dominium-specific. FacMan may call Universal Setup for managed
Factorio installs later, but FacMan is not the proof project for setup
mutation.

Permanent rule:

```text
Universal setup mutates installed software state.
Universal launcher orchestrates runnable product state.
Product bindings interpret product-specific facts.
Frontends present commands and reports.
Contracts preserve compatibility.
Validators prevent regression.
```

## Durable Layout

```text
include/    public `usk` kernel and `usu` utility/platform C ABI headers
runtime/    setup kernel implementation, command service, diagnostics,
            platform adapters, base helpers
apps/       optional CLI, TUI, daemon, and reference app shells
contracts/  ABI, command, schema, result, diagnostic, refusal, policy contracts
content/    universal setup templates and policy
release/    package manifests and release profiles
docs/       human documentation
tests/      proof, fixtures, and golden outputs
tools/      validators and repo automation
cmake/      native build policy
archive/    retained planning/prototype material
```

Retired roots are forbidden:

```text
source/
src/
data/
schemas/
packaging/
factorio/
launcher/
```

The app grammar is:

```text
apps/
  cli/
  tui/
  daemon/
  gui/
```

Universal Setup does not own product GUI matrices. Products can ship GUI
frontends over setup command contracts, but setup mutation, ownership,
transaction, rollback, state, and audit logic stay in this repo's runtime and
contracts.

## Bootstrap Validation

```powershell
python tools\structure_policy_check.py
python -m unittest discover -s tests -v
cmake -S . -B build/native-smoke
cmake --build build/native-smoke
```

The repository now includes bounded read-only `package.verify` and
`package.audit` commands for local built-package roots. They separate integrity,
authenticity, compatibility, completeness, and target match. They do not grant
installation, repair, uninstall, rollback, elevation, registry, package-manager,
or publication authority.

The current repository remains a canonical bootstrap, not a production
installer implementation.
