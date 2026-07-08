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
factorio-launcher   Factorio product binding and app frontends
```

Universal Setup must not contain Factorio, Dominium, Eureka, or AIDE product
semantics. It knows products, components, payloads, install plans,
installed-state records, transactions, platform capabilities, and audit.

## Durable Layout

```text
include/    public `usk` C ABI headers
runtime/    setup kernel implementation, platform adapters, base helpers
apps/       optional setup frontends
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

## Bootstrap Validation

```powershell
python tools\structure_policy_check.py
python -m unittest discover -s tests -v
cmake -S . -B build/native-smoke
cmake --build build/native-smoke
```

The current repository is a canonical bootstrap, not a production installer
implementation yet.
