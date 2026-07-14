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

The repository has an authoritative descriptor-driven command graph, bounded
read-only package verification, and the complete fixture-proven M1 lifecycle.
Package verification separates integrity, authenticity, compatibility,
completeness, and target match. See
[M1 adversarial proof](docs/testing/m1_adversarial_proof.md).

M2-WU1 adds a fail-closed live-target policy and platform inspection. M2-WU2
connects the proven lifecycle to public install, inspect, verify, repair, move,
and uninstall plan/apply commands for a deliberately narrow local acceptance
lane. Planning remains read-only. Every apply rebuilds its nested plan request,
reopens and rehashes source material where applicable, rechecks target and
setup-state authority, and compares the reviewed plan ID and digest before the
first write.

Public lifecycle contexts must use the complete `usk_config_v1` and supply:

- an explicitly absolute setup-owned state root;
- an explicitly absolute authorized acceptance root;
- `operator_acceptance_candidate` or, only after a separate human Pass,
  `accepted_live_portable` target-policy activation.

An unconfigured or legacy-prefix context remains valid for ABI compatibility
but public lifecycle requests fail closed with
`live_target_acceptance_required`. The candidate activation permits mutation
only for `operator_acceptance` targets below the configured acceptance root.
It does not authorize ordinary managed-portable targets.

The public acceptance implementation currently materializes only stored ZIP
entries after the full classic-ZIP inspection succeeds. It refuses existing
install or move targets, stale plans, changed source identity, unsafe target
components, insufficient capacity, and state roots without the exact ownership
marker. Repair touches only changed recorded files. Move verifies the new root
and retains the old root. Uninstall refuses all mutation while changed owned or
unknown files require operator review.

`recovery.inspect` and `recovery.plan` are public and read-only. They validate
the journal's transaction, plan, operation, root authorities, transition chain,
and digest. `recovery.apply` remains explicitly unavailable until M2-WU5 adds
restart-safe staged-file ownership reconstruction; this boundary prevents an
inspection result from being overstated as safe recovery mutation.

No M2-WU2 command performs networking, credential access, registry or shortcut
mutation, elevation, package-manager integration, vendor installer execution,
product execution, signing, or publication. This is an operator-acceptance
candidate, not a production installer or a human acceptance verdict.

## License

Universal Setup is licensed under the [MIT License](LICENSE). The canonical
machine-readable package identity is `release/license.v1.toml`. That license
choice does not imply signing, publication, or publisher authenticity; current
artifacts remain unsigned and unpublished.
