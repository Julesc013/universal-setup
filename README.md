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

The repository now has an authoritative descriptor-driven command graph and
bounded read-only `package.verify` / `package.audit` commands for local
built-package roots. The complete M1 command vocabulary is visible to clients,
but unfinished lifecycle commands are explicitly non-executable. Package
verification separates integrity, authenticity, compatibility, completeness,
and target match. Nothing here grants installation, repair, uninstall,
rollback, elevation, registry, package-manager, or publication authority.

The strict M1 contract spine now defines declarative recipes, stable local
sources, digest-bound plans, installed state, exact ownership, durable journals,
chained audit events, lifecycle reports, and refusals. The old static install
and uninstall previews were removed: plan/apply commands remain unavailable
until the archive inspector and real planner can emit valid bound contracts.

`install_local.inspect` now provides the first real M1 source operation. It
reads one operator-selected classic ZIP through a stable no-follow handle and
returns a deterministic, budgeted entry set. It does not extract, initialize
writable state, inspect a target, or grant any apply authority.

An internal WU4 transaction session now proves exclusive staging, durable
journaling, stable closure verification, same-volume no-replace commit,
fault recovery inspection, and ownership-bounded rollback in disposable native
fixtures. It deliberately remains disconnected from command dispatch, so all
setup lifecycle apply commands are still unavailable.

WU5 adds deterministic no-clobber installed-state and exact-ownership
repositories plus immutable digest-chained audit events. Read-only repository
use does not create state, and a permanent v1 compatibility corpus protects
existing record readers. These repositories are not yet connected to public
lifecycle commands.

WU6 composes those primitives into a real internal lifecycle over disposable
synthetic payloads: install, verify, repair, move with old-root retention,
ownership-safe uninstall, and visible-target recovery. The complete journey is
native-tested, but archive extraction and all public lifecycle apply dispatch
remain unavailable. This is fixture authority, not live product-install
authority.

WU7 adds adversarial, concurrency, scale, sanitizer, and bounded-fuzzer proof.
Unsafe path forms, unsupported Unicode normalization, stale plans, target and
source substitution, conflicting writers, and tampered recovery authority fail
closed. See [M1 adversarial proof](docs/testing/m1_adversarial_proof.md).

The current repository remains a canonical bootstrap, not a production
installer implementation.
