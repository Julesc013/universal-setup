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

## Branch and release train

Universal Setup uses protected `main` and `dev` branches. `main` is stable
canonical provider source; `dev` is the continuously integrated next train and
must always contain `main`. Bounded `task/*` work starts from an exact `dev`
revision, targets `dev`, passes consumer canaries, and reaches `main` through a
reviewed promotion. Stable consumers retain exact pins reachable from `main`;
canary SHAs never rewrite their tracked locks.

See the [repository branch model](docs/governance/branch_model.md) and its
[machine-readable policy](release/index/branch_policy.v1.toml).

## Bootstrap Validation

```powershell
python tools\workspace_hygiene.py paths
python tools\workspace_hygiene.py doctor --measure
python tools\structure_policy_check.py
python -m unittest discover -s tests -v
$layout = python tools\workspace_hygiene.py paths | ConvertFrom-Json
$build = Join-Path $layout.task_root "native-smoke"
cmake -S . -B $build
cmake --build $build
```

The primary checkout is a clean `dev` control checkout. Task edits and build
output belong in marker-owned secondary worktrees and external task roots; do
not recreate in-checkout build trees or shared `.worktrees` farms. See the
[workspace hygiene policy](docs/governance/workspace_hygiene.md).

## CMake SDK candidate

`USK-CMAKE-SDK-PACKAGE-01` packages the existing implemented USK C ABI as an
exact-version, relocatable CMake SDK. It exports only:

```text
UniversalSetup::Headers
UniversalSetup::CoreStatic
UniversalSetup::CoreShared
```

The installed closure contains the implemented public `usk` headers,
static/shared libraries, public schemas, the USK ABI manifest, licence records,
the generated `share/universal-setup/provider-package-manifest.v1.json`, and the
[SDK guide](cmake/README-SDK.md). Private C++ implementation headers and
unimplemented `usu` declarations are not installed; aspirational archive,
lifecycle, client, daemon, or mutation targets are not exported. Embedded
consumers do not build USK apps or tests unless they opt in.

The package version is `1.0.0`, the existing C ABI remains `1.0`, and the
product-package and setup-recipe contracts remain `fixture-qualified`. SDK
distribution does not authorize package acquisition, live mutation, consumer
adoption, signing, or publication.

The provider-package manifest is generated only after installation from the
exact installed bytes. It binds the source commit/tree/ref, CMake package and C
ABI versions, v1 installed-state and transaction-journal formats, public
headers, schemas, targets, licences, toolchain/profile, and every installed
artifact digest. It is identity evidence, not release or mutation authority.

The repository has an authoritative descriptor-driven command graph, bounded
read-only package verification, and the complete fixture-proven M1 lifecycle.
Package verification separates integrity, authenticity, compatibility,
completeness, and target match. See
[M1 adversarial proof](docs/testing/m1_adversarial_proof.md).

The additive [product-package and recipe contracts](docs/architecture/product_package_contracts.md)
bind local package identity, component closure, topology, preservation,
migration, lifecycle, and installed-state compatibility without adding network
acquisition or live-mutation authority.

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

The public acceptance implementation streams stored and Deflate classic-ZIP
and single-disk ZIP64 entries after full bounded inspection succeeds. Planning
incrementally binds each selected entry's compression method, exact compressed
and uncompressed boundaries, CRC32, and SHA-256 without retaining the complete
payload. Apply reuses the reviewed stable archive handle and stages through a
64 KiB output buffer; Deflate adds one private 64 KiB compressed-input buffer.
It refuses existing install or move targets, stale plans, changed source
identity, unsafe target components, malformed or boundary-inexact Deflate,
insufficient capacity, and state roots without the exact ownership marker.
Repair streams only changed recorded files. Move verifies the new root and
retains the old root. Uninstall refuses all mutation while changed owned or
unknown files require operator review.

`recovery.inspect` and `recovery.plan` are public and read-only. They validate
the journal's transaction, plan, operation, root authorities, transition chain,
digest, and restart-safe staged ownership. `recovery.apply` can consume the
exact reviewed plan to roll back only an unchanged, setup-owned staged closure.
Changed or foreign staging content is retained in full. Visible-target
finalization remains recovery-required when the request lacks the exact
original operation context; inspection alone is never promoted to mutation.

No M2-WU2 command performs networking, credential access, registry or shortcut
mutation, elevation, package-manager integration, vendor installer execution,
product execution, signing, or publication. This is an operator-acceptance
candidate, not a production installer or a human acceptance verdict.

The retained synthetic live proofs are documented in
[`m2_live_acceptance.md`](docs/testing/m2_live_acceptance.md) and
[`m2_interruption_recovery.md`](docs/testing/m2_interruption_recovery.md).

## License

Universal Setup's repository-owned code is licensed under the
[MIT License](LICENSE). Packages that contain the private zlib inflate subset
use the `MIT AND Zlib` expression recorded in `release/license.v1.toml` and
install both licence texts. The exact unmodified upstream subset is bound by
`external/zlib/provenance.v1.toml`. These licence records do not imply signing,
publication, or publisher authenticity; current artifacts remain unsigned and
unpublished.
