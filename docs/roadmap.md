# Roadmap

Universal Setup should be proven by Dominium before it grows into a broad
abstract platform.

## USETUP-CANON-01

- Keep the sibling root grammar enforced.
- Keep `usk` and `usu` public ABI families distinct.
- Keep setup product-neutral and free of Factorio, Dominium, Eureka, and AIDE
  semantics.

## USETUP-CONTRACT-01

- Define install plan, installed-state, verify report, audit log,
  transaction, rollback, ownership, refusal, and policy contracts.
- Keep the first policy local-only: no network, registry, package-manager, GUI,
  or product-specific installer mutation.
- Make validators and tests preserve the contract spine before setup commands
  begin mutating state.

## USETUP-MIN-01

- Native command graph over the setup contracts.
- Manifest parser.
- Resolver.
- Install/repair/uninstall plan model.
- Fetch/cache handoff.
- Verify report.
- Transaction stage/commit.
- Rollback journal.
- Installed-state write.
- Audit log.

## M1-WU1 — Authoritative Command Graph

- Implemented a single descriptor registry for dispatch and introspection.
- Declared the complete M1 inspect/plan/apply vocabulary without enabling
  unfinished mutation commands.
- Preserved the bootstrap command ABI and original `usk_config_v1` prefix.
- Added deterministic bounded graph projection, allocator failure handling,
  response-lifetime proof, and exact descriptor coverage.
- Kept dynamic registration and generic operation handlers out of scope.

## M1-WU2 — Setup Contract Spine

- Added strict v1 recipe, source, install/operation plan, installed-state,
  ownership-manifest, transaction-journal, audit-event, lifecycle-report, and
  refusal schemas.
- Bound plans to revalidated source, recipe, target, state, ownership, policy,
  and provider identities.
- Made retained unknown/user content and deferred old-root removal explicit.
- Expanded local-only policy to forbid elevation, installer execution, and
  credential access.
- Retired invalid static install/uninstall previews until a real planner lands.

## USETUP-PACKAGE-VERIFY-AUDIT-01

- Implemented read-only `package.verify` and `package.audit` over bounded local
  package roots.
- Validates built-package identity, component metadata, SHA-256 closure,
  workspace-lock revisions, and caller-requested target/linkage identity.
- Reports unsigned integrity without claiming publisher authenticity.
- Does not perform setup mutation or integrate a product frontend yet.

## DOMINIUM-PROOF-01

- Use Dominium setup requirements to prove rollback, repair, ownership,
  determinism, packaging, and audit contracts.
- Keep Dominium-specific policy outside Universal Setup.

## SETUP-HANDOFF-01

- Expose setup operations to Universal Launcher through installed-state and
  setup request/result contracts.
- Do not let launchers reimplement setup mutation.
