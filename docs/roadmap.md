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

## M1-WU3 — Stable Source and Archive Inspection

- Added stable no-follow source handles with handle/path revalidation and
  singly linked regular-file policy.
- Added shared known-answer-tested SHA-256 source identity.
- Implemented bounded classic ZIP local/central structure inspection.
- Rejects unsafe paths, case collisions, reserved names, unsupported Unicode,
  links/devices/reparse attributes, encryption, ZIP64, ambiguous bytes, and
  count/size/depth/ratio/elapsed budget violations.
- Emits a deterministic normalized entry-set digest without extraction or
  writable state initialization.

## M1-WU4 — Staging and Transaction Session

- Added an internal digest-bound transaction session for disposable and
  synthetic proof roots; public apply commands remain unavailable.
- Persists the complete state sequence through atomically published journals
  before each related visible effect.
- Creates exclusive owned staging, writes no-clobber files, verifies stable
  hashes, and commits with a same-volume no-replace directory rename.
- Detects target, staging, and journal-directory substitution and fails closed
  where the platform lacks a proven no-replace primitive.
- Restricts rollback to recorded files and empty derived directories, retaining
  unexpected content as recovery-required state.
- Exercises every state transition and the rename/journal crash window through
  native fault-injection tests on Windows and Linux.

## M1-WU5 — Installed State, Ownership, and Audit Repositories

- Added strict canonical JSON parsing and deterministic serialization with
  bounded depth, size, value count, and string size.
- Added explicit setup-state and audit layout initialization; read-only
  construction and reads never initialize writable state.
- Added durable no-clobber ownership and installed-state records with exact
  manifest digest, install identity, target-root, and parent-closure checks.
- Added append-only audit chains with immutable sequence files, previous-event
  digests, complete-chain validation, and concurrent-writer no-clobber.
- Added a checked-in v1 compatibility corpus and cross-platform native tests for
  deterministic bytes, stable reads, tamper refusal, and ownership binding.

## M1-WU6 — Fixture-backed Portable Lifecycle

- Added internal, digest-bound plan/apply types for local portable install,
  repair, move, uninstall, and visible-target recovery.
- Install revalidates its reviewed payload and roots, commits through an atomic
  no-replace rename, verifies the visible target, and only then publishes exact
  ownership, immutable installed state, and chained audit evidence.
- Verification distinguishes missing, modified, wrong-type, unreadable, and
  unknown paths without changing the installation.
- Repair stages only affected owned files, retains per-file backups until the
  repaired closure verifies, and preserves unknown content.
- Move copies and verifies the complete tree at the new destination, refreshes
  ownership/state after verification, and retains the old root pending later
  acceptance.
- Uninstall removes only hash-matching recorded files and empty recorded
  directories; changed and foreign content produces `uninstall_blocked` and is
  retained for a later reviewed operation.
- Recovery can reopen only a visible-target finalization journal, validate its
  chain and plan identity, finish missing authority records idempotently, and
  advance the original journal to `completed`.
- The synthetic native journey exercises install, verify, drift, repair, move,
  blocked uninstall, clean uninstall, and interruption recovery.

## M1-WU7 — Adversarial and Scale Proof

- Added plan-time Windows-reserved-name, case collision, unsupported Unicode,
  overlong path, timestamp, and current-state monotonicity refusal.
- Bound recovery to the exact journal root authority in addition to plan and
  transition-chain identity.
- Added concurrent target and audit writer proof, post-plan source/foreign
  drift, target substitution, bounded nested scale, and operational fault
  injection.
- Hardened canonical JSON against invalid and overlong UTF-8 encodings.
- Added Linux ASan/UBSan CI and a bounded Clang libFuzzer canonical JSON target.
- Kept every mutation inside disposable native fixture roots.

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
