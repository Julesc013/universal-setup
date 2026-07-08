# Roadmap

Universal Setup should be proven by Dominium before it grows into a broad
abstract platform.

## USETUP-CANON-01

- Keep the sibling root grammar enforced.
- Keep `usk` and `usu` public ABI families distinct.
- Keep setup product-neutral and free of Factorio, Dominium, Eureka, and AIDE
  semantics.

## USETUP-MIN-01

- Manifest parser.
- Resolver.
- Install/repair/uninstall plan model.
- Fetch/cache handoff.
- Verify report.
- Transaction stage/commit.
- Rollback journal.
- Installed-state write.
- Audit log.

## DOMINIUM-PROOF-01

- Use Dominium setup requirements to prove rollback, repair, ownership,
  determinism, packaging, and audit contracts.
- Keep Dominium-specific policy outside Universal Setup.

## SETUP-HANDOFF-01

- Expose setup operations to Universal Launcher through installed-state and
  setup request/result contracts.
- Do not let launchers reimplement setup mutation.
