# Boundary

Universal Setup owns:

- install
- verify
- repair
- uninstall
- stage / commit / rollback
- installed-state manifests
- setup audit
- setup package-manager handoff

Universal Setup must not own product-specific launcher orchestration or
Factorio-specific semantics. Launchers consume installed-state records; they do
not reimplement setup mutation.

Public ABI namespaces:

- `usk/` is the setup kernel ABI for manifests, plans, transactions, state,
  verify, and audit.
- `usu/` is the setup utility/execution/platform ABI for callbacks, execution
  adapters, platform capability reports, and host-facing reports.
