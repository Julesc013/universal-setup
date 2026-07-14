# Module Graph

```text
include/usk
  -> runtime/setup/kernel
  -> runtime/setup/manifest
  -> runtime/setup/resolver
  -> runtime/setup/plan
  -> runtime/setup/fetch
  -> runtime/setup/verify
  -> runtime/setup/transaction
  -> runtime/setup/state
  -> runtime/setup/audit
  -> runtime/setup/evidence

runtime/setup/transaction
  -> runtime/setup/rollback
  -> runtime/setup/ownership

include/usu
  -> runtime/command
  -> runtime/diagnostics
  -> runtime/platform
```

The graph is intentionally product-neutral. Product repositories supply
manifests and policy; Universal Setup supplies deterministic mutation,
rollback, installed-state, audit behavior, and immutable acceptance evidence.
