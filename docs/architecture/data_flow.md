# Data Flow

```text
manifest
  -> resolver
  -> setup plan
  -> fetch/cache
  -> verify
  -> transaction stage
  -> commit
  -> installed-state write
  -> audit event
```

Rollback journals are produced before irreversible mutation. Diagnostics and
frontends read reports from the command layer; they do not write setup state
directly.
