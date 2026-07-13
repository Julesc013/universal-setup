# Data Flow

```text
local archive + declarative recipe
  -> stable source handle
  -> archive inspect + deterministic entry set
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

Inspection is read-only. It does not initialize writable setup state and its
source, entry-set, budget, and filesystem identities become later plan inputs.
