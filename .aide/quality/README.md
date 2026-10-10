# AIDE File Quality Ledger

Q38 quality artifacts define deterministic, repo-local, advisory measurements
for ownership, docs, tests, validators, generated/evidence boundaries, stale
doc references, orphan candidates, module size, mixed-purpose hints, and reuse
candidates.

Run:

```text
py -3 .aide/scripts/aide_lite.py quality ledger
py -3 .aide/scripts/aide_lite.py quality validate
py -3 .aide/scripts/aide_lite.py quality status
py -3 .aide/scripts/aide_lite.py quality explain-file .aide/scripts/aide_lite.py
```

The ledger consumes Q37 outputs under `.aide/repo/`. It does not move, delete,
refactor, migrate, or auto-fix files. Warnings and candidates mean "inspect
before acting" and are inputs for future WorkUnits, especially Q39 Refactor
Control Plane v0.
