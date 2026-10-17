# AIDE Repair / Doctor Model

Q44 repair artifacts define deterministic, local, no-apply observation,
diagnosis, planning, dry-run, doctor-report, and verification behavior for
broken, partial, stale, or inconsistent AIDE installs.

Q44 does not repair files, overwrite files, delete files, move files, rewrite
references, migrate files, mutate target repositories, or call providers,
models, or network services.

Target repositories must generate their own `.aide/repair/latest-*` outputs
after import. Source-generated repair outputs are evidence for the source repo
only and are not target truth.
