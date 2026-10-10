# AIDE Upgrade Model

Q45 defines deterministic, local, preservation-first upgrade observation,
comparison, planning, dry-run, validation, and reporting.

This directory contains portable schemas plus source-generated latest upgrade
outputs. The generated `latest-*` files are AIDE source-repo evidence only.
Target repositories must generate their own upgrade observations and plans.

Q45 does not apply upgrades, overwrite files, delete files, migrate files,
move files, rewrite references, mutate target repositories, publish releases,
activate CI, or call providers/models/network services.
