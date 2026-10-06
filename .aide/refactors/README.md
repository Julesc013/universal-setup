# AIDE Refactor Control Plane

`.aide/refactors/` contains Q39 refactor-control schemas and generated
dry-run planning artifacts.

Q39 is no-apply infrastructure. It defines how future structural changes can
be represented as refactor plans, operations, move maps, salvage maps,
path-alias plans, migration ledger records, rollback notes, risks, validation
plans, and evidence packets.

Generated `latest-*` files in this directory are AIDE source-repo evidence.
They are not target-repository truth and are not exported as target plans.
Target repositories must generate their own readiness artifacts after import.

Q39 does not move files, delete files, rewrite references, apply migrations,
mutate branches, mutate target repositories, or call providers/models/network
services.
