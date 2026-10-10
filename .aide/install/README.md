# AIDE Install Planning

`.aide/install/` contains Q43 install planning schemas and generated no-apply
install observation, plan, dry-run, ownership-ledger, conflict, preservation,
and verification artifacts.

Q43 is planning infrastructure only. It observes target state, builds a
candidate install plan from the current portable pack, writes dry-run evidence,
and validates that no operation is apply-enabled or overwrite-enabled.

Generated `latest-*` files in this directory are AIDE source-repo evidence.
They are not target-repository truth and are not exported as target install
plans. Target repositories must generate their own install observations and
plans after import.

Q43 does not install files, overwrite target state, migrate files, delete files,
move files, rewrite references, mutate target repositories, mutate branches, or
call providers/models/network services.
