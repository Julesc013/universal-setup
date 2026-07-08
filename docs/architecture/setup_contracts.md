# Setup Contracts

`USETUP-CONTRACT-01` defines the setup contract spine before Universal Setup
implements mutation commands.

The v1 contract set is:

- `install_plan`: plan-first request for local setup work.
- `installed_state`: durable record consumed by launchers and products.
- `verify_report`: integrity and policy check output.
- `audit_log`: append-only setup truth.
- `transaction`: staged, committed, refused, or failed setup work.
- `rollback`: journal for undoing committed or partially staged work.
- `ownership`: mutation authority for an install.
- `refusal`: explicit refusal result when policy or ownership blocks work.
- `policy`: setup-side safety rules.

The initial policy is intentionally conservative:

- no network access
- no registry mutation
- no package-manager mutation
- no product-specific installer execution

Future setup commands must produce these contracts before mutating installed
software state. Product repositories may supply manifests, archives, and policy
input, but Universal Setup remains product-neutral.
