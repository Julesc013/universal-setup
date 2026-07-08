# Transaction Model

Setup mutation is plan-first and audit-first. A transaction must describe the
files, ownership records, state writes, rollback journal, verification gates,
and audit events before commit.

No frontend may skip directly from user intent to filesystem mutation.
