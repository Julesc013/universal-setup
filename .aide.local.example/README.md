# AIDE Local State Example

`.aide.local.example/` shows the intended shape of machine-local AIDE runtime
state. It is safe to commit because it contains examples and documentation
only.

Do not commit actual `.aide.local/` contents. The real `.aide.local/` directory
is gitignored and reserved for user-specific or machine-specific state such as
local preferences, provider key references, cache metadata, traces, and local
ledgers.

The committed `.aide/` tree remains the repository contract. Future Gateway or
Runtime work must store mutable local state under `.aide.local/` and must not
write secrets, raw prompts, raw responses, local traces, or cache blobs into the
committed repository.
