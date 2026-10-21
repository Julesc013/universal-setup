# Local Traces Example

Future local traces may live under `.aide.local/traces/` only when a reviewed
phase authorizes trace collection.

Trace files are local runtime state. They must not be committed, and they must
not contain provider credentials, raw prompts, raw responses, or private user
data by default.
