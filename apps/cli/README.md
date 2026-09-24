# CLI

Universal Setup console frontend entrypoint. Reusable setup behavior belongs under `runtime/setup/`.

`usk_live_acceptance` is the bounded M2 operator-acceptance runner. On Windows
it accepts only `D:\FacMan-Live-Acceptance\M2`; its `--test-mode` exception is
restricted to a child of the platform temporary directory. It creates a new
exclusive run root, uses a harmless non-executable synthetic ZIP, calls only
the public command ABI, and leaves immutable setup state, audit, journal,
evidence packets, and a summary for review. It cannot record a human verdict.

`usk_machine` is the initial one-shot machine command host. Pass `--machine`
for one JSON request on stdin and one JSON response line on stdout, or
`--framed` for a four-byte big-endian length followed by the JSON body in both
directions. Append `--request-file path` to read the exact bounded request bytes
from a file instead of stdin; the selected mode still determines the framing.
For example:

```json
{"schema":"usk.oneshot_request.v1","request_id":"example-1","command":"command_graph.inspect","payload":{},"dry_run":true}
```

The current host admits only read-only inspection commands. It rejects
mutations, oversized input, trailing framed bytes, and unknown request fields.
Diagnostics go to stderr without echoing request content. Human interaction,
response files, and setup mutation commands are still pending.
