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
For `install_local.plan`, also pass `--context-file path` with an explicit
acceptance boundary:

```json
{"schema":"usk.oneshot_context.v1","state_root":"C:/disposable-acceptance/setup-owned","authorized_acceptance_root":"C:/disposable-acceptance","target_policy_activation":"operator_acceptance_candidate"}
```

The context file is bounded to 16 KiB and applies only to that planning
command. The plan payload must request
`required_commit_authority=staged_child_bound_v1`. The host calls the public
planning ABI and copies the response before destroying its context. Planning
inspects the named source and target but does not create the setup or target
root. The protected publisher is not yet qualified, so this plan is not an
installation capability. Use an explicitly authorized, disposable acceptance
root for tests.
For example:

```json
{"schema":"usk.oneshot_request.v1","request_id":"example-1","command":"command_graph.inspect","payload":{},"dry_run":true}
```

The current host admits only read-only inspection and planning commands. It rejects
mutations, oversized input, trailing framed bytes, and unknown request fields.
Diagnostics go to stderr without echoing request content. Human interaction,
setup mutation commands, and general response-file expansion are still pending.
