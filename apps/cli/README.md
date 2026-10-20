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

On Windows, the separate `--candidate-service USK_PUB_<32 lowercase hex>
--request-file path` mode forwards one reviewed `install_local.apply` or
installed-verification request to an already running, registered restricted
publisher service. It prints that service's actual JSON observation; exit 0
means the service reported `pass`, exit 3 means a reported failure or recovery
requirement, and exit 5 means the reply could not establish the operation's
outcome. Retry the same reviewed request after exit 5. This mode cannot
register a service, choose a source or target, or enable the unqualified
general publisher. The existing read-only `--machine` and `--framed` protocols
remain unchanged.

For a registered candidate service, the same one-shot machine envelope can
carry `install_local.apply`, `installed.verify`, or `install_local.recover`:

```text
usk_machine --machine --candidate-service USK_PUB_<32 lowercase hex> --request-file request.json
```

Set `dry_run=false` and use the matching reviewed publisher request as
`payload`. The bounded response retains the service observation in `result`.
`ok` exits 0, a service refusal exits 4, and `recovery_required` or an unknown
transport outcome exits 5 with distinct response statuses. A completed
verification with file drift returns `ok` at the machine layer;
read the nested verification report's `fail`, `warn`, or `unknown` status.
The service still
checks the selected source, plan, target, caller and registered identity;
choosing a candidate service does not grant publisher authority. Planning
contexts cannot be combined with this mode. The hosted machine-client check
exercises this envelope through the restricted service, validates its result,
and independently reads the installed resources.

The registered `--publisher` route also accepts the public SDK recovery family:
`recovery.inspect`, `recovery.plan`, and `recovery.apply`. Put the complete matching
`usk.recovery_inspect_request.v1`, `usk.recovery_plan_request.v1`, or
`usk.recovery_apply_request.v1` document in the one-shot envelope's `payload`.
Use `dry_run=true` for inspection/planning and `dry_run=false` for reviewed apply.
The apply request retains the reviewed plan ID/digest, selected finalize/rollback
choice, timestamp and explicit `APPLY` confirmation. The service determines which
actions its actual interrupted operation supports; selecting an unsupported action
does not enable it.

The host forwards that complete request and validates the native v2 report/plan
using the same codecs as the SDK. A successful outer `result` is the public
`usk.command_response.v1`; read its `payload` for the versioned recovery document.
When dispatch may have occurred but a matching reply cannot be established, exit5
and outer `status=unknown` retain an inner uncertainty response bound to this
invocation, including the original operation and reviewed recovery identity.
Inspect the actual operation before deciding what to do next. A transport failure
does not establish its terminal state or authorize a fresh operation.

The existing operation-specific recovery routes remain compatible. Public recovery
is unavailable through `--candidate-service`. This adapter does not establish
protected recovery, publisher, customer installation or release qualification.
