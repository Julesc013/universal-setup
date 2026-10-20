# Native reviewed authored installation candidate

This native CLI connects a finalized packaged bundle to the existing public
planner and registered publisher. Neither prefab envelope is qualified as an
installer: manifest delivery properties remain `inspect_only` and `unqualified`.
A separately admitted publisher must already exist. The host does not
install/register a service, create a lab envelope, grant target ownership or
weaken an unavailable strict profile.

Use a bundle finalized to its complete selected component closure, with portable
scope and an entrypoint present in the payload. The current target is native
Windows x64, including a Win32 client running on that host. Provide an options
file with exactly these fields:

```json
{
  "schema": "usk.authored_install_options.v1",
  "request_id": "example.preview",
  "install_id": "org.example.product",
  "created_at": "2026-10-21T00:00:00Z",
  "target_root": "C:/ExplicitAcceptance/product",
  "entrypoint": {
    "entrypoint_id": "main",
    "kind": "application",
    "relative_path": "bin/app.exe"
  }
}
```

Use the existing `usk.oneshot_context.v1` planning context with explicit
`state_root`, `authorized_acceptance_root` and `target_policy_activation`.
Planning is read-only; a context file is not publisher authority.

```text
usk_machine.exe --product-plan product.bundle.json --request-file options.json --context-file context.json > review.json
```

Success emits `usk.authored_install_review.v1` containing the complete standard
one-shot `request` and native `response`. Inspect both before confirming, including
target, source, planned files/effects and the native plan ID/digest. A planner
refusal returns the existing one-shot refusal rather than a usable review.

Supply a separate confirmation file with exactly these fields, copying the
reviewed native ID/digest and choosing the apply invocation/transaction identity:

```json
{
  "schema": "usk.authored_install_confirmation.v1",
  "request_id": "example.apply",
  "reviewed_plan_id": "<reviewed plan_id>",
  "reviewed_plan_digest": "<reviewed plan_digest>",
  "transaction_id": "example.transaction",
  "applied_at": "2026-10-21T01:00:00Z",
  "confirmation": "APPLY"
}
```

```text
usk_machine.exe --product-apply product.bundle.json --review-file review.json --request-file confirmation.json --context-file context.json --publisher USK_PUB_<registered-32-lowercase-hex-id>
```

Apply verifies the packaged byte closure again, reconstructs the fixed plan
request and compares it with the saved request. It re-plans under the supplied
context and requires the entire fresh response to equal the reviewed response.
Changed source identity, target, policy, planned files or effects invalidate the
review before transport. Restoring source bytes after mutation need not restore
their filesystem identity; obtain a new review when stale.

The existing one-shot adapter prepares invocation-bound uncertainty before
dispatch; the registered publisher independently revalidates the reviewed plan.
A missing or malformed reply after possible dispatch remains UNKNOWN (exit 5).
Do not infer no effect or retry with a new transaction solely from a timeout.
Recover/inspect the retained invocation under the supported publisher contract.
Ctrl+C uses the same borrowed cancellation event as the existing publisher CLI.

Options and confirmation input files are each bounded to 16 KiB; review input
and output fit the existing 16 MiB response ceiling. Composed one-shot requests
fit the existing 1 MiB request ceiling. These are encoded-document ceilings,
not total memory limits. Existing native/archive limits still apply. No public
C ABI or versioned product/package contract changes.

The focused native process test proves real read-only planning, Python recipe
parity, refusal before transport on altered inputs, and controlled reply/UNKNOWN
handling. Its successful transport is a test adapter; the actual registered
transport case proves refusal for an absent registration. These tests do not
establish successful installation, interruption recovery, package dependency
closure or release acceptance.

