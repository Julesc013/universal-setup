# Verified bundle to read-only machine plan

`usk_bundle_plan.py` connects an already compiled, verified product bundle to
the existing `usk_machine install_local.plan` command. It emits one canonical
`usk.oneshot_request.v1` JSON document on stdout. The command host performs
its own archive and target inspection. Neither this tool nor the command host
installs the payload.

The product author supplies an entrypoint path that exists in the selected
bundle. A compiled bundle with optional components left out of its default
selection is refused because its ZIP would otherwise contain files outside
the requested component set. Finalize the component choice with
`usk_bundle_selection.py finalize` first, then pass the resulting
`product.bundle.json` here. Keep the original compiled bundle and selection
receipt for full-graph provenance; the finalized package is unsigned.
The bundle must admit `portable` scope and its target must match the current
host OS and architecture (`windows`, `linux`, or `macos`; `x64` or `arm64`).
This is a plan compatibility check, not platform publisher qualification.
The adapter preflights the native lifecycle's 4,096-file and path budgets and
accepts only `application`, `tool`, or `server` entrypoint kinds. Native
planning remains the final authority and may refuse other constraints.

Example for a disposable operator acceptance root:

```powershell
python tools/usk_bundle_plan.py `
  --bundle C:\lab\selected\product.bundle.json `
  --target-root C:\lab\installed-product `
  --request-id plan-1 --install-id example.install.1 `
  --created-at 2026-09-25T00:00:00Z `
  --entrypoint-id main --entrypoint-kind application `
  --entrypoint-path bin/app.exe > C:\lab\request.json

usk_machine --machine --request-file C:\lab\request.json `
  --context-file C:\lab\machine-context.json
```

The context file must independently bind the setup state root, acceptance
root and activation as documented in `apps/cli/README.md`. The target must be
absent and within that authorized acceptance root. The request always asks
for `staged_child_bound_v1`; it cannot downgrade to the legacy publisher.
The recipe digest binds the bundle SHA-256 and author-supplied entrypoint.
Archive budgets are calculated from the exact file inventory. This is local
integrity checking, not signature or origin authentication. No production
install path is enabled until the protected publisher is qualified.
