# Gateway Skeleton

## Why Q19 Exists

Q19 adds the first AIDE Gateway boundary only after the token-survival stack is
present: compact context, verifier reports, review packets, token ledger,
golden tasks, outcome recommendations, advisory route decisions, and
cache/local-state policy.

A dumb proxy would not reduce tokens. The Q19 skeleton instead exposes local
evidence and advisory route metadata so future tools can see whether work is
ready before any provider tokens are spent.

## What Q19 Provides

- `.aide/policies/gateway.yaml`: local/report-only Gateway policy.
- `.aide/gateway/architecture.md`: request lifecycle and future provider
  boundary.
- `.aide/gateway/endpoints.yaml`: Q19 endpoint contract.
- `.aide/gateway/latest-gateway-status.json`: compact machine-readable status.
- `.aide/gateway/latest-gateway-status.md`: compact human-readable status.
- `core/gateway/gateway_status.py`: stdlib status and endpoint payload helpers.
- `core/gateway/server.py`: localhost-only HTTP skeleton for safe GET status
  endpoints.
- `py -3 .aide/scripts/aide_lite.py gateway status`
- `py -3 .aide/scripts/aide_lite.py gateway endpoints`
- `py -3 .aide/scripts/aide_lite.py gateway smoke`
- `py -3 .aide/scripts/aide_lite.py gateway serve --host 127.0.0.1 --port 8765`

## Endpoints

Q19 supports compact local JSON responses for:

- `GET /health`
- `GET /status`
- `GET /route/explain`
- `GET /summaries`
- `GET /version`

`gateway smoke` exercises those endpoint payloads in-process and also checks a
safe 404 path. `gateway serve` is optional foreground localhost-only behavior;
it is not auto-started and is not a daemon.

## Safety Boundary

Q19 does not implement:

- provider calls
- model calls
- outbound network calls
- OpenAI-compatible forwarding
- Anthropic-compatible forwarding
- provider adapters
- local model setup
- MCP/A2A
- Runtime workers
- authentication or authorization
- raw prompt logging
- raw response logging

Runtime state and future provider key references must stay under gitignored
`.aide.local/`. Committed Gateway artifacts are deterministic metadata and docs
only.

## How To Use

Run:

```powershell
py -3 .aide/scripts/aide_lite.py gateway status
py -3 .aide/scripts/aide_lite.py gateway endpoints
py -3 .aide/scripts/aide_lite.py gateway smoke
```

Use the generated Gateway status report in evidence and review packets. Do not
send the whole repo or prompt history to a reviewer when Gateway status,
verifier output, route decision, cache-key metadata, and compact packets are
enough.

## How Q20 Builds On Q19

Q20 Provider Adapter v0 builds on Q19 by adding offline provider family
metadata and no-call adapter contracts. It still does not enable live
forwarding, provider probes, credentials, model calls, or OpenAI/Anthropic-
compatible endpoints.

## Why Q21 Remains Next

Q21 Existing Tool Adapter Compiler v0 should consume the provider/Gateway
metadata contract for deterministic tool adapters without enabling provider
execution.
