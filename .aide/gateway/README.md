# AIDE Gateway Skeleton

Q19 introduces the first AIDE Gateway boundary as a local, report-only skeleton.
It exposes AIDE's existing repo-local evidence and advisory routing signals
through health/status/summary surfaces, but it does not forward provider
requests or execute models.

The committed Gateway contract lives under `.aide/gateway/` and
`.aide/policies/gateway.yaml`. Runtime-specific state, credentials, traces, and
future local caches belong under gitignored `.aide.local/`, never in committed
Gateway artifacts.

## Q19 Scope

- Health/status/version metadata.
- Latest advisory route explanation.
- Compact references to token, context, review, verifier, golden-task,
  outcome-controller, route, and cache reports.
- Localhost-only skeleton server behavior when serve mode is used.

## Explicit Deferrals

- No provider calls.
- No model calls.
- No outbound network calls.
- No OpenAI-compatible forwarding.
- No Anthropic-compatible forwarding.
- No provider adapters.
- No raw prompt or response storage.
- No Runtime, UI, Commander, MCP, or A2A implementation.
