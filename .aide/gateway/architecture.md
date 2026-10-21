# Gateway Architecture Boundary

Q19 comes after Q09-Q18 because a Gateway without compact context, verification,
review packets, token accounting, golden tasks, advisory outcomes, routing, and
local-state boundaries would only be a proxy. AIDE's product constraint is token
reduction with quality preservation, so the Gateway skeleton must expose those
signals before any provider adapter exists.

## Target Lifecycle

1. Intake receives or references a work unit.
2. A compact task packet identifies the objective and scope.
3. Context packet and repo maps provide exact refs instead of whole-repo dumps.
4. Verifier, golden tasks, token ledger, outcome controller, route profile, and
   cache-key metadata are read as local evidence.
5. Route explanation remains advisory and may block unsafe or under-evidenced
   work.
6. A future execution/provider phase may act only after a reviewed queue item
   enables it.
7. Evidence and review packets remain the audit surface.

## Q19 Endpoint Layer

Q19 endpoints are local status surfaces only:

- `/health`
- `/status`
- `/route/explain`
- `/summaries`
- `/version`

They return compact JSON metadata and references. They do not include raw source
files, full prompts, raw responses, provider credentials, or `.aide.local/`
contents.

## Future Provider Boundary

Future Q20+ provider adapters must respect:

- `.aide.local/` for local runtime state and provider key references.
- `.aide/policies/cache.yaml` for cache classes and invalidation.
- `.aide/policies/local-state.yaml` for committed versus local state.
- `.aide/policies/routing.yaml` for hard floors and advisory routes.
- `.aide/policies/gateway.yaml` for no raw prompt/response logging defaults.

Q19 documents OpenAI-compatible and Anthropic-compatible Gateway targets but
does not implement request forwarding.
