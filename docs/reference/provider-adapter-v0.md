# Provider Adapter v0

## Why Q20 Exists

Q20 creates the first provider-adapter contract layer after AIDE has compact
context, verification, evidence review, token accounting, golden tasks,
outcome recommendations, advisory routing, cache/local-state boundaries, and a
local Gateway skeleton.

Provider routing can reduce token spend only when provider families are
described through auditable metadata instead of prompt folklore. Q20 records
that metadata without enabling live execution.

## What Q20 Provides

- `.aide/policies/provider-adapters.yaml`: offline provider-adapter policy.
- `.aide/providers/provider-catalog.yaml`: provider family catalog.
- `.aide/providers/capability-matrix.yaml`: conservative capability metadata.
- `.aide/providers/adapter-contract.yaml`: required adapter metadata shape.
- `.aide/providers/status.yaml`: Q20 no-call status record.
- `.aide/providers/latest-provider-status.json`: generated provider status.
- `.aide/providers/latest-provider-status.md`: human-readable provider status.
- `core/providers/**`: standard-library metadata contracts and validators.
- `py -3 .aide/scripts/aide_lite.py provider list`
- `py -3 .aide/scripts/aide_lite.py provider status`
- `py -3 .aide/scripts/aide_lite.py provider validate`
- `py -3 .aide/scripts/aide_lite.py provider contract`
- `py -3 .aide/scripts/aide_lite.py provider probe --offline`

## Provider Families

Q20 records provider families, not live accounts:

- deterministic tools
- human review
- local Ollama
- local LM Studio
- local llama.cpp
- local vLLM
- local SGLang
- OpenAI
- Anthropic
- Google Gemini
- DeepSeek
- OpenRouter
- other remote provider

Each family records adapter class, provider class, privacy class, credential
requirements, credential location, live-call status, and conservative notes.

## Capability Metadata

Capabilities use conservative status values:

- `supported_by_contract`
- `planned`
- `unknown`
- `not_applicable`
- `requires_future_probe`

Q20 does not claim measured performance, pricing, model availability, latency,
quality, or exact long-context behavior. Local and remote model capabilities
remain planned or probe-required until a future reviewed phase validates them.

## Commands

Run:

```powershell
py -3 .aide/scripts/aide_lite.py provider list
py -3 .aide/scripts/aide_lite.py provider status
py -3 .aide/scripts/aide_lite.py provider validate
py -3 .aide/scripts/aide_lite.py provider contract
py -3 .aide/scripts/aide_lite.py provider probe --offline
```

`provider status` refreshes `.aide/providers/latest-provider-status.json` and
`.aide/providers/latest-provider-status.md`. `provider probe --offline` is a
metadata readiness check only; it does not contact providers.

## Credential Boundary

Credentials are forbidden in committed `.aide/` records. Future credential
references must live under gitignored `.aide.local/` and must be introduced
only by a future reviewed queue phase. Q20 records where credentials would
belong later, but configures none.

## Routing And Gateway Use

Route decisions may reference provider family candidates as metadata only.
Gateway status may include provider-adapter readiness as local metadata only.

Neither surface executes a route, calls a provider, probes availability, or
forwards OpenAI/Anthropic-compatible requests.

## Safety Boundary

Q20 does not implement:

- live provider calls
- model calls
- outbound network calls
- provider probes
- credential setup
- local model setup
- Gateway forwarding
- provider billing or pricing checks
- exact tokenizer integration
- raw prompt storage
- raw response storage
- provider response cache
- MCP/A2A

Provider selection must still respect router hard floors, verifier results,
golden tasks, cache/local-state policy, and review gates.

## Why Q21 Remains Next

Q21 Existing Tool Adapter Compiler v0 can build on Q20 by compiling
metadata-only contracts for existing deterministic tools. It still must not
enable provider execution unless a later reviewed phase explicitly authorizes
that boundary.
