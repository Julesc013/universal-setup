# Gateway Security Boundary

Q19 is a local skeleton, not a production Gateway.

## Enforced In Q19

- Provider calls are disabled.
- Model calls are disabled.
- Outbound network calls are disabled.
- Raw prompt logging is disabled.
- Raw response logging is disabled.
- Secrets must not appear in committed files.
- `.aide.local/` remains gitignored local runtime state.
- Route decisions remain advisory.
- Verifier and golden tasks must not be bypassed by Gateway status surfaces.

## Forbidden In Q19

- OpenAI-compatible forwarding.
- Anthropic-compatible forwarding.
- Provider adapters.
- Local model setup or downloads.
- MCP/A2A tools.
- Semantic cache or vector indexes.
- Long-running daemon management.

## Future Risks

Future provider work must add authentication, authorization, request logging
policy, secret handling, cache invalidation, and provider-specific failure
handling through reviewed queue items before any live forwarding exists.
