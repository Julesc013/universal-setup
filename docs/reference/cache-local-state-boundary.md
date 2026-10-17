# Cache And Local State Boundary

Q18 defines AIDE's first boundary between committed repo contract state and machine-local runtime state.

## Why Q18 Exists

AIDE will eventually need reuse and cache behavior to reduce token and provider cost, but unsafe cache storage can leak secrets, reuse stale context, or pollute committed evidence. Q18 establishes the boundary first:

- committed contract and reviewable metadata live under `.aide/`
- local runtime state belongs under gitignored `.aide.local/`
- `.aide.local.example/` documents the shape without containing secrets
- cache-key reports are deterministic metadata only
- raw prompts, raw responses, provider responses, semantic answers, traces, and cache blobs are not committed

## Local State

`.aide.local/` is reserved for future machine/user-specific runtime state. It is ignored by `.gitignore` and must not be tracked or staged.

`.aide.local.example/` is the safe template. It contains README files and an example config, but no provider keys, credentials, prompts, responses, traces, embeddings, or cache bodies.

Future Gateway/Runtime work must use this boundary instead of inventing ad hoc local cache or secret paths.

## Cache Keys

Cache keys use SHA-256 metadata over packet/report surfaces and selected dependency hashes. The current format is:

```text
aide-cache-v0:<surface>:<short_sha256>
```

Generated reports:

- `.aide/cache/latest-cache-keys.json`
- `.aide/cache/latest-cache-keys.md`

These reports include paths, content hashes, dependency hashes, policy versions, git commit when available, dirty-state metadata, and notes. They do not include raw file contents.

## Commands

```powershell
py -3 .aide/scripts/aide_lite.py cache init
py -3 .aide/scripts/aide_lite.py cache status
py -3 .aide/scripts/aide_lite.py cache key --file .aide/context/latest-task-packet.md
py -3 .aide/scripts/aide_lite.py cache key --task-packet .aide/context/latest-task-packet.md
py -3 .aide/scripts/aide_lite.py cache report
```

`cache init` verifies the boundary and updates missing `.gitignore` protection if needed. It does not create committed local state.

`cache status` checks `.aide.local/` ignore status, example layout presence, policy files, cache report presence, and tracked-local-state risk.

`cache key` computes metadata for one safe file or task packet. It refuses ignored, local-state, secret-risk, missing, directory, and binary-like paths.

`cache report` refreshes the latest JSON and Markdown cache-key reports for known compact surfaces.

## Safety Rules

- Cache hits must not bypass verifier, golden tasks, review gates, or hard floors.
- Semantic cache for code edits is forbidden unless a future reviewed policy explicitly enables it.
- Provider response caching is disabled until a future Gateway phase defines exact prompt hashes, risk classes, storage rules, and redaction behavior.
- `.aide/cache/**` stores policy and metadata reports only, not live cache contents.
- Actual `.aide.local/` contents remain uncommitted.

## Deferred Work

Q18 does not implement Gateway, provider/model calls, a live prompt/response cache, semantic cache, embeddings/vector indexes, local model KV cache, exact tokenizer, provider billing integration, Runtime, Service, Commander, UI, Mobile, MCP/A2A, or autonomous loops.

Q19 should build Gateway Architecture and Skeleton against this boundary without weakening it.
