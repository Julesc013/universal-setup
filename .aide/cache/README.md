# AIDE Cache Metadata

`.aide/cache/` stores committed cache policy and deterministic cache-key
metadata only. It is not a live cache and must not contain raw prompts, raw
responses, provider credentials, trace logs, model cache blobs, embeddings, or
semantic answer cache content.

Actual local runtime state belongs under `.aide.local/`, which is gitignored.
The example layout lives under `.aide.local.example/`.

Cache hits must not bypass verifier, golden tasks, route hard floors, or review
gates. Unknown or stale cache metadata is not trusted.
