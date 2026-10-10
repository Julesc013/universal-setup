# Local Cache Example

This directory documents where future local cache metadata or cache blobs may
live under a real `.aide.local/cache/` directory.

Q18 does not implement a live cache. Future cache entries must not be committed
and must not bypass verifier, golden tasks, route hard floors, or review gates.

Raw prompts, raw responses, semantic answer caches, embeddings, vector indexes,
and provider response caches stay disabled unless a later reviewed policy
explicitly enables them.
