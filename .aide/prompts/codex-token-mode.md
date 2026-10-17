# Codex Token Mode

Use this mode for AIDE queue implementation work after Q09.

## Rules

- Start from the compact task packet when available.
- Use repo references, repo-map/test-map/context-index refs, and exact paths instead of restating long project history.
- Prefer exact line refs such as `path#Lstart-Lend` when details are load-bearing.
- Do not paste full prior chat transcripts.
- Do not paste whole repo snapshots or repeated roadmap dumps.
- Paste full file contents only when exact contents are required and a file reference is insufficient.
- Emit deltas and concise evidence instead of narrative transcripts.
- Run proportionate validation before reporting completion.
- Run `py -3 .aide/scripts/aide_lite.py verify` before claiming substantial queue work is complete when Q12 verifier behavior is available.
- Run `py -3 .aide/scripts/aide_lite.py review-pack` before premium-model review when Q13 review workflow behavior is available.
- Run `py -3 .aide/scripts/aide_lite.py ledger scan`, `ledger report`, and relevant `ledger compare` commands when Q14 token-ledger behavior is available.
- Run `py -3 .aide/scripts/aide_lite.py eval run` when Q15 golden-task behavior is available and the work touches token-saving, context, verifier, review, ledger, adapter, or eval surfaces.
- Run `py -3 .aide/scripts/aide_lite.py outcome report` and `optimize suggest` when Q16 outcome-controller behavior is available.
- Treat controller recommendations as advisory only; do not mutate prompts, policies, routing, or context artifacts automatically.
- Implement controller recommendations only through a future queue item or explicit human approval, and rerun golden tasks before promotion.
- Run `py -3 .aide/scripts/aide_lite.py route explain` before expensive review or execution when Q17 Router Profile behavior is available.
- Treat route decisions as advisory only until a future reviewed Gateway/Runtime phase exists.
- Do not demote hard floors; architecture, security, self-modification, final promotion, governance, high-stakes, and destructive work require frontier or human review paths.
- Prefer the no-model/tool route when deterministic AIDE Lite or Harness commands can complete the work.
- Run `py -3 .aide/scripts/aide_lite.py cache status` and `cache report` when Q18 cache/local-state behavior is available and the work touches cache, local-state, Gateway, routing, review, token, or provider-adjacent surfaces.
- Never commit actual `.aide.local/` contents, raw prompts, raw responses, provider response cache blobs, semantic answer caches, traces, or provider keys.
- Treat cache-key reports as metadata only; cache hits must not bypass verifier, golden tasks, review gates, or hard floors.
- Keep semantic cache for code edits forbidden unless a future reviewed policy explicitly allows it.
- Run `py -3 .aide/scripts/aide_lite.py gateway status` and `gateway smoke` when Q19 Gateway skeleton behavior is available and the work touches Gateway/provider-adjacent surfaces.
- Treat Q19 Gateway as local/report-only; do not expect provider forwarding, OpenAI/Anthropic-compatible endpoints, Runtime execution, or model calls.
- Do not log raw prompts or raw responses through Gateway status, smoke, or future endpoint evidence.
- Run `py -3 .aide/scripts/aide_lite.py provider status`, `provider validate`, and `provider probe --offline` when Q20 provider-adapter behavior is available and the work touches provider, routing, Gateway, cache, credential, or adapter metadata surfaces.
- Treat Q20 provider metadata as offline advisory contracts only; do not use it as proof of provider availability, quality, pricing, or capability performance.
- Do not add provider credentials, account IDs, raw prompts, raw responses, provider probes, live model calls, or Gateway forwarding in provider-adapter work.
- Future live provider work requires an explicit reviewed queue phase and must keep credentials under `.aide.local/`.
- Keep provider/model calls forbidden unless a future reviewed phase explicitly enables them.
- Use `py -3 .aide/scripts/aide_lite.py export-pack --name aide-lite-pack-v0` for Q21-style portable AIDE Lite Pack generation before cross-repo pilots.
- Use `py -3 .aide/scripts/aide_lite.py import-pack --pack .aide/export/aide-lite-pack-v0 --target <target> --dry-run` before importing a pack into any target repository.
- Do not copy source repo `.aide/profile.yaml`, `.aide/queue/`, `.aide/memory/*.md`, generated context, reports, latest route/cache/Gateway/provider status, `.aide.local/`, raw prompts, raw responses, or secrets into target repositories.
- Target repositories must generate their own snapshot, index, task packet, verifier output, token reports, and project memory after import.
- Treat Q21 fixture import as portability evidence only; Eureka and Dominium value must be measured in Q22/Q23 pilots.
- Use `py -3 .aide/scripts/aide_lite.py adapter list`, `adapter render`, `adapter validate`, and `adapter drift` for Q24-style existing-tool guidance work.
- Treat `.aide/generated/adapters/**` as downstream guidance, not canonical truth.
- Do not overwrite Claude/Aider/Cline/Continue/Cursor/Windsurf files unless a future reviewed target policy authorizes it; Q24 only writes safe managed AGENTS sections.
- Keep existing tools pointed at compact task packets and evidence packets rather than long histories or full repo prompts.
- Do not store raw prompts or raw responses in committed ledger records.
- Treat token reduction as invalid if golden tasks fail.
- Treat token savings as invalid if quality evidence, validation, provenance, or review gates are weakened.
- Write task-local evidence for substantial work.
- Run `py -3 .aide/scripts/aide_lite.py index` and `context` when context artifacts are stale or absent.
- Commit coherent subdeliverables with verbose commit bodies.
- Stop at review gates and blockers.

## Output Discipline

Final reports must include status, changed files, validation, verifier result when available, review packet path when available, token ledger result when available, golden task result when available, outcome-controller recommendation status when available, router profile decision when available, cache/local-state status when available, Gateway status when available, provider-adapter status when available, evidence, risks, and next recommended phase.
