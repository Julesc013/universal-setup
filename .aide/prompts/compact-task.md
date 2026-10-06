# AIDE Compact Task Packet Template

## PHASE

`<queue id and title>`

## GOAL

`<one observable outcome>`

## WHY

`<why this reduces tokens, preserves quality, or unlocks direct utility>`

## CONTEXT_REFS

- `.aide/memory/project-state.md`
- `.aide/context/repo-snapshot.json`
- `.aide/context/repo-map.json`
- `.aide/context/test-map.json`
- `.aide/context/context-index.json`
- `.aide/context/latest-context-packet.md`
- `.aide/routing/latest-route-decision.json` when Q17 routing is available
- `.aide/routing/latest-route-decision.md` when Q17 routing is available
- `.aide/cache/latest-cache-keys.json` when Q18 cache-key metadata is available
- `.aide/cache/latest-cache-keys.md` when Q18 cache-key metadata is available
- `.aide/gateway/latest-gateway-status.json` when Q19 Gateway skeleton status is available
- `.aide/gateway/latest-gateway-status.md` when Q19 Gateway skeleton status is available
- `.aide/providers/latest-provider-status.json` when Q20 provider-adapter metadata is available
- `.aide/providers/latest-provider-status.md` when Q20 provider-adapter metadata is available
- `.aide/generated/adapters/manifest.json` when Q24 adapter compiler outputs are relevant
- `.aide/generated/adapters/drift-report.md` when Q24 adapter compiler outputs are relevant
- `<task-specific source refs>`

## ALLOWED_PATHS

- `<explicit allowlist>`

## FORBIDDEN_PATHS

- `.git/**`
- `.env`
- `secrets/**`
- `.aide.local/**`
- `<task-specific denylist>`

## IMPLEMENTATION

- `<bounded deliverable>`

## VALIDATION

- `<exact command>`
- `py -3 .aide/scripts/aide_lite.py verify`
- `py -3 .aide/scripts/aide_lite.py review-pack`
- `py -3 .aide/scripts/aide_lite.py ledger scan`
- `py -3 .aide/scripts/aide_lite.py ledger report`
- `py -3 .aide/scripts/aide_lite.py eval run`
- `py -3 .aide/scripts/aide_lite.py outcome report`
- `py -3 .aide/scripts/aide_lite.py optimize suggest`
- `py -3 .aide/scripts/aide_lite.py route explain`
- `py -3 .aide/scripts/aide_lite.py cache status`
- `py -3 .aide/scripts/aide_lite.py cache report`
- `py -3 .aide/scripts/aide_lite.py gateway status`
- `py -3 .aide/scripts/aide_lite.py gateway smoke`
- `py -3 .aide/scripts/aide_lite.py provider status`
- `py -3 .aide/scripts/aide_lite.py provider validate`
- `py -3 .aide/scripts/aide_lite.py provider probe --offline`
- `py -3 .aide/scripts/aide_lite.py adapter validate`
- `py -3 .aide/scripts/aide_lite.py adapter drift`

## COMMITS

- `<coherent commit sequence>`

## EVIDENCE

- changed files
- validation commands and results
- verifier result and latest verification report path when Q12 verifier is available
- latest review packet path when Q13 review-pack is available
- token estimate, ledger record status, and savings comparison when Q14 ledger behavior is available
- golden task result summary when Q15 eval behavior is available
- outcome-controller recommendation status when Q16 controller behavior is available
- route decision class, hard-floor status, and advisory-only status when Q17 router behavior is available
- cache/local-state status and latest cache-key report path when Q18 cache behavior is available
- gateway skeleton status and endpoint smoke result when Q19 Gateway behavior is available
- provider-adapter status, provider validation result, and offline probe result when Q20 provider behavior is available
- adapter compiler status, generated manifest path, drift result, and preview-only/write boundaries when Q24 adapter behavior is available
- risks and deferrals

## NON_GOALS

- `<explicit deferred work>`

## ACCEPTANCE

- `<pass/fail criterion>`

## OUTPUT_SCHEMA

Return a compact final report with:

- `STATUS`
- `SUMMARY`
- `COMMITS`
- `CHANGED_FILES`
- `VALIDATION`
- `VERIFIER_RESULT`
- `REVIEW_PACKET`
- `TOKEN_SURVIVAL_RESULT`
- `TOKEN_LEDGER_RESULT`
- `GOLDEN_TASK_RESULT`
- `OUTCOME_CONTROLLER_RESULT`
- `ROUTER_PROFILE_RESULT`
- `CACHE_LOCAL_STATE_RESULT`
- `GATEWAY_RESULT`
- `PROVIDER_ADAPTER_RESULT`
- `ADAPTER_COMPILER_RESULT`
- `RISKS`
- `NEXT`

## TOKEN_ESTIMATE

approx_tokens: `<estimate from characters divided by four>`

Record the compact packet's character-count estimate. This is not an actual
tokenizer measurement or parent/child/host usage. Keep unavailable actual usage
unknown; do not infer allowance savings from this document-size estimate.
