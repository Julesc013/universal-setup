# Outcome Controller v0

## Purpose

Q16 adds a deterministic, repo-local advisory controller. It reads local outcome signals and turns them into bounded recommendations so future optimization work is based on evidence, not repeated broad review.

## Inputs

- `.aide/reports/token-ledger.jsonl`
- `.aide/reports/token-savings-summary.md`
- `.aide/verification/latest-verification-report.md`
- `.aide/context/latest-review-packet.md`
- `.aide/context/latest-task-packet.md`
- `.aide/evals/runs/latest-golden-tasks.json`
- `.aide/context/repo-map.json`
- `.aide/context/test-map.json`
- `.aide/context/context-index.json`
- `AGENTS.md` managed-section status

## Commands

Run from the repository root:

```bash
py -3 .aide/scripts/aide_lite.py outcome report
py -3 .aide/scripts/aide_lite.py outcome add --phase Q16 --source validation --result PASS --failure-class unknown --severity info
py -3 .aide/scripts/aide_lite.py optimize suggest
```

Use `python` instead of `py -3` only when the Windows launcher is unavailable.

## Outputs

- `.aide/controller/outcome-ledger.jsonl`: metadata-only outcome records.
- `.aide/controller/latest-outcome-report.md`: compact current outcome summary.
- `.aide/controller/latest-recommendations.md`: advisory recommendations.
- `.aide/controller/failure-taxonomy.yaml`: local warning/failure classes.
- `.aide/policies/controller.yaml`: controller policy and safety boundary.

## Recommendation Rules

The controller recommends repair before promotion when local signals show:

- golden tasks warn or fail
- packets exceed token budgets or regress
- verifier result is not clean enough for review
- review packet is incomplete
- context artifacts are missing or stale
- managed adapter guidance drifted

If core signals pass, it recommends Q17 Router Profile v0 as an advisory profile only.

## Safety Boundary

Recommendations are advisory only. Q16 does not mutate prompts, policies, routes, provider settings, context artifacts, or generated files outside explicit controller outputs and Q16 deliverables. It does not call models, providers, network services, Gateway, Runtime, Commander, hosts, or autonomous loops.

Implementation of any recommendation requires a future queue item or explicit human approval, followed by validation and golden tasks.

## Limits

Signal parsing is conservative and local. Q16 does not prove arbitrary coding quality, does not use an exact tokenizer, does not measure provider billing, and does not implement the Q17 Router Profile.
