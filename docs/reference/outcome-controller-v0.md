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

## Preserving project metadata

The ledger keeps unfamiliar JSON fields as opaque project data. Reading, adding an
observation, or regenerating the current run preserves those fields when the existing
`run_id`, `phase`, and `source` identify exactly one replacement. Metadata does not
grant permissions or automatically change routing, evaluation, or recommendations.
Keep source references and compact lessons here; raw prompts, responses and secrets
remain forbidden by the storage policy.

Malformed JSON, duplicate keys, non-object records, non-finite numbers, invalid known
field types and missing identities stop updates with a line-specific diagnostic.
The original ledger and existing reports remain untouched. Unmatched, ambiguous or
conflicting metadata also stops regeneration. Inspect and reconcile the indicated
record explicitly, preserving the original observation; the controller does not
silently delete it or guess a repair. Valid older records retain optional defaults.

The complete ledger is serialized before the existing atomic replacement helper
publishes it. This prevents a failed replacement from leaving a partly written
ledger; it does not establish concurrent-writer exclusion, a multi-file transaction,
or power-loss recovery. Reports remain regenerable views. Updating the same identity
and regenerating `q16.current` retain their existing replacement semantics. Use
distinct run identities and the existing attempt evidence for historical failures;
this ledger is not an immutable attempt log.

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

## Current, scoped lessons

Run outcome lessons --path tests/check.py --json to inspect advisory lessons
for one exact, case-sensitive repository-relative path. The command reads the
existing outcome ledger and bounded local evidence. It writes nothing, runs no
models and does not alter context, permissions, routing or evaluators. Text mode
shows selected advice and exclusion reasons. JSON preserves the selected lesson
object, its identity, exact evidence hashes and explicitly unverified claims.

A project may add an optional lesson object to a uniquely identified outcome row:

    {
      "schema_version": "aide.outcome-lesson.v1",
      "id": "consumer-oracle",
      "revision": 1,
      "state": "active",
      "summary": "Keep the consumer oracle independent of the implementation.",
      "applies_to": ["tests/check.py"],
      "evidence": [{"path": "tests/check.py", "sha256": "<actual lowercase SHA256>"}],
      "supersedes": null,
      "required_features": ["advisory_only", "revision_chain", "source_sha256"]
    }

Use the normal reviewed project workflow to author the row. Active is declared
project state, not proof of review, authorship or semantic correctness. Original
outcome fields, compact notes and evidence remain; no new ledger is introduced.
This increment provides retrieval, not an automatic lesson writer.

Correct a lesson by appending a new outcome row with a distinct
run_id/phase/source identity, the same lesson ID, the next revision and the
digest of the previous complete lesson object in supersedes. Retire it the same
way with state: retired. Preserve every earlier row. Digest serialization is
UTF-8/ASCII JSON with sorted keys, ASCII escapes, separators comma and colon, and
non-finite numbers refused; the digest is SHA256 with no trailing newline.
Unknown optional fields participate in that digest and remain opaque.

Every revision from1 to latest must be present exactly once and linked correctly.
Duplicate identities/revisions, broken chains and unknown schema or required
features refuse the whole selection. Retirement immediately excludes the latest
lesson; stale or missing evidence does not revive an earlier revision. An explicit
later revision may reactivate corrected guidance. There is no retrieval cache.

Only latest active lessons matching the exact requested path read their evidence.
All references must match their recorded bytes before advice is selected.
Missing, changed, unsafe or unreadable evidence excludes the lesson with a reason;
out-of-scope and retired summaries are not selected or emitted. Optional unfamiliar
metadata is preserved, not interpreted as a grant. Hash equality establishes byte
identity, not the truth of a claim or applicability to an unrecorded environment.

Limits:1MiB ledger,2048 physical rows,256 lesson revisions,16 applicability paths,
8 references per revision,128 distinct evidence references,128KiB per reference.
Evidence is read twice (at most32MiB total) and the ledger is re-read to detect
observed changes. These are cooperative snapshot checks, not hostile-filesystem
isolation or a transaction. Existing path exclusions reject private/local and
redirected references. They are not a content-classification or secret detector.
Store only appropriately shareable metadata under the existing controller policy.
A missing ledger is reported separately from an observed ledger with no matches.

The portable helper follows the executing CLI, not a module in the selected
project. Source-local lessons are not copied into a new project's history.
This does not demonstrate improved model performance or authorize model training.
