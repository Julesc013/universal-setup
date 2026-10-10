# Intent Compiler and Prompt Normalization v0

## Purpose

Q36 adds a deterministic intake layer for raw prompts. AIDE does not execute
raw user intent directly. A prompt must first become a reviewable intent packet
and draft WorkUnit, or be blocked, split, or redirected to an audit/preflight.

The compiler is policy-based and local-only. It does not call models,
providers, outbound network services, GitHub APIs, Gateway forwarding, target
repositories, branch mutation commands, or the compiled WorkUnit.

## Command Surface

```powershell
py -3 .aide/scripts/aide_lite.py intent compile --prompt "next"
py -3 .aide/scripts/aide_lite.py intent compile --file prompt.txt
py -3 .aide/scripts/aide_lite.py intent validate
py -3 .aide/scripts/aide_lite.py intent examples
py -3 .aide/scripts/aide_lite.py intent status
```

`intent compile` writes:

- `.aide/intake/latest-intent-packet.json`
- `.aide/intake/latest-intent-packet.md`
- `.aide/intake/latest-workunit-draft.json`
- `.aide/intake/latest-workunit-draft.md`

The raw prompt is not logged. The packet stores a SHA-256 hash and a bounded
excerpt only.

## Classification

The compiler uses deterministic phrase rules from:

- `.aide/policies/intent.yaml`
- `.aide/policies/prompt-normalization.yaml`
- `.aide/policies/task-classes.yaml`
- `.aide/policies/risk-classes.yaml`
- `.aide/policies/workunit-sizing.yaml`

Task classes include audit, repair, docs, test, implementation, refactor,
release, install, upgrade, rollback, git, github, adapter, context, evidence,
and unknown.

Risk classes include low, medium, high, destructive, security, governance,
release, external_side_effect, and unknown.

Sizing classes include one_shot, two_shot, refactor_gate, live_test_gate,
audit_only, split_required, and blocked.

## Normalization Examples

- `next` becomes a context/audit-style action to inspect repo queue state, not
  invented product work.
- `fix everything` becomes overbroad and split_required.
- `clean up the repo` becomes refactor/high risk and requires inventory before
  moves.
- `delete old XStack stuff` is destructive and rejects direct deletion.
- `merge dev to main` is Git/release risk and requires branch-policy evidence.
- `publish a release` is blocked until release gates, tags, assets, and approval
  exist.
- `install AIDE into Dominium` requires preflight and preservation of target
  doctrine/tooling.
- `repair failing test` can be one_shot when the failure and validation target
  are clear.

## Using The Output

The latest intent packet is evidence for the next queue or intake decision. It
is not permission to implement. For non-trivial work, convert the draft into a
filesystem queue item with an ExecPlan, allowed paths, validation, evidence, and
review gates.

`safe_to_execute` means the prompt can become a bounded next action after normal
queue controls. It does not bypass commit discipline, branch policy, recovery
policy, or review gates.

After Q37, intent packets may cite `.aide/repo/latest-repo-intelligence.md` and
`.aide/repo/file-inventory.json` when those outputs exist. This is a compact
repo-state reference only; intent compilation still falls back gracefully when
repo intelligence has not been generated in a target repository.

## Limits

Q36 is intentionally conservative. It uses deterministic heuristics, not
semantic model inference. Q37 adds deterministic ownership, dependency, test,
documentation-link, and generated-output indexes, but Q36 still does not
execute compiled WorkUnits or make quality/refactor decisions.
