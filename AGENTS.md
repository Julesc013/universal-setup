# AGENTS.md

<!-- AIDE-PORTABLE:BEGIN section=aide-lite-pack-v0 mode=managed -->
## AIDE Lite Portable Guidance

- This repository uses a portable AIDE Lite Pack imported from AIDE.
- Keep target-specific project state in `.aide/memory/`; do not copy source AIDE memory.
- Do not copy source `.aide/queue/`, generated context, reports, route decisions, cache-key reports, Gateway/provider status reports, `.aide.local/`, raw prompts, raw responses, or secrets.
- Generate target-local context with `py -3 .aide/scripts/aide_lite.py snapshot`, `index`, `context`, and `pack`.
- Use `py -3 .aide/scripts/aide_lite.py test` for portable AIDE Lite validation.
- Use `commit check`, `commit template`, and `changelog preview` for Q27-style structured commits.
- Use `task inspect`, `task noop-check`, and `task recover` before repeated or out-of-order work.
- Use `git policy`, `git detect`, and `git plan` before branch-sensitive work; do not mutate branches without explicit helper plan, validation evidence, and operator approval.
- Use `github advisory` and `github validate` for report-only GitHub/CI planning; do not install workflows or mutate GitHub settings without a later reviewed target item.
- Provider/model/network calls and Gateway forwarding remain forbidden unless a future reviewed target queue item enables them.
<!-- AIDE-PORTABLE:END section=aide-lite-pack-v0 -->

## Universal Setup continuation

Continue USK-SPEC-TO-RELEASE-01 using existing campaign records, active bindings,
repository engineering memory and the FacMan task's compact checkpoint. AIDE is
optional development tooling. This import does not start a goal, campaign or
queue, replace the current implementation, or activate AIDE execution pools.

Use one primary writer, the existing worktree/build/laboratory and configured
FacMan output root. The owner removed the fixed 20GiB campaign stop on
2026-10-17: continue development and retire verified disposable outputs. Keep
the 10GiB disk reserve, 2GiB RAM reserve and one-heavy-job limit. Preserve
coherent unfinished work with honest checkpoints. Use the existing Windows 10
Hyper-V VM when a VM is required; the old VM retirement is complete.
Follow the user's standing qualified-merge authorization and exact-source checks.

During active development, integrate reviewed checkpoints into dev at least
daily after its required core checks pass. An explicitly incomplete publisher
qualification may remain red on dev; record the failure and deployment limits.
Promote dev into main at least weekly when main's additional publisher
qualification and applicable acceptance gates pass. A missed target requires a
concrete blocker and next action, not a bypass or a fabricated qualification.
Do not accumulate a completed feature on a task branch waiting for the whole
specification. Main promotion, release publication and consumer adoption remain
separate qualified outcomes.

On BLACKGLASS-WIN1, credential-dependent GitHub operations use the actual
BLACKGLASS-WIN1\Jules identity and Julesc013 account. Record Windows identity
and perform read-only user-context authentication checks before authentication
claims. Isolated/service-account results are non-authoritative. Never expose,
switch or modify credentials; do not request login after valid user-context checks.

The portable section above is AIDE Apache-2.0 material; upstream license and
NOTICE are retained in external/aide. Project guidance below/above it remains
outside the importer-managed section and survives ownership-aware updates.
