### Change communication

**Default:** explain the outcome and reason, show what was checked, and include
material risks or next actions. Use enough detail to assess and maintain the
change. The goal is information density, not minimum words or a fixed form.

These defaults apply to AIDE and adopting projects through project-owned policy.
Preserve local conventions, templates, notices and compatibility obligations.
They do not install hooks, configure hosting, post messages or grant authority.

**Presentation**

- Commits must remain readable as plain text in Git, email and older tools:
  a short subject, blank line, concise paragraphs and bullets where useful.
- PRs, issues and comments use short prose, **bold labels**, bullets and inline
  code for paths, commands and identifiers. Use italics sparingly.
- Use H3/H4 when longer material needs navigation; no H1/H2 defaults. Underline
  is optional in supporting renderers (GitHub: `<ins>text</ins>`). Never depend
  on HTML for meaning or use underline in place of a link.
- Lead with the decision or result. Use tables for comparisons, checkboxes for
  real obligations, and links for logs/evidence. Preserve enough rationale
  locally to make sense if an external link disappears.
- Avoid repeated summaries, diff narration, chat chronology, empty sections,
  boilerplate `None`, unmeasured savings and unchecked claims.

**Length is proportional.** Aim for roughly 50-72 subject characters and wrap
plain prose at 72-100 columns when practical. Never split URLs or identifiers.
These are guidelines, not a proven optimum. A small change may need one paragraph
and validation; a migration needs impact, migration and recovery information.
There is no word quota. Do not compress away failures or compatibility impact.

### Commits

Use `type[(scope)][!]: description` with a specific imperative description.
Scope identifies a stable component. Existing types plus `style` are accepted.
A type or breaking marker never authorizes a version bump, support claim or release.

New AIDE-managed queue commits use **compact-v1**. The final trailer block
contains `Validation`, one or more `Changelog` entries, `AIDE-Task` and
`AIDE-Format`, separated from an informative body by a blank line.
Metadata keys are plain text. Indented continuation lines are allowed.
Optional `Risk`, `Follow-up`, `BREAKING CHANGE` and standard attributed trailers
belong there too. Never invent sign-offs, reviewers, results or task identities.

```text
fix(pack): load effort from the installed helper

Installed projects have no core tree. Resolve the import-owned helper
so the CLI works without the source checkout.

Validation: PASS - source checks; NOT RUN - installed recovery checks
Changelog: Fixed: Resolve effort through the installed helper
AIDE-Task: EXAMPLE-01
AIDE-Format: compact-v1
```

This is illustrative, not evidence those checks ran. Record actual named checks
with `PASS`, `WARN`, `FAIL` or `NOT RUN` and explain omissions. Mixed results
stay mixed; passing syntax checks do not establish product acceptance.

Changelog categories remain `Added`, `Changed`, `Fixed`, `Removed`, `Deprecated`,
`Security`, `Docs`, `Tests`, `Internal`, `Risks` and `Follow-up`. Repeat the
`Changelog` trailer for separate entries. Internal evidence-only work needs an
`Internal` entry, not an invented user feature. Categories are never inferred.

A `!` requires a nonempty `BREAKING CHANGE` (or `BREAKING-CHANGE`) explanation
of impact and migration. The parser retains the text; review establishes its
adequacy. Include recovery and remaining limitations when material.

Compact-v1 accepts a trailing suffix of blank lines and default Git `#` comments
after complete trailers. It retains the text and heading warnings; neither
reader nor hook edits the message. Other comment characters and verbose editor
diffs are unqualified. This rule is identical for drafts and committed messages.

Unknown formats, missing facts and ambiguous singleton metadata fail.
Length, trailing-period and H1/H2 findings are presentation warnings in compact
messages, avoiding a new cosmetic release blockade. Unmarked messages retain
their original v0 checks and historical disposition rules. No old failure is
converted to a pass. `commit template` supplies the new plain-text draft.

### Pull requests

Write for a reviewer who has not read the conversation. Start with the concrete
problem and resulting behavior. A Conventional Commit title is useful when the
project uses squash titles for release automation; GitHub does not require it.

- **Validation:** relevant checks/results, revision/environment when material,
  and unrun checks with reasons. Link full evidence.
- **Review focus:** important entry points, non-obvious decisions or requested
  feedback, only when useful.
- **Compatibility / risk:** material impact, migration, recovery and limitations.
- **References:** relevant task, issue or design.

These are information needs, not mandatory headings. Small PRs can use two
sentences and a short validation list. Rewrite the description when scope changes.
Check generated summaries against the actual diff and evidence. Use issue-closing
keywords only when merging fulfils the issue. Draft, green CI, approval, merge,
publication and downstream adoption remain distinct states.

### Merge and sync records

Identify the source/target and reviewed candidate, why integration is needed,
meaningful conflict resolutions and validation of the combined result.
A parent test does not automatically cover a conflict resolution.

Fast-forwarding creates no merge commit: retain the observed ref transition in
the existing integration receipt. Do not manufacture a commit for presentation.
New merge messages may use `chore(merge): ...` and an `Internal` integration
entry rather than repeat constituent user-facing changelog entries.
Existing automatic `Merge ...` history retains legacy handling. Message syntax
does not extend the single-parent managed-create command or change Git policy.

If a project chooses squash merging, describe the complete accepted result in
the final commit; review its metadata rather than concatenate interim messages
or copy the PR conversation. This is not permission to squash AIDE history.
After syncing, report observed remote commits and separately state whether work
reached `dev`, `main`, a release, and its consumer.

### Reviews and comments

Lead with the finding or decision. For actionable findings, name the trigger
and location, impact, evidence and smallest sufficient remedy. Label comments
**Required**, **Optional** or **Question** as appropriate. Discuss code respectfully.

Replies state the disposition and changed commit/check, or explain why the
finding does not apply. Blocker updates name the owner, missing condition,
preserved work and next action. Post when something changes. A review may find
no actionable issues. Existing machine-consumed review packets keep their schemas;
do not silently reformat their required fields into prose.

### Research basis

Checked 18 October 2026:
[Git messages](https://git-scm.com/docs/git-commit),
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/),
[Google descriptions](https://google.github.io/eng-practices/review/developer/cl-descriptions.html),
[GitHub PR guidance](https://docs.github.com/en/pull-requests/concepts/helping-others-review-your-changes),
[Google review comments](https://google.github.io/eng-practices/review/reviewer/comments.html),
[GitHub formatting](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax),
and [Git trailers](https://git-scm.com/docs/git-interpret-trailers).
Length targets and compact-v1 metadata are AIDE choices, not an externally
mandated or experimentally optimal template.

### Proportionate Historical Checks

The owner adopted presentation-only history as advisory on 2026-10-07.
`commit check --range` applies that rule only to commits proven ancestral to
the full immutable `historical_presentation_advisory_through` object in
`commit-messages.yaml`. Missing, malformed or unavailable boundaries stay
strict. Target repositories must adopt their own local boundary; AIDE's
source checkpoint is not a target decision.

The reviewed 18 October amendment advances the source cutoff from `143ed761`
to `dfae9356241dda6a03e2cc48cf9acb245c9a6be1`, under the existing standing
instruction. [The amendment](../../.aide/queue/AIDE-HISTORICAL-PRESENTATION-BOUNDARY-02/ExecPlan.md)
preserves the original cutoff and every failed observation in history.
This is a bounded policy adoption, not individual owner acceptance of messages.
The retained successor still requires separate integration and release checks;
missing changelog categories remain visible and are never invented.

The conservative syntax classifier permits missing bullets/trailers,
category formatting, outcome-label casing, subject length/trailing period
and separating whitespace only when all substantive sections contain text
and Validation states an outcome. Missing sections or outcomes, placeholders,
secret findings and unknown checks remain failures. Invalid registries and
explicit matching dispositions cannot be bypassed. This classification does
not establish that a description, changelog claim or test result is true;
their independent evidence and release checks remain required.

Qualifying entries report `PRESENTATION_ADVISORY`, the range reports
`PASS_WITH_WARNINGS`, and original strict failures remain visible. Raw mode
`--no-dispositions` disables both advisories and exact dispositions. No Git
object, parent, tree, message, release note or test result is rewritten.
Future commits, latest checks, message files and managed commit creation
remain strict. Correct a new draft's formatting before guarded creation when
its meaning is known; do not invent task ids, categories or PASS results to
satisfy the template. Harmless published presentation need not be repaired.

### Exact Historical Dispositions

Beyond presentation advisories, an immutable historical failure may be dispositioned only during a range
check and only through `.aide/git/commit-message-dispositions.json`. An
accepted record is bound to the full commit and tree object ids, ordered
parents, canonical message digest, exact checker failures, fixed narrow scope,
reviewer identity, review date, decision and evidence file digests, and a
digest of the record itself. Replacement objects are disabled while expanding
the range and reading commit messages.

Before any record can apply, the entire registry must be structurally valid
and have unique disposition and commit identities. Acceptance additionally
requires a content-hashed JSON decision whose exact disposition, commit, tree,
message, scope, decision, accountable reviewer, and date match the registry.
The reviewer must appear in the reviewed policy allowlist, and the date must
fall between the policy start and the current UTC date. A request for a
decision is not an acceptance decision.

Proposed, rejected, stale, incomplete, duplicate, wildcard, prefix, or
otherwise altered records have no effect. The original failed checks remain
visible under the `DISPOSITIONED` commit result, and the range result becomes
`PASS_WITH_DISPOSITIONS`; neither result claims the historical message passed.
Use `--no-dispositions` to reproduce raw range-policy failures. Latest-commit,
message-file, and hook checks never consume dispositions.

The general policy and schema are portable. This repository's decision
registry is source-specific and is excluded from exported packs so target
repositories cannot inherit AIDE's historical decisions.

### Portable Pack

Q31 and later pack exports include this policy, `.aide/hooks/commit-msg`,
`.aide/git/commit-template.md`, the commit checker commands, changelog preview
support, and the related reference docs through `aide-lite-pack-v0`. Imported
target repos receive the hook template but do not get `.git/hooks/commit-msg`;
hook installation remains an explicit target-repo operator action.

### Guarded Normal Local Commit

`commit create` invokes the strict checker directly, then checks the exact
message digest, current HEAD/ref, staged tree and finite declared staged paths.
It is a preview unless `--apply` is supplied. Run it only within the admitted
WorkUnit and reviewed local effect; the command does not grant task authority.

```powershell
py -3 .aide/scripts/aide_lite.py commit create --message-file <file> --expect-message-sha256 <sha256> --expect-ref <refs/heads/task/...> --expect-head <full-oid> --expect-tree <full-tree-oid> --path <staged-path>
# Add --apply only for the accepted exact local commit effect.
```

Prepare the message and intended staged tree once. A caller can obtain the
identities with `git rev-parse HEAD`, `git symbolic-ref HEAD`, `git write-tree`
and a SHA256 of the final message. Repeat `--path` for the explicit staged scope.
No staging, unstaging, body correction or scope widening occurs inside create.

Apply holds its own exclusive index lock against cooperating Git writers,
creates an unreferenced commit object, verifies its exact message/tree/ordered
single parent, rechecks the inputs, then prepares Git's dereferenced HEAD update
from the expected old id. Git holds HEAD and referent locks while AIDE verifies
the exact symbolic branch and staged inputs; only then is commit sent. Normal
HEAD and branch reflogs are preserved. Staged and
unstaged file bytes are preserved. New messages never consume dispositions.

The designed normal path requires an existing parent, Git support for the
explicit prepare/commit transaction, UTF-8 LF messages up to128KiB, index up to16MiB
and at most256 exact staged paths. Active commit/reference hooks, signing,
fsmonitor, Git redirection/config-file overrides, merge/rebase and unknown index locks
refuse specifically; they are not disabled or overwritten. Bounded runtime
`safe.directory` trust pairs are accepted and preserved; unsupported keys or
malformed count/pairs refuse. Each Git subprocess revalidates that environment.
The existing runner null-global/no-system pair is also accepted unchanged;
arbitrary or partial config-file isolation overrides refuse. Git2.53 Windows is
the current qualification target; other versions need their own evidence.

An invalid message cannot advance this managed branch. A later failed check
may leave an unreferenced candidate object: its id is returned for recovery.
`UNCERTAIN` preserves the observed effect and requires reconciliation; never
retry blindly or reset an advanced ref. An unknown ref-transaction outcome reports
`branch_advanced: null`, rather than claiming the branch stayed unchanged.
Existing/changed locks are preserved.
If the Git transaction child cannot be confirmed reaped, the owned index lock
also remains for explicit recovery. Lock retirement never assumes a failed kill
or wait stopped the child.
This path does not amend66, intercept unrestricted raw Git, constrain outer
editors/plugins or certify publication. It does not claim noncooperating raw
filesystem writers are confined by a Git index lock.

The current Windows qualification is recorded in
`.aide/queue/AIDE-MANAGED-COMMIT-CREATE-01/evidence/native-result-v7-passed.log`:
49 new actual Git/CLI cases and23 unchanged Q27 regressions passed with no skips,
including prepared HEAD/branch lock contention, both reflogs, changed-input
refusal, lost acknowledgements and authenticated fixture retirement. This is
source/worker evidence; the unchanged held archive does not contain the new path.
