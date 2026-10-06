# Commit Discipline

Q27 defines AIDE's changelog-ready commit standard. New AIDE-managed queue work
uses:

```text
type(scope): summary
```

Subjects must be specific, 72 characters or fewer, and must not end with a
period. Substantive commits require these Markdown body sections:

- `## Summary`
- `## Why`
- `## Changed`
- `## Validation`
- `## Changelog`
- `## Risks`
- `## Follow-up`

Run:

```powershell
py -3 .aide/scripts/aide_lite.py commit check --latest
py -3 .aide/scripts/aide_lite.py commit check --range HEAD~5..HEAD
py -3 .aide/scripts/aide_lite.py commit check --range HEAD~5..HEAD --no-dispositions
py -3 .aide/scripts/aide_lite.py commit template
```

The optional hook is installed only when explicitly requested:

```powershell
py -3 .aide/scripts/aide_lite.py commit install-hook
```

Q27 does not rewrite old commits. Q34 reports malformed history and consumes
the structured body categories and AIDE trailers through `changelog preview`,
`changelog validate`, and `changelog status` to produce preview-only release
drafts.

## Exact Historical Dispositions

An immutable historical failure may be dispositioned only during a range
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

## Portable Pack

Q31 and later pack exports include this policy, `.aide/hooks/commit-msg`,
`.aide/git/commit-template.md`, the commit checker commands, changelog preview
support, and the related reference docs through `aide-lite-pack-v0`. Imported
target repos receive the hook template but do not get `.git/hooks/commit-msg`;
hook installation remains an explicit target-repo operator action.

## Guarded Normal Local Commit

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
