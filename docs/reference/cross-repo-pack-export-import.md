# Cross-Repo Pack Export / Import v0

## Project customization and update explanation

These existing interfaces are included in the candidate stable Lite contract
in `.aide/policies/release-versioning.yaml`. Final delivered-byte qualification
and public compatibility activation remain open; the candidate list is not a
shipping claim. Explanation and optional local feedback use dry-run forms,
including predecessor updates and explicit conflict resolution.

The portable importer creates `.aide/profile.yaml` from a template on first
import. That file belongs to the project thereafter. A later pack preserves its
bytes. Other project-authored text outside the portable `AGENTS.md` section is
also preserved. If a managed file is edited outside AIDE and an incoming pack
changes it, import stops before payload writes and reports a conflict.
For an automatic update of unchanged AIDE-owned bytes, keep the exact previous
pack and pass it as `--from-pack <old-pack>` in both preview and apply. A local
receipt alone does not prove an overwrite baseline. If the old pack is absent,
the importer reports a conflict and preserves the existing bytes.

`import-pack --dry-run --explain` prints the ownership reason for preserved,
conflicting, and managed update operations. It does not guess why a project
made a change. A project may optionally write `.aide/customizations.json`:

```json
{
  "schema_version": "aide.project-customizations.v1",
  "entries": {
    ".aide/profile.yaml": {
      "observed_digest": "<sha256 of the current file bytes>",
      "rationale": "Keep our project adapter active."
    }
  }
}
```

The rationale is shown only while its digest matches the observed file. An
absent or stale rationale is `unknown`; the file grants no overwrite authority.
A syntactically valid v1 document with malformed advisory rationale fields
does not stop an ordinary import, but `--explain` refuses it. Invalid JSON
refuses import because its control schema cannot be classified. Malformed v2
controls also refuse import. No
customization metadata is created or sent automatically. A pack payload that
tries to supply `.aide/customizations.json` is refused, even when checksummed.
Windows case and trailing-dot aliases of that reserved path are refused too.

For an optional example tree, the project can use strict v2 controls. The
current admitted feature ID is `local_state_examples`, covering only
`.aide.local.example/`. Unknown or duplicate IDs refuse the import:

```json
{
  "schema_version": "aide.project-customizations.v2",
  "entries": {},
  "disabled_features": [
    {"feature_id": "local_state_examples", "rationale": "Our project maintains its own examples."}
  ]
}
```

Preview the change, then apply with its exact plan digest. Import records the
disabled ID and controls-file digest in a v2 receipt and leaves existing
example bytes untouched across later packs. If the controls file disappears or
becomes malformed, a subsequent import refuses to silently reenable the
feature. Reenable by explicitly removing its entry from a valid v2 file, then
review the new plan. The rationale is optional; missing rationale remains
`unknown`. This control does not disable core `.aide/` files.

For a conflict between a receipt-owned local edit and changed upstream bytes,
prepare a manually merged file outside both the target and packs. The importer
does not guess the merge. On Windows, use the exact predecessor pack named by
the receipt and run:

```text
py -3 -I -B <new-pack>/files/.aide/scripts/aide_lite.py --repo-root <target> import-pack --pack <new-pack> --from-pack <old-pack> --target <target> --resolve .aide/prompts/compact-task.md <merged-file> --dry-run --explain
py -3 -I -B <new-pack>/files/.aide/scripts/aide_lite.py --repo-root <target> import-pack --pack <new-pack> --from-pack <old-pack> --target <target> --resolve .aide/prompts/compact-task.md <merged-file> --expect-plan <preview-plan-digest>
```

The plan binds the predecessor identity, current receipt, local preimage,
incoming digest, merged-file digest, and controls digest. Apply rechecks those
inputs after recording its recovery intent and writes only the preflight-read
merged bytes. Its receipt distinguishes the installed project overlay from the
new upstream source, so a later changed pack requires a fresh resolution;
unchanged upstream preserves the overlay. A missing previously managed file is
a conflict, not an implicit reinstall. The resolution file path and raw bytes
are not stored in the intent or optional feedback. Rollback and owned-file
repair refuse overlays or skipped optional paths; removal preserves an overlay
and retains the partial receipt. Interrupted imports require exact intent
reconciliation before another update. This bounded apply path is available only
on Windows; release support requires separate delivered-artifact qualification.

To make a local packet that the project can review and share manually, add
`--feedback-out <new-path>` to a dry run. The new path must be outside the target
and every supplied pack, including `--from-pack`. The packet contains paths, digests, ownership decisions, and
any current recorded rationale; review it before sharing. This flag performs
no network, provider, or model call.
If a previous import has an unresolved recovery intent, a dry run reports
`RECOVERY_REQUIRED` without changing that intent or writing feedback. Use the
explicit recovery path before requesting a fresh update plan.

For a Windows import stopped after some payload writes, inspect the pending
intent and its `plan_digest`, preserve the target and both packs, and repeat
the exact original inputs with `--recover-partial --expect-plan <digest>`.
Include the same `--from-pack`, `--mode`, and each `--resolve` file used for the
interrupted update. An ordinary retry still refuses a partial state. The
explicit recovery verifies the saved full plan against the pack, predecessor,
receipt, project controls, resolution bytes, and every target preimage or
postimage before continuing. It refuses changed, linked, or unsafe files and
keeps the intent for inspection. Older partially applied intents without a full
plan snapshot require manual reconciliation. Completed or no-effect intents have
separate reconciliation/retirement paths that do not replay payload writes.
Partial continuation never takes a new update plan or
infers the reason for a project edit.
Final Windows publication holds existing controls and resolution files against
write or replacement. If controls are absent, a temporary exclusive filename
reservation prevents creation until intent retirement; Windows removes that
reservation on handle close or process exit. It does not create lasting
project customization metadata.

## Purpose

Q21 creates the first portable AIDE Lite Pack. Q25 repairs its integrity and
safe import scope. Q31 makes the pack carry the portable Q27-Q30 governance
surface. Q34 adds portable changelog/release-note preview support while keeping
generated source previews out of target truth. Q35 adds portable GitHub
protection and CI advisory policy while keeping source advisory reports out of
target truth. Q36 adds portable deterministic intent-compilation policy,
schemas, examples, tests, golden tasks, and docs while keeping source-generated
latest intent packets out of target truth. Q37 adds portable repo-intelligence
policies, schemas, tests, golden tasks, and docs while keeping source-generated
`.aide/repo/*.json` and latest repo-intelligence Markdown out of target truth.
Q38 adds portable file-quality policies, schemas, tests, golden tasks, commands,
and docs while keeping source-generated file-quality ledgers and reports out of
target truth. Q39 adds portable refactor-control policies, schemas, tests,
golden tasks, commands, and docs while keeping source-generated refactor
readiness and example plans out of target truth. Q40 adds portable root
recycling policies, schemas, tests, golden tasks, commands, and docs while
keeping source-generated root inventories, classifications, plans, exceptions,
and risk summaries out of target truth. Q41 adds portable existing-tool
absorption policies, schemas, tests, golden tasks, commands, and docs while
keeping source-generated tool inventories, classifications, wrap plans, adapter
maps, and risk summaries out of target truth. Q42 adds portable move-map,
salvage-map, path-alias, reference-rewrite, and migration-ledger policies,
schemas, tests, golden tasks, commands, and docs while keeping source-generated
current maps, alias plans, rewrite plans, draft ledgers, and validation reports
out of target truth. Q43 adds portable install observation, preservation,
ownership, conflict, migration, verification, and dry-run planning policies,
schemas, tests, golden tasks, commands, and docs while keeping
source-generated install observations, install plans, dry-run reports,
ownership-ledger examples, conflict reports, preservation reports, and
verification plans out of target truth. Q44 adds portable repair, repair-class,
repair-safety, repair-detection, repair-verification, and doctor policies,
schemas, tests, golden tasks, commands, and docs while keeping source-generated
repair observations, diagnoses, plans, dry-run reports, doctor repair reports,
and verification plans out of target truth. Q45 adds portable upgrade,
upgrade-compatibility, upgrade-preservation, upgrade-conflict, upgrade-migration,
and upgrade-verification policies, schemas, tests, golden tasks, commands, and
docs while keeping source-generated upgrade observations, comparisons, plans,
dry-run reports, conflict reports, migration reports, compatibility reports, and
verification plans out of target truth. Q46 adds portable rollback and uninstall
policies, schemas, tests, golden tasks, commands, and docs while keeping
source-generated rollback and uninstall observations, plans, dry-run reports,
and verification plans out of target truth. Q47 adds portable release-bundle
policies, schemas, commands, tests, golden tasks, and docs while keeping
source-generated `.aide/release/dist/**` archives and latest release reports out
of target truth. Q48 adds portable GitHub Release draft policies, schemas,
commands, tests, golden tasks, and docs while keeping source-generated release
drafts, asset lists, upload plans, checklists, and publication-boundary reports
out of target truth. The pack lets a target repository
receive AIDE Lite scripts, policies, prompts, templates, starter evals, and
no-call metadata without inheriting this AIDE repository's identity, queue
history, generated context, reports, local state, or secrets.

Q21 exists before the Eureka and Dominium pilots because direct manual copying
would be unsafe and noisy. Target repositories need their own profile, memory,
snapshot, index, task packet, verifier reports, token reports, and evidence.

## Portable Pack

The committed pack lives at:

```text
.aide/export/aide-lite-pack-v0/
```

Run the exporter from this repository root:

```bash
py -3 .aide/scripts/aide_lite.py export-pack --name aide-lite-pack-v0
```

The exporter writes:

- `manifest.yaml`
- `checksums.json`
- `README.md`
- `install.md`
- `import-policy.yaml`
- `export-report.md`
- `files/` with portable AIDE Lite content and target templates

The pack includes portable scripts, tests, token/context/verifier/review/ledger
policies, prompts, verification templates, target-neutral local-state examples,
starter golden tasks, no-call router/Gateway/provider metadata, and docs.
After Q35 it also includes portable commit-message policy, the opt-in commit
hook template, commit template, changelog policy/config/templates, changelog
preview/validate/status support, task resumption, WorkUnit and recovery policy,
generic Git workflow policy, branch roles, promotion/sync/prune policy, project
workflow profiles, dry-run Git helper policy, GitHub protection/branch
protection/CI gate advisory policies, intent compiler policy/schemas/examples,
repo intelligence policy/schemas/docs, file quality policy/schemas/docs,
refactor-control policy/schemas/docs, map/alias planning policy/schemas/docs,
install planning policy/schemas/docs, repair/doctor policy/schemas/docs,
rollback/uninstall policy/schemas/docs, release-bundle policy/schemas/docs,
GitHub release-draft policy/schemas/docs, and governance golden tasks.
The documentation-only `.aide.local.example/secrets/README.md` file is allowed
as a safe example so Q18 local-state validation and target imports agree on the
example tree shape; real `secrets/**` paths remain ignored and forbidden.

Q25 keeps optional broad roots in the export pack for reviewed fixtures but
makes command import safe by default. Q31 safe import still skips broad `core/`
roots and non-reference `docs/` roots, but it allows portable
`docs/reference/**` governance docs because target repos need the imported
commit, recovery, Git workflow, and GitHub/CI advisory references.

The pack excludes source repo identity, source queue history, source memory,
generated context, reports, controller ledgers, latest route/cache/Gateway or
provider status reports, eval runs, AIDE-specific Git workflow detection
outputs, latest helper plans, AIDE-specific dev/main branch policy and plan
artifacts, generated changelog previews and preview JSON, latest changelog
reports, source-generated latest intent packets and WorkUnit drafts,
source-generated repo intelligence indexes and summaries, source-generated
file-quality ledgers and reports, source-generated refactor readiness and
example plans, source-generated root and tool inventories/plans,
source-generated current move/salvage/path-alias/reference-rewrite maps,
migration ledger drafts, map validation reports, source-generated install
observations, install plans, dry-run reports, ownership-ledger examples,
conflict reports, preservation reports, verification plans, source-generated
release bundles, release validation reports, release provenance reports,
GitHub release drafts, release asset lists, upload plans, checklists,
publication-boundary reports,
`.aide.local/`, `.env`, raw prompts, raw responses, and provider credentials.

Pack checksums cover payload and static pack docs. Mutable metadata files
`manifest.yaml`, `checksums.json`, and `export-report.md` are intentionally
excluded from the checksum map so validation does not become self-inconsistent.
Payload tampering still fails `pack-status`, and pack validation also fails if
a payload file exists in the pack without a checksum entry.

`pack-status` validates provenance separately from checksums. A clean manifest
must match the current Git commit. If the exporter runs while the source tree is
dirty, the manifest records `source_dirty_state: true`; `pack-status` reports
that as `DIRTY_SOURCE_RECORDED` rather than treating it as a hidden clean pass.
Missing provenance, malformed dirty-state metadata, or stale clean provenance
fail validation.

## Import Dry Run

Use dry-run before writing to a target repository:

```bash
py -3 .aide/scripts/aide_lite.py import-pack --pack .aide/export/aide-lite-pack-v0 --target <target-repo> --dry-run
```

Dry-run validates checksums, reports exact planned writes, reports skipped
optional broad roots, reports conflicts, and writes nothing.

## Import

Use the same pack path without `--dry-run` to import:

```bash
py -3 .aide/scripts/aide_lite.py import-pack --pack .aide/export/aide-lite-pack-v0 --target <target-repo>
```

The default importer mode is `safe`. It copies portable `.aide/` files,
`.aide.local.example/`, target templates, managed `AGENTS.md` guidance, and
`.gitignore` local-state rules. It creates target-specific profile and memory
placeholders from templates when absent, preserves manual `AGENTS.md` content,
and ensures `.aide.local/` is ignored.

Use `--mode full` only in a reviewed local fixture when optional broad roots
such as `core/` and `docs/` are intentionally selected. Target pilots should
normally use safe mode and then generate target-local snapshot/index/pack
artifacts.

The importer does not create actual `.aide.local/`, does not overwrite existing
target files without reporting conflicts, and does not call providers, models,
network services, or Gateway forwarding paths.

## Bounded receipt-owned removal

On Windows, preview the receipt-owned paths with `plan-removal --target
<target-repo> --json`, then pass its exact `plan_digest` to `apply-removal
--target <target-repo> --expect-plan <digest>`. Apply takes the portable
lifecycle lock, records a target-local removal intent, and removes only regular
files whose bytes still match the validated import receipt. It checks and
deletes each file through the same anchored Windows handle. It can also remove
the entire `AGENTS.md` file when its bytes are exactly the scaffold generated
for a new project, with a receipt-matching managed block and no authored text.
For an authored `AGENTS.md`, it replaces the file through pinned Windows
handles with the exact receipt-owned managed block removed and every outside
byte preserved. A changed preview,
receipt, leaf, or parent path refuses the effect; an interruption leaves the
intent for exact-byte reconciliation on a repeated call with the same digest.

When every recorded managed path is removed by the reconciled operation, it deletes the
installed runner last, retires the exact receipt, and reports `DETACHED`.
An interruption after receipt retirement leaves the removal intent; rerun the
same command and plan digest from the extracted pack to reconcile it. Empty
directories and target-owned project state remain.

When any recorded bytes changed or were already absent, the command preserves
the remaining state, the runner, and the receipt, and reports
`PARTIAL_REMOVAL` (exit code 2). An
existing removal intent must be reconciled before import or a new removal
preview. Non-Windows removal apply fails closed until anchored equivalent
behavior is qualified.

## Target Initialization

After import, the target repository must generate its own local artifacts:

```bash
py -3 .aide/scripts/aide_lite.py doctor
py -3 .aide/scripts/aide_lite.py snapshot
py -3 .aide/scripts/aide_lite.py index
py -3 .aide/scripts/aide_lite.py repo inventory
py -3 .aide/scripts/aide_lite.py repo validate
py -3 .aide/scripts/aide_lite.py repo status
py -3 .aide/scripts/aide_lite.py quality ledger
py -3 .aide/scripts/aide_lite.py quality validate
py -3 .aide/scripts/aide_lite.py quality status
py -3 .aide/scripts/aide_lite.py refactor status
py -3 .aide/scripts/aide_lite.py refactor plan
py -3 .aide/scripts/aide_lite.py refactor validate
py -3 .aide/scripts/aide_lite.py refactor map
py -3 .aide/scripts/aide_lite.py refactor validate-map
py -3 .aide/scripts/aide_lite.py install observe
py -3 .aide/scripts/aide_lite.py install plan
py -3 .aide/scripts/aide_lite.py install dry-run
py -3 .aide/scripts/aide_lite.py install validate
py -3 .aide/scripts/aide_lite.py pack --task "<target task>"
```

Target maintainers must replace placeholder profile and memory text with
target-specific facts before treating the pack as project-aware.

After Q34, target maintainers can also validate the imported governance surface:

```bash
py -3 .aide/scripts/aide_lite.py commit template
py -3 .aide/scripts/aide_lite.py commit check --message-file <message-file>
py -3 .aide/scripts/aide_lite.py changelog preview
py -3 .aide/scripts/aide_lite.py changelog validate
py -3 .aide/scripts/aide_lite.py task inspect
py -3 .aide/scripts/aide_lite.py git policy
py -3 .aide/scripts/aide_lite.py git detect
py -3 .aide/scripts/aide_lite.py git plan
py -3 .aide/scripts/aide_lite.py intent compile --prompt "<target task>"
py -3 .aide/scripts/aide_lite.py intent validate
py -3 .aide/scripts/aide_lite.py repo explain-file .aide/scripts/aide_lite.py
py -3 .aide/scripts/aide_lite.py refactor dry-run
py -3 .aide/scripts/aide_lite.py refactor map-status
py -3 .aide/scripts/aide_lite.py install status
py -3 .aide/scripts/aide_lite.py install conflicts
py -3 .aide/scripts/aide_lite.py install ownership
py -3 .aide/scripts/aide_lite.py upgrade status
py -3 .aide/scripts/aide_lite.py rollback status
py -3 .aide/scripts/aide_lite.py uninstall status
py -3 .aide/scripts/aide_lite.py release status
py -3 .aide/scripts/aide_lite.py release draft-status
```

The hook template is imported under `.aide/hooks/commit-msg`, but it is not
installed into `.git/hooks`. Hook installation remains an explicit target-repo
operator action through `commit install-hook`.

## Boundary

### Restore one missing portable managed file

An installed safe-mode consumer can restore one missing file recorded as `managed_file` in its import receipt. Use the same extracted, checksum-valid pack whose exact identity appears in the receipt:

```text
py -3 -I -B <pack>/files/.aide/scripts/aide_lite.py --repo-root <target> repair-owned-file --pack <pack> --target <target> --path .aide/prompts/compact-task.md --dry-run
py -3 -I -B <pack>/files/.aide/scripts/aide_lite.py --repo-root <target> repair-owned-file --pack <pack> --target <target> --path .aide/prompts/compact-task.md --expect-plan <preview-plan-digest>
```

The preview checks pack checksums, exact receipt and source digests, safe-mode ownership, and a missing target. Apply requires its exact plan digest. An existing file, local edit, unknown receipt entry, different pack, pending import intent, or stale plan refuses the write. A target-local repair intent records a write before it occurs. On Windows, repair holds non-renamable directory handles for every path component, rejects reparse points, stages complete bytes, and publishes through a handle-relative no-clobber hard link. A competing file or parent substitution cannot redirect that publication. Repair cleanup opens the intent beneath pinned ancestors without following reparse points, verifies its exact bytes and regular single-link identity, and deletes through that same handle. A changed or redirected intent remains untouched. Every effectful import, including a first install, and repair acquire a per-target lifecycle guard before preflight or intent changes. Windows uses a named kernel mutex that leaves no target lock file; POSIX import uses a private persistent temporary lock file whose advisory lock is released on process exit. Rerunning the exact apply after interruption verifies a completed postimage or retries a missing preimage; unknown bytes remain blocked. A dry-run leaves the target unchanged. Repair apply fails closed on non-Windows platforms until equivalent anchored path operations are implemented. The importer’s separate intent cleanup remains outside this repair guarantee. The repair command does not restore managed sections, target-owned templates, modified files, or multiple paths.

An installed Windows consumer can inspect its receipt-owned files without the development checkout:

```bash
py -3 -I -B <pack>/files/.aide/scripts/aide_lite.py --repo-root <target> repair-health --pack <pack> --target <target> --json
```

The read-only report identifies matching, missing, changed and unknown paths, pending import/repair/removal intents, and receipt v1/v2 overlays or disabled features. It checks each receipt row against the validated current pack's source digest and admitted source-to-target mapping before calling a row matching or repairable. A re-digested receipt cannot relabel a directly edited file or an authored file as healthy AIDE-owned content. Only a missing, safe-mode, receipt-owned managed file with a successful exact-pack `repair-owned-file --dry-run` receives a repair plan digest. Changed files, hard links, unsafe paths, managed sections and project overlays are preserved. A pending intent requires recovery before new repair eligibility. Project overlay rationale remains unknown unless the project records it. The report is a snapshot, not authority for an effect: apply rechecks the pack, receipt, path and plan. Inspection itself is limited to Windows anchored handles; other platforms report `UNSAFE_TARGET` until equivalent observation is qualified.

### Return to an exact predecessor portable pack

For a completed safe-mode update whose receipt names both the current pack and
its predecessor, a Windows consumer can preview and apply an exact return to
the predecessor:

```text
py -3 -I -B <current-pack>/files/.aide/scripts/aide_lite.py --repo-root <target> rollback-pack --current-pack <current-pack> --previous-pack <previous-pack> --target <target> --dry-run --json
py -3 -I -B <current-pack>/files/.aide/scripts/aide_lite.py --repo-root <target> rollback-pack --current-pack <current-pack> --previous-pack <previous-pack> --target <target> --expect-plan <preview-plan-digest> --json
```

Both packs must pass checksum validation and have the same safe payload path
set. The receipt must bind their exact manifest and checksum identities, and
its managed baselines must match the current pack. Changed receipt-owned
bytes, a local edit to the managed `AGENTS.md` section, or a changed preview
refuses the rollback before new writes. Project-owned templates and authored
content outside the managed section stay intact. The existing importer intent
records the effect; an interrupted or uncertain transaction remains
`RECOVERY_REQUIRED` and is not silently replayed by an ordinary rollback.
For an exact partial rollback intent, repeat the read-only preview. Its
`recovery_plan_digest` is the saved import-intent digest, distinct from the
original rollback preview digest. After preserving the target and both packs,
continue explicitly with the same pair:

```text
py -3 -I -B <current-pack>/files/.aide/scripts/aide_lite.py --repo-root <target> rollback-pack --current-pack <current-pack> --previous-pack <previous-pack> --target <target> --recover-partial --expect-plan <recovery-plan-digest> --json
```

This uses the existing guarded importer recovery, refuses the reverse pack
direction, changed bytes or an unknown intent, and reports
`ROLLED_BACK_RECOVERED` only after the receipt and intent reconcile. Completed
and no-effect interruption states continue through the existing exact importer
reconciliation path; this option is only for a partial rollback.
This narrow path cannot restore arbitrary prior bytes without the exact
predecessor pack or resolve additions and removals between pack payload sets.
Apply fails closed outside Windows until equivalent anchored effects qualify.

The portable pack is metadata and tooling, not proof that AIDE reduces tokens in
the target. Q22 Eureka Import Pilot and Q23 Dominium Import Pilot must measure:

- prompt-size reduction from compact task/context/review packets
- quality preservation through verifier and golden tasks
- local-state and secret safety
- target-specific usefulness

The Existing Tool Adapter Compiler remains deferred until those pilots prove
the pack is useful outside this repository.

Q22 and Q23 produced initial Eureka and Dominium token-reduction evidence. Q25
repairs pack integrity and import scope before Q26 performs the Eureka handover
review. Q31 makes the canonical pack ready for Q32 Eureka sync and Q33 Dominium
sync; Q34 extends the pack with release draft previews; Q37 extends the pack
with repo intelligence support; Q38 extends it with advisory file-quality
ledger support; Q39 extends it with no-apply refactor-control planning support;
Q40 extends it with no-apply root recycling framework support; Q41 extends it
with no-execution existing-tool absorption support; Q42 extends it with
candidate move/salvage/path-alias/reference-rewrite map support; Q43 extends
it with no-apply install observation, preservation, ownership, conflict,
migration, verification, and dry-run planning support; Q44 extends it with
no-apply repair observation, diagnosis, repair planning, dry-run, doctor
reporting, and repair verification support; Q45 extends it with no-apply
upgrade observation, source-pack comparison, candidate upgrade planning,
dry-run, conflict, migration, compatibility, and verification support; Q46
extends it with no-apply rollback and uninstall observation, ownership-evidence
planning, dry-run, preservation boundaries, and verification support; Q47
extends the source repository with local release-bundle generation for the pack
itself; Q48 extends the source repository with local GitHub Release draft
generation from those bundle artifacts. Target repositories must not treat
AIDE-source release outputs as target truth.
Those target phases must regenerate their own branch detection, helper plans,
repo intelligence indexes, file-quality ledgers, refactor readiness plans, root
inventories, root classifications, root plans, tool inventories, tool wrap
plans, current maps, alias plans, rewrite plans, context packets, review
packets, install observations, install plans, install dry-run reports,
conflict reports, ownership ledgers, preservation reports, verification plans,
repair observations, repair diagnoses, repair plans, repair dry-run reports,
doctor repair reports, repair verification plans, upgrade observations,
upgrade comparisons, upgrade plans, upgrade dry-run reports, upgrade conflict
reports, upgrade migration reports, upgrade compatibility reports, upgrade
verification plans, rollback observations, rollback plans, rollback dry-run
reports, rollback verification plans, uninstall observations, uninstall plans,
uninstall dry-run reports, uninstall verification plans, GitHub release drafts,
asset lists, upload plans, checklists, publication-boundary reports, and
evidence locally; they must not reuse AIDE's generated source-repo reports,
release-bundle outputs, or release-draft outputs as target truth.
