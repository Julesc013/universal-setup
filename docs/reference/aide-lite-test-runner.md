# AIDE Lite Test Runner

## Purpose

QFIX-02 makes AIDE Lite validation boring on purpose. Future agents should not
need to remember Python `unittest` import rules for a hidden `.aide/` directory
before they can trust the token-survival substrate.

## Portable Lite command

Run this from the repository root:

```bash
py -3 .aide/scripts/aide_lite.py test
```

Use `python` or `python3` only when the Windows launcher is unavailable.

The command runs the existing internal AIDE Lite selftest checks, prints
PASS/FAIL output, returns nonzero on failure, writes no committed repo state,
and makes no provider, model, or network calls.

`selftest` remains supported:

```bash
py -3 .aide/scripts/aide_lite.py selftest
```

## Maintainer resource admission

Campaign builds, packaging and external unittest processes use the explicit
maintainer job path. This reuses AIDE's Windows Job process owner; it does not
activate the autonomous broker or replace the metadata-only TestJob contract.
`git detect`, `git plan` and `task status` inspect current state without rewriting
tracked reports by default. Their `--write-reports` option explicitly invokes
the existing report generators when a projection is required.
In the AIDE source checkout, `test`, `selftest` and `eval run` require this
admission. The child proves membership in the exact named Windows Job and
rechecks the source/CLI input manifest. Setting temporary-directory environment
variables alone cannot satisfy the guard. Extracted Lite carries that same
Windows owner for explicitly configured jobs, while its portable no-model
`test` and `selftest` remain usable without source-checkout admission after
the extracted pack's manifest and payload checksums validate. A source checkout
with a missing queue index refuses admission rather than bypassing it. The
exported pack does not include the source checkout's self-hosting queue or
copy `core/**` into a target through safe import.

```powershell
py -3 .aide/scripts/aide_lite.py job setup --config <checkout>/.aide.local/execution.json --selection <local-selection-json> --approved-parent <owner-selected-existing-parent>
py -3 .aide/scripts/aide_lite.py job inspect --config <local-config> --manifest <job-json>
py -3 .aide/scripts/aide_lite.py job run --config <local-config> --manifest <job-json>
py -3 .aide/scripts/aide_lite.py job recover --config <local-config>
py -3 .aide/scripts/aide_lite.py job wait --config <local-config> --job-id <exact-id> --manifest-digest <exact-digest>
py -3 .aide/scripts/aide_lite.py job usage --stream <codex-exec-jsonl>
py -3 .aide/scripts/aide_lite.py job usage --attempt-set <attempt-roster-json>
codex debug prompt-input | py -3 .aide/scripts/aide_lite.py job context
```

`job run` waits in deterministic code and normally prints one bounded terminal
view; `--full` prints its detailed result for consumers that need it. The full
receipt and logs remain under the configured retained root. Portable Lite
`job wait` can attach to that exact job without importing the runner,
submitting work, changing reservations or emitting healthy progress
ticks. It returns `PENDING` on timeout and never treats a missing or malformed
receipt as success. `job setup`, `job inspect` and `job run` in extracted Lite
use the shipped Windows owner and require an explicit local configuration,
finite limits and a source-bound Git working root. They do not activate a
model or grant authority to modify a target repository. The view reports the
number of observations and unchanged observations, a retained receipt locator
and hash, and the exact source. Its
`model_requests_started_by_observer: 0` describes this CLI only; host model
requests and internal inference remain unknown until a supported host adapter
measures them. The observer does not verify all retained output bytes.

Portable `job usage` imports one to eight ordinary Codex `exec --json` files
without launching a model or printing raw event content. Each stream is bounded
to 16 MiB and each event line to 1 MiB. Exact duplicate streams and repeated
identical terminal events count once only when one `turn.started` bounds the
stream. Missing or multiple turn starts, failed turns, absent usage fields, unknown
usage keys and multiple distinct streams for the same session remain explicit
coverage gaps: incomplete totals are `null`, while observed known subtotals
remain visible. The JSONL format reports completed turns, not the number of
internal model requests, model identity or usage from unmediated Codex/Work
sessions. The input files remain with their existing custodian; this command
writes no ledger or copy of raw prompts and responses.

`--attempt-set` attributes one to eight supplied streams by `parent`, `child`,
`review`, `retry`, `repair` or `overhead` role. Its bounded JSON file uses schema
`aide.codex-exec-attempt-roster.v1`, a short `work_id`, and an `attempts` array.
Each attempt supplies a unique `attempt_id`, `role`, `parent_attempt_id`, a
relative `stream` path under the roster directory, and its lowercase SHA-256
`stream_sha256`. The one parent has a null parent ID. A missing stream uses null
for both stream fields and remains an explicit gap. The command checks links,
digests, path containment and duplicate streams before reporting role known
subtotals. It never prints the stream paths or raw events. A supplied roster
cannot prove that it includes every attempt, so work totals, work outcome and
internal model requests remain unknown and the attributed result is always
`PARTIAL`. Same-session streams with uncertain turn identity suppress known
subtotals rather than risk double counting.

Portable `job context` accepts one Codex `debug prompt-input` JSON stream on
stdin, capped at 2 MiB. It reports message/part counts and visible text sizes
by role without printing or retaining the supplied text. Unknown roles and
non-text parts remain explicit coverage gaps. The parser starts no model turn;
the producer command and its permissions are separate. Its byte counts are not
token counts, and the debugger view does not establish tool-definition size,
internal inference or the effective context of an existing long-lived thread.

Inspection only reads state. The machine-local configuration belongs in the
existing `.aide.local/` boundary; `.aide.local.example/execution.json` contains
placeholders and finite example limits, not an approved machine placement.
`job setup` takes an explicit local selection using those same root, working
root and limit fields. It verifies an existing owner-selected parent, creates
only the selected missing storage children, observes their volume IDs and
capacity, then writes each checkout's local config once. A matching config is
an unchanged success. A changed config, redirected path, nonempty unowned
storage or unavailable capacity is refused without selecting another drive.
Two existing checkouts can share populated roots when the first already has
the same validated configuration. Setup does not change global settings.
`git detect` and `git plan` also inspect without writing by default; their
existing tracked report projections require explicit `--write-reports`.
All three storage roots must exist and match their declared volume identities
before `job inspect` or `job run` admits work. Missing/unavailable storage
refuses admission without fallback.
All campaign workspaces must share one control root; its OS lock serializes
heavy jobs and their disk/memory reservations. This is not a global quota for
unmanaged tools or for jobs configured with another control root.

Job JSON identifies owner, WorkUnit, exact source commit/tree, input/oracle
file SHA-256 values, absolute executable/digest, `cwd`, literal `argv`, and
`adapter: python`, under schema `aide.maintainer-job.v1`. Module and script
commands are supported. Python temporary creation is pinned to the admitted
temporary directory; output belongs in `AIDE_JOB_OUTPUT` and caches in the
provided process-local cache variables. Additional tool adapters require
qualification of their actual output/cache placement before admission.
For the explicit `codex_exec` adapter, the same control record retains a
bounded fingerprint for every admitted request. It binds the working-root
filesystem identity, source commit/tree, declared input content hashes,
prompt/schema roles, executable hash, model and effort. Windows case, slash
and short-name aliases of the same file cannot create a new fingerprint;
duplicate aliases within one Codex input manifest are refused. A filesystem
that cannot supply stable file identity refuses this adapter. Changing only
an owner label does not permit another turn. An exact repeat is
refused before scratch allocation, including after a failed or interrupted
host attempt whose effect remains uncertain. A new bound input or model/effort
choice still requires matching local permission and available turn budget.
Older positive-count dispatch records without request identities refuse new
Codex admission until reconciled. This guards only turns launched through
this owner; it does not intercept unmediated Codex or internal host inference.
Source `export-pack` requires its export output root. `release stable-build`
and `release stable-validate` require only `.aide/release`; their export pack
is a read-only input. Other commands using the shared packaging guard still
require both existing canonical output roots, with their actual volume IDs and
finite byte reservations. Evaluation requires its existing runs destination.
Default source-checkout `changelog preview` also requires a managed job with
`.aide/changelog` declared as a finite canonical output. It refuses a direct
unadmitted source run before writing. An alternate `--output-dir` in the source
checkout is refused; extracted Lite and fixture repositories retain their
explicit output-directory behavior. This keeps the current release preview
inside the same reservation and retirement boundary as its later bundle.
For example, a packaging manifest adds:

```json
"canonical_outputs": {
  ".aide/export/aide-lite-pack-v0": {"volume_id": "ACTUAL_VOLUME_GUID", "bytes": 134217728},
  ".aide/release": {"volume_id": "ACTUAL_VOLUME_GUID", "bytes": 134217728}
}
```

Their combined budgets must fit the local `canonical_bytes` allowance (example:
512 MiB). Missing roots, unknown destinations, aliases, wrong volumes or absent
allowance refuse admission without creating a replacement. Reservations include
canonical and scratch/collection peaks on each affected volume. OS disk sampling
covers those volumes; bounded canonical metadata checks run at admission, every
thirty seconds and completion. A quick overrun still fails the job. These source
outputs remain in their established locations and are never scratch-retirement
targets. Packaging qualification and final byte/replay checks remain required.

Memory, descendant count and combined logs have Windows Job/pipe enforcement.
Disk capacity and occupancy are monitored thresholds, not filesystem quotas
or a security sandbox. OS disk/memory counters are sampled once per second;
only owned scratch metadata is counted every 30 seconds. A short transient
may exceed the occupancy threshold between samples. Logs are truncated at the
configured byte limit and the attempt fails explicitly.

The runner persists named Job identity, process creation identity, command,
input/environment digests, limits, capacity and peaks. The Job kills owned
descendants if its controller exits. Normal/cancelled runs retain output and
bounded logs once, then remove only their ownership-marked temporary/cache
tree and release the reservation. Interrupted runs require `job recover`;
unknown aliases, changed configuration or a partial conflicting collection
remain preserved and reported for reconciliation. Neither process IDs nor
directory age authorize deletion.

### Live scratch observation and strict collection

A live scan may encounter a regular, non-reparse file with zero links while
its owner deletes it. It reobserves that metadata at most twice, with5 ms waits.
Confirmed absence is omitted; surviving fresh metadata must pass the existing
type/link, byte and file-count checks. Persistent zero links, reparse metadata,
outside hardlinks and observation errors still refuse. Strict quiescent result
collection does not retry or accept zero-link files. The source60 regressions
and an unchanged real partial-import CLI task qualified this boundary in the
[resource WorkUnit](../../.aide/queue/AIDE-CAMPAIGN-RESOURCE-CLEANUP-01/REPORT.md).
Disk monitoring remains separate from a hard filesystem quota.

## Scoped repository-check worker entry

`job run --config <local-config> --manifest <job>` can explicitly select an
`execution_host` with schema `aide.scoped-host.local.v1`, kind
`codex_sandbox_readonly`, exact `codex_executable`/`codex_sha256`, approved
toolchain `read_roots`, finite `aggregate_bytes`, and a `runtime` object with
repository-relative `root` and exact dependency `files` SHA-256 map. The pinned
owner must be an already accepted export; a changed source checkout does not
become its own supervisor. Keep this selection in ignored operator-local state.
Alternatively `runtime` may name a repository-relative accepted `archive`, its
exact `sha256`, member `prefix` and member `files` hashes. The ZIP loads directly
without extraction, allowing affected exports to be refreshed while keeping
the trusted archive intact. Kind `codex_sandbox_checks` may additionally declare
an exact `canonical_outputs` allowlist from the owner's existing supported
destinations. Job declarations still require finite bytes and matching volumes.
Any destination overlapping the supervising runtime is refused. A readonly
selection cannot grant canonical writes.

No host or machine defaults are changed. Setup does not infer this selection.

The public entry refuses unpinned runtime source/bytecode, changed executables,
already imported execution code and unsupported workloads. It currently
supports Python repository checks and explicitly admitted canonical generation,
without model calls. The worker can write its owned tmp/cache/output directories
and exact declared canonical destinations only. The exact
active receipt is readable for the existing job guard; control/config and
trusted runtime writes are excluded. Full logs and effective scope are retained
by the same owner, followed by normal scratch retirement and recovery.

Aggregate admission inventories scratch (including cache), retained logs/results
and control bytes plus declared canonical artifacts, and reserves the next
attempt inside the existing estate lock
before allocation. Incomplete observations or insufficient budget refuse launch
without a fallback root. Existing disk checks monitor growth; this is not a hard
filesystem quota. Source is readonly apart from declared artifacts; external caches,
other pools and unmanaged tools are outside its budget.

Installed Codex 0.145.0 qualified worker write/process boundaries but failed
read exclusion in AIDE's local qualification. Read isolation remains unqualified.
This option does not constrain an unrestricted outer shell/editor, plugins,
other sessions or GitHub integration and must not be called whole-session
containment. Qualification evidence is in the session-containment and
scoped-job-entry queue items.

### Inspection boundary diagnostics

Successful `job inspect` retains its existing resource/dispatch fields and adds
`execution_boundary`, bound to the same configuration digest. An explicit scoped
selection reports its configured command sandbox, canonical allowlist, read-root
count and aggregate ceiling. Legacy selection reports that Windows Job resources
do not enforce filesystem placement.

This is configuration evidence. Inspection does not run the locked aggregate
inventory, verify filesystem behavior or establish read isolation. Aggregate
admission happens under the owner lock during `job run`; disk growth remains
monitored and no hard filesystem quota is supplied by this mechanism.

Outer-session containment remains `unobserved`: the job does not control the
outer shell, editing/filesystem tools, plugins/integrations, other sessions or
unmanaged processes and external host metadata/caches. A configured worker is
therefore not a whole-session qualification. Existing exact route observations
remain necessary and may include failures.

The scoped diagnostic uses the envelope captured by the prepared host, rather
than the earlier command read. A digest mismatch refuses inspection without a
fallback or allocation. A selected older scoped adapter without this metadata
interface also refuses cleanly; no cross-version operation is inferred. A refusal
remains `REFUSED` with `writes: false`; it does
not acquire a successful boundary report. Unknown local configuration fields and
their values are not projected. This addition grants no new writes, permissions,
model requests, setup operations or automatic retries.

## Raw unittest discovery

The supported raw unittest discovery command is:

```bash
py -3 -m unittest discover -s .aide/scripts/tests
```

QFIX-02 verified this command passes.

## Non-Canonical Command

Do not use:

```bash
py -3 -m unittest discover -s .aide/scripts/tests -t .
```

With `-t .`, `unittest` requires `.aide/scripts/tests` to be importable as a
package path from the repo root. `.aide/` is a hidden committed contract
directory, not a Python package namespace, so that form fails before loading
tests. Adding `__init__.py` files would not be the right fix because it would
blur the `.aide/` contract boundary.

## Cross-Repo Implication

Q21 Cross-Repo Pack Export / Import v0 can now rely on one obvious local command
when evaluating copied AIDE Lite packs:

```bash
py -3 .aide/scripts/aide_lite.py test
```

The command is stdlib-only and no-call, so it is safe to run before any future
Gateway/provider/runtime work.

### Public archive fixtures under the scoped Windows worker

Public archive projection/extraction and selected release-test fixtures use
`public_archive_fixture` inside the authenticated job TMP. These newly created
ordinary directories inherit the existing allocated parent permissions, so the
separate controller can measure and retire their public bytes. This avoids the
Windows Python private-temp/controller mismatch demonstrated in job46e91fbf.
No ACL setter, global tempfile replacement, new pool or larger resource allowance
is involved. Unmanaged and unrelated temporary directories retain stdlib private
behavior. A forged context, outside TMP or unknown fixture namespace refuses
before allocation. Changed directory identities and shared/redirected entries
refuse cleanup and preserve the material; ordinary read-only file flags in
Git test fixtures can be cleared only on verified files within that fixture.

Qualification is limited to these exercised public fixture routes. A tool that
creates other private output can still cause a monitored job to stop and require
owned recovery. Whole-client containment and a hard filesystem quota remain
unqualified. Native measurement, affected checks and retirement evidence must
be recorded before calling this repair qualified.
