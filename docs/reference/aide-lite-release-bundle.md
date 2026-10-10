# AIDE Lite Release Bundle

Q47 defines how AIDE turns the validated portable AIDE Lite Pack into local
downloadable archives. It is deterministic, local, no-call, and publication-free.

Q47 does not create Git tags, create GitHub Releases, upload artifacts, publish
packages, mutate branches, install CI, install AIDE into target repositories, or
apply install, repair, upgrade, rollback, or uninstall actions.

## Lifecycle

The local release-bundle lifecycle is:

1. validate source repository
2. regenerate the export pack
3. validate `pack-status`
4. build local archives
5. bind changelog and release-note previews to the exported source revision
6. compute checksums
7. write and validate the exact asset index
8. extract archives into fixtures
9. validate archive contents and forbidden-path exclusions
10. write evidence
11. review
12. GitHub release draft review
13. future publish

Q47 implements local generation and validation only.

## Commands

```text
py -3 .aide/scripts/aide_lite.py release bundle
py -3 .aide/scripts/aide_lite.py release validate
py -3 .aide/scripts/aide_lite.py release status
py -3 .aide/scripts/aide_lite.py release assets
py -3 .aide/scripts/aide_lite.py release manifest
py -3 .aide/scripts/aide_lite.py release checksums
py -3 .aide/scripts/aide_lite.py release provenance
py -3 .aide/scripts/aide_lite.py release clean --dry-run
```

`release clean` is dry-run only in Q47. It lists generated release artifacts
that a future cleanup phase could remove, but deletes nothing.

Q48 consumes the generated bundle with:

```text
py -3 .aide/scripts/aide_lite.py release draft
py -3 .aide/scripts/aide_lite.py release draft-validate
py -3 .aide/scripts/aide_lite.py release draft-status
py -3 .aide/scripts/aide_lite.py release upload-plan
py -3 .aide/scripts/aide_lite.py release checklist
py -3 .aide/scripts/aide_lite.py release publication-boundary
```

Those commands generate review material only. They do not create tags, call
GitHub APIs, upload assets, or publish releases.

## Separate First-Stable Candidate

The bounded release-effect WorkUnit adds a separate candidate path. From a
clean source checkout with a validated, clean-provenance export pack, run the
commands through the owner-configured managed D runner:

```text
py -3 -B .aide/scripts/aide_lite.py release stable-build --version 1.0.0
py -3 -B .aide/scripts/aide_lite.py release stable-validate --version 1.0.0
```

`stable-build` permits only the conditional first stable `1.0.0` candidate;
the actual version still depends on fresh tag/release history at freeze. It
does not decide whether to publish. The command writes versioned ZIP/tar,
an immutable asset manifest and SHA256SUMS under `.aide/release/stable/`,
leaving Q47/Q48 `dist/` previews untouched. Each archive retains the portable
pack root and adds `stable-release.json` with version, profile, source commit
and tree, public CLI forms and version-policy digest. Its pack checksums cover
the marker. Validation checks archive safety and member identity before any
extraction; it rejects nonregular, escaping or oversized members.

These files are frozen **candidate bytes**, not evidence of publication.
The final supported Windows environment, warning disposition, consumer
qualification, independent release `ACCEPT`, main/tag/publication and
downloaded-byte verification belong to the separate release-effect record.
Do not upload the Q47/Q48 preview metadata as stable release evidence.

## Artifact Layout

Release artifacts are written under:

```text
.aide/release/dist/
```

The generated local bundle includes:

- `aide-lite-pack-v0.zip`
- `aide-lite-pack-v0.tar.gz`
- `aide-lite-pack-v0.checksums.json`
- `SHA256SUMS.txt`
- `manifest.yaml`
- `install.md`
- `CHANGELOG.preview.md`
- `RELEASE_NOTES.preview.md`
- `release-validation.json`
- `release-validation.md`
- `release-provenance.json`
- `release-assets.json`

Q47 also writes latest source-repo evidence:

- `.aide/release/latest-release-bundle.json`
- `.aide/release/latest-release-bundle.md`
- `.aide/release/latest-release-artifacts.json`
- `.aide/release/latest-release-validation.md`
- `.aide/release/latest-release-provenance.md`

These files are local evidence. They are not official release notes, not a
GitHub Release, and not target-repository truth.

Q48 additionally writes local GitHub Release draft evidence under
`.aide/release/github-release-*` and
`.aide/release/latest-github-release-draft.*`. Those files are also source-repo
review material, not target-repository truth.

## Archive Contents

Archives are built from `.aide/export/aide-lite-pack-v0/` with the stable root:

```text
aide-lite-pack-v0/
```

The archive includes pack files such as `manifest.yaml`, `checksums.json`,
`import-policy.yaml`, `install.md`, `export-report.md`, and `files/**`.
Release-level metadata such as install notes, checksum summaries, provenance,
validation, changelog preview, and release-note preview may also be included.

Archives must not include `.git/`, `.aide.local/`, `.env`, `secrets/**`, raw
prompt or response logs, source repo queue history outside the pack payload, or
source-generated target state as install truth.

## Checksum Validation

`release bundle` writes `aide-lite-pack-v0.checksums.json` and
`SHA256SUMS.txt`. `release checksums` recomputes the recorded artifact hashes
and fails if any recorded artifact is missing or mismatched, or if either file
contains a stale or incomplete artifact set. `release-assets.json` is validated
separately against every indexed file's final SHA-256 and byte size. The asset
index and validation reports are excluded from their own dependency sets so
the metadata graph has no self-reference.

Release identity and provenance come from the validated export-pack manifest,
not the local checkout path or task-branch name. Equivalent pack inputs in
different directories therefore produce the same provenance and bundle
metadata.

The changelog and release-note copies must identify the exported source commit.
A preview generated at its immediate parent is accepted only when the intervening
commit changes preview outputs and nothing else. Missing or stale previews are
replaced with explicit `blocked_stale_source_preview` records and cannot become
publication candidates.

`release validate` also extracts both archive formats into temporary fixture
directories and checks:

- expected archive root exists
- required pack files exist
- forbidden paths are absent
- portable AIDE Lite script exists under the pack payload
- import policy and install notes exist
- checksums validate

No target install apply is run.

## Install Notes Boundary

The Q43-Q46 planning commands remain observe/plan/dry-run. Separate Windows
`import-pack`, `repair-owned-file`, `rollback-pack`, and `apply-removal`
commands have bounded exact-plan apply implementations, with supported forms
and final artifact qualification still determined by the release manifest.
The generated local draft must describe this distinction and retain its
no-publish boundary. Target repositories must run their own preflight and
validation after extraction or import. Target-specific memory, queue,
evidence, golden tasks, tools, doctrine, and manual guidance remain
target-owned.

## Export Boundary

The portable export pack includes release-bundle policies, schemas, README,
commands, tests, golden tasks, and this reference doc. It excludes
source-generated `.aide/release/dist/**` artifacts and
`.aide/release/latest-release-*` reports as target truth.

## Publication Boundary

Q47 is not a public release. It creates local files only:

- no Git tag
- no GitHub Release
- no upload
- no package registry publication
- no branch mutation
- no active CI installation
- no target repo mutation

Q48 adds local GitHub Release draft generation on top of this bundle, with a
checksum-backed asset list, no-upload plan, and publication checklist. Q49
Dominium Fresh Install Preflight is next because downstream install readiness
still needs target-local evidence before any public readiness claim.

The later stable Lite package rule is recorded in
`.aide/policies/release-versioning.yaml` and the bounded Windows profile in
`specs/control-plane/product/scope-and-profiles.md`. They define a contract
candidate for a future release, not a change to this Q47 archive's
`aide-lite-pack-v0` format identity or its no-publish metadata. Stable
version, tag, supported predecessor matrix, exact source and assets, and
downloaded-consumer qualification must be frozen and reviewed in a separate
release-effect WorkUnit. Existing Q47 outputs cannot be relabeled as stable
release assets by editing prose or a draft flag.
