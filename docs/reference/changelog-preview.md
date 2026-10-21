# Changelog Preview

Q34 makes AIDE's structured commit discipline operational by compiling local Git history into reviewable changelog and release-note drafts.

```powershell
py -3 .aide/scripts/aide_lite.py changelog preview
py -3 .aide/scripts/aide_lite.py changelog preview --range HEAD~5..HEAD
py -3 .aide/scripts/aide_lite.py changelog validate
py -3 .aide/scripts/aide_lite.py changelog status
```

Inputs:

- Conventional Commit subjects.
- Compact-v1 prose and final trailers (`AIDE-Format: compact-v1`), or preserved legacy v0 structured bodies.
- Explicit `Changelog: Fixed: ...` trailers, or legacy `## Changelog` category bullets. Both feed the existing preview schema. Malformed compact messages emit no release entries.
- AIDE trailers such as `AIDE-Task`, `AIDE-Phase`, and `AIDE-Result`.

Outputs:

- `.aide/changelog/CHANGELOG.preview.md`
- `.aide/changelog/RELEASE_NOTES.preview.md`
- `.aide/changelog/changelog.preview.json`
- `.aide/changelog/release-notes.preview.json`
- `.aide/changelog/malformed-commits.md`
- `.aide/changelog/latest-changelog-report.md`

Malformed or legacy commits are reported, not hidden and not rewritten. Merge commits can be ignored as non-structured inputs. The generator is preview-only: it does not tag, publish, create GitHub Releases, mutate branches, call providers/models, or use the network.

The portable pack exports the policy, config, templates, command support, tests, golden tasks, and this reference doc. Generated preview outputs remain source-specific and are not exported as target truth.

Installed projects may generate previews after creating their own queue. The
changelog guard recognizes a completed import receipt whose managed CLI matches
the installed bytes. Missing or invalid receipts, changed CLI bytes, CLI overlays,
pending lifecycle operations and AIDE self-hosting identity do not qualify for
that recognition. Project-owned profiles and policy customization remain valid.
Profile identity accepts explicit plain or quoted scalars and trailing comments;
duplicate fields, inherited identity and unsupported scalar forms are refused.
This recognition applies only to changelog generation; source-checkout admission,
packaging and test execution retain their existing boundaries. Receipt matching
detects inconsistent local state; it is not a sandbox or a cryptographic trust
claim against an actor able to rewrite both code and receipts.
