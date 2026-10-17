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
- Structured Markdown commit bodies with `## Summary`, `## Why`, `## Changed`, `## Validation`, `## Changelog`, `## Risks`, and `## Follow-up`.
- Machine-readable `## Changelog` bullets such as `- Added:` and `- Fixed:`.
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
