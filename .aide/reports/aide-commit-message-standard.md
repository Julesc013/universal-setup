### AIDE commit message standard

New authoring uses **compact-v1**: a specific Conventional Commit subject,
informative prose, actual validation, explicit changelog and task/format trailers.
No seven-heading report is required.

The [policy](../policies/commit-messages.yaml) defines the formats.
The [writing guide](../../docs/reference/commit-discipline.md) covers commits,
PRs, merges and comments. The [plain-text template](../git/commit-template.md)
is available through `commit template`.

Check drafts with `commit check --message-file <path>` and committed messages
with `commit check --latest`. Range checks retain historical rules;
`--no-dispositions` reproduces raw checks. Changelog output remains preview-only.
Legacy messages and original failures remain intact. Syntax checks are not
test evidence, acceptance or permission to merge.
