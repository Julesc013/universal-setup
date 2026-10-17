# GitHub Protection And CI Advisory

Portable defaults leave main hosting protection optional and dev normally
unprotected. Set each project's `rules.<branch>.protect` boolean in
`.aide/policies/branch-protection.yaml` to opt in or override. The advisory now
reads these choices instead of hard-coding protected main/dev. It accepts the
existing two/four-space mapping with literal booleans; missing, duplicate or
unsupported values remain unknown and fail policy validation. Human and JSON
reports show the same choice and preserve existing remote settings. They do not
claim that remote protection was observed or changed. Main review, applicable
tests, no-force-push and persistent-branch retention remain independent duties.

Q35 adds report-only GitHub protection and CI advisory support.

The advisory uses repo-local evidence:

- branch roles from `.aide/policies/branch-roles.yaml`;
- promotion rules from `.aide/policies/promotion-rules.yaml`;
- Git helper state from `.aide/git/**`;
- structured commit and changelog policies;
- export-pack and validation command posture.

Commands:

- `py -3 .aide/scripts/aide_lite.py github advisory` writes reviewable advisory
  reports under `.aide/github/`.
- `py -3 .aide/scripts/aide_lite.py github protection` refreshes the branch
  protection plan only.
- `py -3 .aide/scripts/aide_lite.py github ci` refreshes the CI gate plan only.
- `py -3 .aide/scripts/aide_lite.py github validate` validates advisory
  policy and generated reports.

Boundaries:

- no GitHub API mutation;
- no `.github/workflows` creation;
- no branch creation, deletion, merge, push, promotion, or prune;
- no tags or GitHub Releases;
- no provider/model/network calls.

Future phases may turn these plans into apply-capable workflows only after they
add dry-run evidence, rollback plans, operator approval, and review gates.
