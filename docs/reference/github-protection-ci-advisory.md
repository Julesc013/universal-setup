# GitHub Protection And CI Advisory

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
