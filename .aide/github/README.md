# AIDE GitHub Advisory

`.aide/github/` contains report-only GitHub protection and CI advisory outputs.

Q35 has no GitHub API mutation. It does not call the GitHub API, install branch protection, write
`.github/workflows`, create tags, publish releases, push branches, or run
provider/model calls. It compiles repo-local policy and Git state into reviewable
plans that a later reviewed phase can use.

Useful commands:

- `py -3 .aide/scripts/aide_lite.py github advisory`
- `py -3 .aide/scripts/aide_lite.py github status`
- `py -3 .aide/scripts/aide_lite.py github protection`
- `py -3 .aide/scripts/aide_lite.py github ci`
- `py -3 .aide/scripts/aide_lite.py github validate`
