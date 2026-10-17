# Acceptance

- Prune requires ancestor containment.
- Protected roles are never eligible.
- Ancestor containment uses `git merge-base --is-ancestor`.
- Prune policy remains dry-run by default.
