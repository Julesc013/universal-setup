# Acceptance

- `main` classifies as canonical.
- `dev` classifies as integration.
- `task/*` and `codex/*` classify as task.
- `review/*`, `release/*`, `hotfix/*`, and `gh-pages` classify to their dedicated roles.
- Unknown branch names classify as unknown and are treated conservatively.
- `develop` only records a GitFlow-like warning; it does not force full GitFlow.
