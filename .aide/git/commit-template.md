# Commit Template

Use this shape for AIDE-managed commits:

```text
type(scope): concise summary

## Summary

- What changed at a glance.

## Why

- Why this change exists.

## Changed

- Concrete files or behaviors changed.

## Validation

- `command`: PASS | WARN | FAIL | NOT RUN.

## Changelog

- Added: user-visible or operator-visible addition.
- Changed: changed behavior or policy.
- Fixed: repaired issue.
- Removed: removed behavior or file.
- Deprecated: deprecated surface.
- Security: security-relevant note.
- Docs: documentation-only note.
- Tests: test-only note.
- Internal: internal-only note.
- Risks: risk note for release notes.
- Follow-up: future work.

## Risks

- Remaining risk or `None`.

## Follow-up

- Next action or `None`.

AIDE-Task: <queue-id>
AIDE-Phase: <phase-id>
AIDE-Result: PASS | WARN | FAIL | partial
AIDE-Scope: <paths-or-domain>
AIDE-Token-Impact: <summary>
AIDE-Quality-Gate: <validation-summary>
```

Do not include raw prompts, raw responses, provider credentials, secrets, or
local `.aide.local/` state in commit messages.
