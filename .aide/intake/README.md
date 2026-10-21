# AIDE Intake

Q36 adds deterministic intent intake for raw prompts. AIDE does not execute raw
prompts directly. `aide_lite.py intent compile` reads repo-local policy, queue
state, latest task packet hints, and branch state, then writes:

- `.aide/intake/latest-intent-packet.json`
- `.aide/intake/latest-intent-packet.md`
- `.aide/intake/latest-workunit-draft.json`
- `.aide/intake/latest-workunit-draft.md`

The compiler stores a SHA-256 prompt hash and a bounded excerpt. It does not
store raw long prompt logs, raw responses, provider traces, credentials, or
local `.aide.local/` state.

Intent packets are evidence and planning surfaces. They are not permission to
execute the drafted WorkUnit. Queue, branch, evidence, and policy state still
control whether work may proceed.

Portable targets receive the policy, schemas, examples, and command support in
the AIDE Lite export pack, but source-generated latest intent packets are not
exported as target truth.
