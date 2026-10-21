# WorkUnit Idempotency

Q27 defines a WorkUnit as a bounded queue task with a stable id, allowed paths,
status, evidence, validation, and acceptance criteria. Repeated prompts must
inspect repo-local state before asking the user.

Default command surface:

```powershell
py -3 .aide/scripts/aide_lite.py task inspect
py -3 .aide/scripts/aide_lite.py task noop-check
py -3 .aide/scripts/aide_lite.py task status
py -3 .aide/scripts/aide_lite.py task recover
```

If a task is already complete and required evidence exists, the expected result
is `noop_already_complete`. If it is partial, continue from status/evidence.
If dependencies are missing, destructive ambiguity exists, or manual content
cannot be merged safely, stop and record the blocker.

The governing policies are:

- `.aide/policies/task-resumption.yaml`
- `.aide/policies/work-units.yaml`
- `.aide/policies/recovery.yaml`
- `.aide/policies/intent.yaml`

## Portable Pack

Q31 exports these policies and the `task` command surface through the portable
AIDE Lite Pack. Imported target repos must still generate their own queue,
status, evidence, context, and review artifacts; AIDE source queue history is
not target truth.

## Intent Compile Before Execution

Q36 adds an intake step before implementation. Raw prompts should be compiled
with:

```powershell
py -3 .aide/scripts/aide_lite.py intent compile --prompt "<task>"
```

The latest intent packet and WorkUnit draft are evidence, not authorization to
execute the task. Vague, overbroad, destructive, Git, release, and target-repo
prompts must still pass queue policy, branch policy, review gates, and evidence
requirements before implementation begins.
