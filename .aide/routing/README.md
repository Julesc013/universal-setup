# AIDE Routing Profile v0

Q17 routing is advisory only. It reads compact task/context packets plus local
token, verifier, review, golden-task, and outcome-controller signals, then writes
a deterministic route decision explaining what class of executor is justified.

The router does not call providers, models, networks, Gateway, Runtime, or UI
surfaces. It does not execute the route. It does not mutate prompts, policies,
or generated context artifacts except for explicit route-decision outputs.

Primary commands:

- `py -3 .aide/scripts/aide_lite.py route list`
- `py -3 .aide/scripts/aide_lite.py route validate`
- `py -3 .aide/scripts/aide_lite.py route explain`

Generated route decisions:

- `.aide/routing/latest-route-decision.json`
- `.aide/routing/latest-route-decision.md`
