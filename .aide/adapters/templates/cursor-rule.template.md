{{managed_begin}}
---
description: AIDE token-survival and evidence workflow
alwaysApply: false
---

- Use `.aide/context/latest-task-packet.md` as the compact task source.
- Do not paste full histories, full repo dumps, secrets, provider keys,
  `.aide.local/`, raw prompts, or raw responses.
- Prefer exact file refs and line refs; ask for focused context when needed.
- Run `py -3 .aide/scripts/aide_lite.py doctor`, `validate`, `pack`, `verify`,
  and `review-pack` where available.
- Generated adapter outputs are not canonical truth; `.aide/` policy and queue
  records remain authoritative.
- Gateway/provider calls and forwarding remain deferred until reviewed policy.
{{managed_end}}
