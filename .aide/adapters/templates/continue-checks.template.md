{{managed_begin}}
# AIDE Token-Survival Check For Continue

Before handing work to an assistant:

- Prefer `.aide/context/latest-task-packet.md` over long chat history.
- Confirm the request does not require full-repo prompting.
- Keep secrets, provider keys, raw prompts, raw responses, and `.aide.local/`
  out of committed context.
- Run `py -3 .aide/scripts/aide_lite.py validate` and generate or refresh a
  compact packet with `pack --task "<bounded task>"` when useful.
- Use `verify` and `review-pack` for evidence-bearing changes.
- Treat Gateway/provider metadata as advisory; no live forwarding is enabled.
{{managed_end}}
