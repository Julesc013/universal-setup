# Registered publisher C SDK client

This is an active development interface. The context and failure controls build locally; selected installed SDK reentry and public verification have hosted positive evidence, while generic recovery and complete lifecycle qualification remain incomplete. This document does not declare release or production support.

Include `usk/usk_publisher_client.h` and call `usk_context_create_publisher_v1(local_config, publisher_config, &context)`. The separate sized endpoint configuration is copied during creation. It selects an existing administrator-configured service and grants no registration, elevation, raw-volume or target authority. Creation performs no service activation.

The existing `usk_config_v1` prefixes, four original entry points, ABI 1.0 version result, allocator pairing and borrowed response lifetime remain unchanged. The added factory is an opt-in symbol; its presence is separate from the baseline version getter. Non-Windows factory calls return `USK_STATUS_UNSUPPORTED_VERSION` with a null context.

`usk_command_execute_v1` accepts the same public requests. Local planning keeps the optional local configuration. Selected effects and verification use the authenticated service route. Full `recovery.apply` forwarding retains the reviewed recovery plan/digest, confirmation and `finalize`/`rollback` choice, but its native adapter is not implemented and current admission refuses it before dispatch. An older four-field recovery selector cannot preserve those checks.

Each invocation owns its UNKNOWN response before transport can send request bytes. Lost, malformed, mismatched or allocation-failed replies after possible dispatch return `USK_STATUS_ERROR`, JSON status `unknown` and error code `publisher_outcome_unknown`. This does not establish whether effects occurred. Do not blindly repeat an apply; inspect or recover the bound operation using its actual reviewed contract.

The payload `usk.publisher_client_outcome.v1` retains the canonical public request SHA-256 and bounded caller-supplied operation/recovery identity. These fields are correlation data, not native evidence or authority. Full requests, archive paths and payload bytes are not copied into uncertainty output. The identity receipt has a 64 KiB bound; request and response parse limits have separate meanings.

Only the concrete transport can establish pre-dispatch refusal. Validated native refusal and recovery-required outcomes remain distinct from transport uncertainty. Failure never selects the privileged legacy client or retries through local mutation.

Response bytes remain borrowed until the next call on the same context or destruction. Copy retained results before that boundary. Serialize calls to one context; independent contexts own separate buffers. No transport callback is part of the public ABI.

At [c42752f](https://github.com/Julesc013/universal-setup/commit/c42752fe20f8096fac0b2b2736d2455baf0fd9fd), [hosted run 39260395143](https://github.com/Julesc013/universal-setup/actions/runs/39260395143) completed source-retired SDK apply reentry and five-field verification under the held standard-account client. Returned installed state and both payload hashes matched independent SYSTEM readback, with client/account cleanup confirmed. Installed and relocated static/shared SDK consumer checks also passed locally on x64 and Win32. These selected results do not qualify fresh SDK installation, generic recovery, the complete publisher or a public release.
