# Compatibility Tiers

Universal Setup compatibility is capability-tiered.

```text
U0 - Minimal manifest, digest, and state-record subset
U1 - Hosted portable local install/verify/uninstall plans
U2 - Native permissions, filesystem, service, and rollback integration
U3 - Modern signing, package-manager bridges, diagnostics, and scheduled CI
U4 - Product GUI frontends outside the setup kernel
```

Not every platform supports every setup effect. The contracts should expose
preview, refusal, audit, and diagnostics so unsupported effects fail closed.
