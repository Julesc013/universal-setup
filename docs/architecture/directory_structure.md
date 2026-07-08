# Directory Structure

```text
universal-setup/
  include/    public `usk` C ABI headers
  runtime/    setup kernel implementation, platform adapters, base helpers
  apps/       optional setup frontends
  contracts/  ABI, command, schema, result, diagnostic, refusal, policy
  content/    universal setup templates and policy
  release/    package manifests and release profiles
  docs/       human documentation
  tests/      proof, fixtures, and golden outputs
  tools/      validators and repo automation
  cmake/      native build policy
  archive/    retained planning/prototype material
```

`source/` and `src/` are retired. Do not create implementation bucket
directories. Implementation belongs under `runtime/` or app entrypoint roots.

Universal Setup must not contain product-specific behavior. In particular, it
must not contain Factorio discovery, mods, saves, servers, Mod Portal behavior,
launcher profiles, or launch-plan semantics.
