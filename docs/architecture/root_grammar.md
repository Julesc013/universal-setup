# Root Grammar

Universal Setup uses the same sibling-repo grammar as Universal Launcher and
FacMan:

```text
include/     public ABI headers owned by this repo
runtime/     private compiled implementation
apps/        executable frontends and thin app shells
contracts/   ABI, schemas, command contracts, result/refusal law
content/     templates, product data, declarative policies
release/     packaging recipes and release profiles
docs/        human documentation
tests/       unit/integration/golden/fault tests
tools/       validators and developer automation
cmake/       build modules and toolchain rules
external/    vendored third-party code, if any
archive/     quarantined old/prototype/generated retained material
```

`runtime/` is not a renamed `source/` bucket. Setup runtime modules must map to
setup ownership: manifest, resolver, plan, fetch, verify, transaction,
rollback, state, ownership, policy, audit, and package.

Runtime folders are domain folders, not language-version buckets. Do not create
`runtime/**/cpp98`, `runtime/**/cpp11`, `runtime/**/c11`, or similar paths.
Language level is a build policy, not a source ownership boundary.
