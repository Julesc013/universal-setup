# Ecosystem Vision

Universal Setup is a sibling of Universal Launcher, not a submodule inside a
product launcher.

```text
Factorio proves the universal launcher through FacMan.
Dominium proves the universal setup.
FacMan ships as the first serious Factorio product binding.
```

Universal Setup owns install mutation:

```text
install
verify
repair
uninstall
stage / commit / rollback
installed-state manifests
setup audit
```

Universal Launcher owns runnable state. Product bindings own product-specific
facts. Frontends present commands and reports.

Dominium is the first serious setup proving ground because setup needs real
rollback, repair, ownership, determinism, packaging, and audit pressure before
it should be generalized too aggressively.
