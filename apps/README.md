# Apps

Frontend project/package shells. App roots are thin entrypoints over setup
commands and reports.

```text
apps/
  cli/
  tui/
  daemon/
  gui/
```

Reusable setup behavior belongs under `runtime/`. GUI providers must not own
install, repair, rollback, verification, state, or audit logic.

Product-specific GUI matrices live in product repos. Universal Setup may host
reference app-shell policy, but it must not absorb WinForms, WinUI, AppKit,
SwiftUI, GTK, Qt, or product-specific UI behavior into the setup kernel.
