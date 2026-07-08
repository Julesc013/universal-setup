# Apps

Frontend project/package shells. App roots are thin entrypoints over setup
commands and reports.

```text
apps/
  cli/
  tui/
  daemon/
  gui/
    win32/
    appkit/
    gtk/
    qt/
```

Reusable setup behavior belongs under `runtime/`. GUI providers must not own
install, repair, rollback, verification, state, or audit logic.
