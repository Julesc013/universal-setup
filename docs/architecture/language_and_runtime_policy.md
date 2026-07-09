# Language And Runtime Policy

Universal Setup is the installed-software mutation authority. Its implementation
must stay portable, auditable, and free of GUI toolkit assumptions.

## Kernel Policy

```text
include/usk/       public setup kernel C ABI
include/usu/       public utility/platform C ABI
runtime/setup/     setup transaction and mutation machinery
runtime/command/   setup command graph surface
runtime/platform/  low-level platform adapters
```

Public headers must not expose C++ classes, STL containers, exceptions,
templates, C# types, Swift types, Objective-C classes, or GUI toolkit objects.

## Mutation Boundary

Setup owns install, verify, repair, uninstall, rollback, installed-state
records, ownership, policy, and audit. CLI, TUI, daemon, and any future GUI
shells must call command contracts rather than implementing mutation behavior.

## Compatibility

Portable helpers may use C++98-style implementation techniques behind C ABI
wrappers when justified. Do not name runtime folders after language standards;
use ownership names such as `transaction`, `rollback`, `ownership`, `audit`, or
`platform`.
