# Ownership

Universal Setup owns installed-state mutation and audit truth. It must not own
product semantics, launcher profiles, launch plans, Factorio mods, saves,
servers, Mod Portal rules, or branded product assets.

The two public ABI families are:

- `usk`: setup kernel ABI.
- `usu`: setup utility, execution, callback, report, and platform ABI.
