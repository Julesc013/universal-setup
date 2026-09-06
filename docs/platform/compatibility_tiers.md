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

## Windows native path admission

The JSON contracts retain their 32768-character input syntax budget. That
budget is not a filesystem capability promise. USK's ordinary Win32 calls
operate independently of a consuming application's manifest or machine-wide
long-path configuration. This implementation conservatively admits absolute
file paths up to 259 UTF-16 code units, directories and ancestors up to 247,
and individual components up to 255. These limits exclude the terminating NUL.
Supplementary Unicode characters occupy two UTF-16 code units. Admission
measures the actual native spelling, including any dot components passed to a
native call. Public archive paths still require strict UTF-8, exact native
round-trip, normalized absolute local paths, and refuse UNC/device namespaces.

These bounds follow the ordinary Windows `MAX_PATH` and directory creation
restrictions described in Microsoft's [maximum file path documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
and [CreateDirectory documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createdirectory).
USK does not add extended namespace prefixes or assume the host opts into
long paths. Supporting longer paths requires a separately qualified change.

Planning checks known source, target, payload, audit and state paths without
creating setup state. Apply checks the selected transaction ID and the complete
derived staging, journal (including its full sequence temporary name), audit,
installed-state, ownership, repair, move and uninstall paths before transaction
effects. A short-root plan can therefore be accepted while an apply request
with a longer transaction ID is refused with `native_path_limit_exceeded`.
Choose shorter authorized roots or identifiers and regenerate/review the plan.
Evidence packet paths are checked before their directory initialization too.
Record writers and stable source readers also enforce native capacity at use.

Admission is a pure capacity check: it grants no object identity, ownership,
replacement, deletion, rollback or live-target authority. Existing streamed
transactions continue to retain uncertain staging during live and resumed
rollback. Entry restart, generation leases, object-bound retained staging
cleanup, and complete lifecycle Unicode path persistence remain separate work.
POSIX capacity admission is unchanged. Hosted platform checks and native
boundary regressions qualify the tested paths only; they do not certify every
filesystem, host manifest or arbitrarily deep external build directory.
