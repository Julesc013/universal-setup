# WU-027 Windows 10 read-only canary

The exact Windows 10 Enterprise x64 build `10.0.19045` host ran the public
`usk_machine` one-shot command `command_graph.inspect` from source
`26925ecb55b1a8fabdc5d66b77d535bb98bd04d2` (tree
`3c2eb664e6c4f72abbc5beab24754d0c803cda4c`). The process returned
`ok` with exit 0. The same executable refused `install_local.apply` with
`command_unavailable` and exit 2. The existing process-boundary smoke and C
ABI layout smoke passed on this host. The exact observations and binary
identity are in [the canary record](../../release/profiles/windows10_19045_x64_readonly_canary.v1.json).

This is an early feasibility observation for a reduced read-only profile. It
does not qualify any mutation, a Windows 10 release, or the first Windows NT
x64 publisher profile. The one-shot host exposes only its admitted inspect
commands; other public ABI functions and future clients need separate tests.

## Binary audit

The Release x64 executable was built with Visual Studio 18 2026, MSVC
19.51.36252.0 and Windows SDK 10.0.26100.0. `dumpbin /headers` recorded x64,
Windows CUI, and PE OS/subsystem version 6.00. `dumpbin /imports` recorded the
direct DLL list in the canary record. The executable loaded and ran on the
observed target, so its dependencies were available there. The VC and UCRT
DLLs were supplied by that development host. A distributable runtime closure,
earlier-build import floor, and baseline ISA audit have not been established.
The PE header version alone is not a support floor.

The retained lab receipt is `wu027-windows10-process-observation.json` with
SHA-256 `8a1af1b7dab8029793e0439acbbd9892832c477b56085749f8e6c6f8671a7d9a`.
The retained direct-import dump has SHA-256
`19e6e69e321b9b4de9db17b3fa60c754d277f3b6ff27e2f369eea18e880754f2`.
The retained `wu027-readonly-checks-receipt.json` binds the two smoke commands,
both exits and both executable hashes to the source and target; its SHA-256 is
`2963550b677701f763a7c476c722f462bb2d78562550ac97020f976265849b3a`.
These local receipts are observations, not packaged release artifacts.

## Repeat on a named target

Build `usk_machine` and `usk_abi_layout_smoke` for Release x64, then run
`tests/native/usk_machine_process_probe.py` against the built host and run the
ABI smoke executable. Audit the actual executable with `dumpbin /headers`,
`/dependents`, and `/imports`. Record the source tree, binary digest, OS build,
toolchain, process outputs, and runtime DLL provenance separately for each
target. Do not infer an earlier loader floor from a newer build host or PE
header metadata.
