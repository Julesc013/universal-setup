# M1 Adversarial and Scale Proof

M1-WU7 treats refusal as a successful safety outcome when an input or host
capability cannot be proven safe. It does not convert unsupported Unicode
normalization, linked paths, or missing atomic rename primitives into weaker
fallback behavior.

The native proof set covers:

| Area | Proved behavior |
| --- | --- |
| Archive structure | traversal, absolute/drive/ADS paths, empty/dot segments, reserved names, case collisions, file/tree collisions, links/devices/reparse attributes, encryption, streaming, unsupported methods, alternate Unicode, compression ratio, entry/count/depth budgets, ambiguous bytes, and ZIP64 are refused |
| Stable source | no-follow singly-linked handles, changed-source detection, bounded reads, and read-only archive inspection |
| Plan law | reserved, case-colliding, non-normalized Unicode, overlong, and invalid-time inputs are refused before state mutation |
| Target law | target appearance after plan retains the existing sentinel; atomic no-replace commit has exactly one winner under concurrent applies |
| Transaction faults | every journal state plus staging creation, pre-write capacity failure, post-rename, and post-rollback finalization |
| Recovery | transition digest and exact root-authority tampering refuse resume |
| Repair/uninstall races | foreign content arriving after repair plan is retained; content arriving after uninstall plan invalidates apply before deletion |
| Move drift | any complete-tree source change after plan invalidates the reviewed move and leaves the destination absent |
| Audit concurrency | competing appends have exactly one immutable next-sequence winner |
| Scale | 258 files across nested directories install and verify as one deterministic owned closure |
| JSON | malformed numbers, duplicate keys, invalid escapes/surrogates/UTF-8, depth/value budgets, and non-idempotent canonicalization are rejected |

Linux sanitizer CI runs the native suite under AddressSanitizer and
UndefinedBehaviorSanitizer. A bounded Clang libFuzzer smoke target exercises the
strict JSON parser and canonical round-trip invariant. The local Debian/WSL1
host also runs the sanitizer suite, while its old kernel intentionally takes
the tested no-replace capability-refusal branch.

These are synthetic/disposable proofs. They do not authorize public lifecycle
commands or live product targets.
