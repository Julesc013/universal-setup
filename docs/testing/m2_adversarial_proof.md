# M2 Cross-Platform Adversarial Proof

M2-WU9 runs the complete Universal Setup Python, policy, native lifecycle, and
strict-validation suite on `ubuntu-24.04`, `macos-15-intel`, and
`windows-2022`. Linux sanitizer and bounded libFuzzer jobs remain separate and
continue to exercise the same native core.

macOS runner fixtures bind `TMPDIR` to the real `/private/var/...` directory.
The default `/var/...` spelling crosses the `/var` symlink and is intentionally
refused by the same no-link root policy under test; CI normalization changes
only the disposable fixture path and does not weaken production inspection.

The machine-readable corpus is
`tests/fixtures/setup/m2-adversarial-coverage.v1.json`. The strict checker
requires every Setup-owned case to name an existing test and exact source
markers. It also records frontend cancellation/process termination as an
explicit FacMan consumer proof instead of claiming that Universal Setup owns a
frontend process boundary.

| Required case | Setup proof |
| --- | --- |
| Unicode and long paths | deterministic plan refusal outside the admitted portable path profile |
| Case and Unicode-normalization collisions | archive and plan refusal before mutation |
| Links and reparse-like entries | archive, stable-source, target, and recovery refusal |
| Source replacement | public apply reopens and revalidates the archive; changed bytes refuse before state creation |
| Target ancestor replacement | direct transaction and public apply both retain the substituted sentinel and refuse |
| Concurrent applies | exactly one no-replace winner; the other operation refuses |
| Read-only sources | inspection produces the same identity and entry-set digest without source writes |
| Partial writes | an unrecorded partial staging file yields `retain_for_operator`, never silent cleanup |
| Insufficient space | the pre-write capacity fault leaves no created payload and remains recoverable |
| Cross-device move | copy, verify, and destination-local no-replace commit; Linux uses `/dev/shm` when it is a distinct device |
| Changed ownership or audit records | digest/chain validation refuses tampering |
| Stale and replayed plans | changed digest and repeated apply both refuse without changing the committed closure |
| Foreign files during repair/uninstall | foreign content is retained and later mutation is refused where required |

A missing second device is a host capability fact, not permission to weaken the
move algorithm. The normal move suite still runs on every platform; the Linux
case performs a real cross-device source-to-destination copy when `/dev/shm`
has a distinct device identity. Other target runners require separately
provisioned volumes before claiming a target-native cross-device observation.

All results are automated findings. They cannot set `Pass`, `Fail`, or
`Inconclusive`, enable ordinary live apply, authorize product execution, or
change H1.
