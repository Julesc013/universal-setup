### Portable lifecycle filesystem bindings

**Status:** accepted development-package lifecycle cases passed on the four exact Windows/Linux/macOS environments below. [Observed evidence and acceptance state](https://github.com/Julesc013/aide/blob/1e5193b0f1e7e8e3c14f30ba0124e8f44b799c9d/.aide/queue/AIDE-LITE-POSIX-LIFECYCLE-01/REPORT.md) remain separate from versioned release qualification. Published Lite 1.1.0 retains its exact Windows support profile; source presence or successful collection alone does not expand support.

AIDE keeps one import, update, repair, rollback and removal implementation in `.aide/scripts/aide_lite.py`. Filesystem bindings implement only the operations that depend on the operating system. They do not own separate plans, task queues, receipts, policy, upgrade rules or release versions. The new standard-library sibling `posix_filesystem.py` follows the existing export pattern and remains loaded during same-process self-removal.

| Responsibility | Shared owner | Binding responsibility |
|---|---|---|
| Adopt an existing project | Import plan and exact preimages | Publish complete bytes without replacing a competing entry |
| Preserve customization | Ownership receipts, project controls and three-way decisions | Read bounded regular files and preserve native metadata on replacement |
| Recover interruption | Existing intents, observation and reconciliation | Preserve the original inode in an intent-bound backup when publication is uncertain |
| Repair missing owned content | Exact pack, receipt and preview | Refuse an existing target and publish only the expected new file |
| Discontinue use | Removal plan and managed-section ownership | Dispose only verified single-link files; preserve authored bytes and unknown state |

### Actual protection boundaries

**Windows** retains its existing pinned-directory and deny-sharing handles, no-replace publication and handle-bound disposition. Its qualified profile does not imply that every editor, plugin or shell on the host is contained.

**The Linux/macOS candidate profile requires one cooperative mutation owner.** Directory descriptors, no-follow traversal, exact bytes and entry/inode checks detect many changed inputs. The existing lifecycle lock serializes cooperating AIDE operations. These mechanisms cannot prevent an unrelated same-user process from changing a name between inspection and unlink, and cannot make several file operations one atomic transaction. Do not advertise hostile-writer isolation or Windows-equivalent deny-sharing.

The binding refuses unavailable descriptor operations and native no-replace rename support. Linux uses `renameat2(RENAME_NOREPLACE)`; Darwin uses `renameatx_np(RENAME_EXCL)`. Filesystem support is required as well as an available library symbol. There is no fallback to a path-based overwrite. Other POSIX systems remain explicit future native profiles, even when they can inspect the same project records.

Ancestors must be real directories, and files must be ordinary single-link files. Symlinks, hardlinks, special files, stale bytes, changed identities and competing publication names are refused. The persisted identity remains the existing 24-hex-digit representation: 32-bit device and 64-bit inode. An unrepresentable identity refuses rather than truncating. New files and directories default to private `0600` and `0700`, subject to the process umask.

**Metadata is part of preservation.** Replacements retain owner, group, mode and native ACL/xattr metadata before publication. Linux copies and verifies descriptor xattrs; Darwin uses `fcopyfile` for ACLs and xattrs. Set-ID permission bits, nonzero native file flags, unavailable metadata operations and an inability to preserve ownership refuse the replacement. Independent native ACL/xattr fixtures must pass before making a preservation claim for a profile. No privilege escalation is attempted.

File and parent-directory synchronization retain the established durability intent; unavailable directory synchronization refuses before target-file effects. This is not a promise against every hardware, network-filesystem or storage-controller failure.

### Recovery and safe exit

- Ordinary interruption between completed payload writes retains the exact intent and explicit `--recover-partial --expect-plan` route. Changed controls, resolution bytes, source, predecessor or target observations refuse automatic continuation.
- A process termination between parking the preimage and publishing its replacement can leave an absent target, an original backup and a private stage. The existing import owner classifies outstanding backups as uncertain and retains them. It does **not** automatically adopt, overwrite or delete them. Preserve the intent, compare the exact preimage and identities, and reconcile explicitly before retrying. A process-exit regression verifies this refusal; it is not an automatic-recovery claim.
- The existing authored-`AGENTS.md` removal recovery may restore an intent-bound original backup only when its recorded identity and digest match and the destination is absent. A competing destination remains untouched.
- Missing installed helpers refuse effectful operation. Use the matching delivered pack for applicable owned-file repair or reconciliation; do not silently load another project's module.
- Actual 1.1-to-development rollback with changed payload paths continues to refuse. A same-path rollback pass does not qualify that downgrade. A separately verified detach followed by predecessor reinstall preserves the supported exit pattern without relabelling it automatic rollback.

Removal preserves project memory, customization, tools, unknown material and edited owned files. When preservation requires it, a receipt and minimal runner can remain for reconciliation; `PARTIAL_REMOVAL` is not full detachment. Users can continue with other tools. AIDE records do not grant peers authority over their project.

### Qualification and release

The bounded candidate uses exact CPython 3.14.8 on local Windows 10 build 19045/x64 and standard hosted Windows Server 2025 build 26100/x64, Ubuntu 24.04/kernel 6.17.0-1022-azure/x64 and macOS 15/Darwin 24.6.0/arm64. The local continuation and hosted run passed all sixteen current-development adoption/upgrade cases across those environments. Hosted tests produced 447 passes and 21 explicit skips; all fifteen POSIX primitive tests, including native ACL/xattr preservation, passed on each Linux/macOS profile. Tests include unchanged shared behavior oracles, native no-clobber/refusal/metadata fixtures, installed-CLI self-removal, an actual published 1.1 predecessor conflict, selected resolution, interruption, repair and project-preserving exit. Windows-only skips remain separate and never count as POSIX passes. The unchanged published 1.1 package still refused POSIX removal at its historical Windows-handle guard; this does not invalidate its original Windows release profile.

The versioned Lite 1.2 release still requires frozen archives, checksums, acquired-byte replay, support-profile records, documentation/changelog closure and reviewed publication. Historical failures and valid successes retain their own subjects. BSD, Unix, Solaris/SunOS, older Windows, DOS/FreeDOS and OS/2 native work remains staged under the [portability plan](portability-and-build-profiles.md); companion access does not complete native qualification.

**API references:** [Python descriptor operations](https://docs.python.org/3.14/library/os.html), [Linux no-replace rename](https://man7.org/linux/man-pages/man2/rename.2.html), [Apple rename declarations](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stdio.h), [Apple copyfile declarations](https://github.com/apple-oss-distributions/copyfile/blob/main/copyfile.h), [Linux ACL interchange](https://github.com/torvalds/linux/blob/master/include/uapi/linux/posix_acl_xattr.h). These references establish API behavior, not AIDE qualification.
