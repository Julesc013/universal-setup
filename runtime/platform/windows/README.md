# Windows

Windows platform capability adapter.

`usk_publisher_handle_observation` reads native directory identity, name,
attributes, link count, case sensitivity, owner, DACL protection, and ordered
allow/deny ACEs from one already-opened handle. Unknown ACE forms and missing
security access fail closed. The disposable smoke fixture reobserves the same
object after protecting its DACL. This is a read-only WU-006 building block:
it does not establish service identity, protected creation, a complete
descendant closure, durable publication, or profile qualification. The strict
runtime path continues to refuse publication.

The additional WU-006 candidate primitives read the process token and current
thread impersonation state, require a canonical Windows service SID in the
necessary restricted-token predicate, build an owner-`SYSTEM` protected
two-ACE descriptor, and create a single directory with that descriptor
relative to a held parent handle using create-only native semantics.
Disposable fixtures exercise ordinary-login refusal, impersonation, forged
non-service SIDs, descriptor shape, collisions, and parent-path substitution.
They do not bind an installed restricted service, dedicated volume, protected
parent chain, durable journal, or complete descendant closure. None is linked
to the strict production publisher.

The read-only volume/stream candidate observes local NTFS volume facts through
the held object handle, including the 64-bit file-ID volume prefix and the
admitted remote-protocol query failure. Its bounded stream enumeration checks
the candidate's exact shape: one unnamed data stream for a file and no data
streams for a directory. Disposable fixtures exercise named streams on both
types and the empty-directory query result. These per-handle facts do not
qualify a dedicated volume or establish a closed protected tree.

The next read-only candidate enumerates `FileIdExtdDirectoryInfo` children from
a retained directory handle, validates canonical names and a bounded listing,
then reopens each child relative to that handle with no-follow native options.
It compares the listed 128-bit ID to the reopened ID, checks the exact native
parent/name relation, and refuses a reparse point or multiple links. Its tree
walk uses bounded live listings and 64 KiB content reads to record a sorted
descendant path/identity/digest set. Local ordinary-user fixtures include a
640-file pagination case, case-only and forged-ID refusal, hard-link refusal,
and alternate-stream refusal. A file's listing size was observed as stale
while its writer handle remained open; content size comes from the reopened
handle. `FILE_OPEN_NO_RECALL` returned `STATUS_INVALID_PARAMETER` with the
candidate relative-open options on Windows 10 build 19045 and is not used.
The tree walk by itself is a fresh observation; it does not admit protected
security or anchor/ancestor roles, or durably publish and recover.

The following local slice extends the same-handle security observer to regular
files and includes owner, DACL protection, and ordered ACE facts for every
read-only descendant observation. A comparison helper requires fresh phase
volume/root/descendant equality, with one caller-supplied expected native root
path transition for a post-rename observation. A disposable fixture checks a
descendant DACL-control change and an actual root rename. The expected visible
path still has to come from independently bound destination-parent evidence;
the helper does not establish effective rights, protected service provenance,
or crash-safe publication.

The parent-bound wrapper now derives that expected visible path from a retained
destination-parent handle, enumerates its exact child, reopens that child
relative to the handle, observes the complete read-only tree again, and
rechecks the parent. A disposable native test renames the held parent and
creates a substitute at its old path; the wrapper still reopens the original
visible child. This does not prove that the parent chain is protected from
untrusted mutation or that the later publication state is durable.

A necessary security-shape predicate checks the exact `SYSTEM` owner,
protected DACL, and two ordered allow ACEs for a canonical service SID on the
root and every descendant. The ordinary-user OS tree is rejected and a
synthetic matching structure passes; the synthetic pass is not an OS admission
result. The actual restricted SCM service, effective-right checks, protected
volume-root chain, and attacker harness are still required.
