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
