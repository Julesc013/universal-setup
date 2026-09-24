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
