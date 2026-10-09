# Base

Portable primitives shared by the setup kernel.

`usk::json::Value` owns only its active JSON alternative. Copy construction and
assignment retain independent trees; copy assignment completes its replacement
before changing the current value. Objects use exclusive owned storage, with
deep copies and allocation-free transfers; moved-from values become JSON null.
Array/object references belong to that
active value and must not survive its reassignment or destruction. Parsing,
canonical encoding, equality and budgets use the same six JSON types. This
internal storage change does not qualify publisher performance or a profile.

`usk_sha256` provides the single setup-owned SHA-256 implementation used for
package and source identity. `usk_stable_file` opens read-only local sources
without following links, rejects multiply linked/non-regular files, performs
bounded handle reads, and verifies that both the handle and path identity stay
unchanged.
