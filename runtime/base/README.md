# Base

Portable primitives shared by the setup kernel.

`usk_sha256` provides the single setup-owned SHA-256 implementation used for
package and source identity. `usk_stable_file` opens read-only local sources
without following links, rejects multiply linked/non-regular files, performs
bounded handle reads, and verifies that both the handle and path identity stay
unchanged.
