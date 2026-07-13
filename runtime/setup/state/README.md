# State

The WU5 state repository stores canonical `usk.installed_state.v1` records in
an explicitly initialized setup-owned root. Constructing a reader does not
create directories or files.

An installed-state write succeeds only after the repository re-reads and
validates the exact ownership manifest named by the install, including its
digest and target root. Writes are durable and no-clobber. Reads use stable
no-follow handles, reject non-canonical or incompatible records, and revalidate
the ownership binding.

The repository is not a central database. A derived index may later be rebuilt
from these per-install records.
