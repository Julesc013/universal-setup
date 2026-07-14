# Live-target evidence

This module produces deterministic, sanitized M2 evidence packets and stores
them with no-clobber semantics. Runtime builders emit only a pending operator
verdict. Recording `Pass`, `Fail`, or `Inconclusive` is a separate API that
creates a new immutable packet linked to the pending packet digest.

The packet contains identity digests rather than source or target paths. It is
evidence about setup behavior, not setup authority, and cannot enable mutation
or product execution.
