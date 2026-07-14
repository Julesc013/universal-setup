# CLI

Universal Setup console frontend entrypoint. Reusable setup behavior belongs under `runtime/setup/`.

`usk_live_acceptance` is the bounded M2 operator-acceptance runner. On Windows
it accepts only `D:\FacMan-Live-Acceptance\M2`; its `--test-mode` exception is
restricted to a child of the platform temporary directory. It creates a new
exclusive run root, uses a harmless non-executable synthetic ZIP, calls only
the public command ABI, and leaves immutable setup state, audit, journal,
evidence packets, and a summary for review. It cannot record a human verdict.
