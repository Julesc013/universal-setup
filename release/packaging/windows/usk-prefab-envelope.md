# Windows inspect-only prefab envelope

`tools/usk_prefab_envelope.py` composes a Windows x64 `product.bundle.json`, its
exact `payload.zip`, and a supplied `usk_machine.exe` into either:

- `sidecar`: four adjacent files, including `prefab.manifest.json`; one machine
  host entrypoint, no extraction.
- `one_file_carrier`: one deterministic `setup.carrier.zip`; no direct
  entrypoint, extraction required before using its contents.

The machine host accepts a bounded read-only command subset. Its
`--product-info <path>/product.bundle.json` mode now opens an adjacent compiled
bundle and prefab manifest, checks the three packaged member sizes and hashes,
streams the stored ZIP payload through the native archive inspector, and
compares every file's size and SHA-256 against the authoring inventory. These
unsigned hashes establish package byte consistency, not publisher authenticity.
It reports product identity, component IDs and byte totals. The native
`--product-select <path>/product.bundle.json [--select ID ...]` command runs
the same complete packaged-byte check, then resolves required/default choices,
requested components, dependency closure and directional conflicts. It checks
the entire dependency graph for cycles, including unselected components, and
returns a stable dependency-first list with the bundle and payload hashes.
This is a read-only selection, not a machine plan or setup operation. Neither
envelope is a
qualified installer, and the one-file carrier is not an executable. The manifest records
`installation_mode=inspect_only` and an unqualified runtime dependency closure.
The builder does no signing, native integration, launch, or user-state change.
The source probe launches the packaged host for its read-only command and
product-byte inspection, and checks refusal after a payload-byte mutation.

## External product walkthrough

Create a declarative project in a separate product directory using the
`usk.authoring_project.v1` schema. Point each selected target variant at
already-finalized files. Build and inspect its bundle with the WU-012 compiler:

```text
python tools/usk_bundle_author.py build --source <product>/project.json --target windows-x64 --output-dir <empty-bundle-output>
python tools/usk_bundle_author.py inspect --bundle <empty-bundle-output>/product.bundle.json
```

Build `usk_machine` in an external CMake build root, then compose either profile
into a separately created empty output directory:

```text
python tools/usk_prefab_envelope.py build --bundle <bundle-output>/product.bundle.json --runtime <build>/usk_machine.exe --profile sidecar --output-dir <empty-envelope-output>
python tools/usk_prefab_envelope.py inspect --path <envelope-output>
<empty-envelope-output>/usk_machine.exe --product-info <empty-envelope-output>/product.bundle.json
<empty-envelope-output>/usk_machine.exe --product-select <empty-envelope-output>/product.bundle.json --select <component-id>
```

For the carrier profile, use `--profile one_file_carrier`, inspect
`<envelope-output>/setup.carrier.zip`, extract it to a new directory, and run
the extracted `usk_machine.exe --product-info <extracted>/product.bundle.json`.
The builder validates the compiled
bundle before and after composition, streams the supplied runtime and payload
without changing their bytes, and reopens the emitted closure. The reopened
manifest must match the manifest derived from the reviewed inputs, so a valid
alternate output substituted during composition is refused. Rebuilding from
identical inputs produces identical unsigned output bytes. The provided runtime
is identified by its SHA-256 and a Windows PE header prefix; this is not a
signature, provenance, import or compatibility qualification. An independent
source audit and runtime dependency inventory are required before product use.

Inspection checks the entire ZIP carrier against a disposable canonical
reconstruction, including bytes outside declared ZIP members. It also runs the
existing product-bundle inspector on the emitted sidecar or on named members
extracted to a disposable directory. Large carrier inspection therefore needs
temporary disk space for its canonical copy and extracted payload.
