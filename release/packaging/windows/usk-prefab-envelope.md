# Windows inspect-only prefab envelope

`tools/usk_prefab_envelope.py` composes a Windows x64 `product.bundle.json`, its
exact `payload.zip`, and a supplied `usk_machine.exe` into either:

- `sidecar`: four adjacent files, including `prefab.manifest.json`; one machine
  host entrypoint, no extraction.
- `one_file_carrier`: one deterministic `setup.carrier.zip`; no direct
  entrypoint, extraction required before using its contents.

The current machine host accepts a bounded read-only command subset. It does
not load this product bundle or perform setup. Neither envelope is a qualified
installer, and the one-file carrier is not an executable. The manifest records
`installation_mode=inspect_only` and an unqualified runtime dependency closure.
No signing, native integration, launch, or user-state change occurs here.

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
```

For the carrier profile, use `--profile one_file_carrier` and inspect
`<envelope-output>/setup.carrier.zip`. The builder validates the compiled
bundle before and after composition, streams the supplied runtime and payload
without changing their bytes, and reopens the emitted closure. Rebuilding from
identical inputs produces identical unsigned output bytes. The provided runtime
is identified by its SHA-256 and a Windows PE header prefix; this is not a
signature, provenance, import or compatibility qualification. An independent
source audit and runtime dependency inventory are required before product use.
