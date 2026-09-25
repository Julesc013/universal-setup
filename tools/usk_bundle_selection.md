# Finalize a component selection

After compiling a product bundle, create a new empty output directory outside
the compiled bundle. `finalize` verifies every source payload byte, resolves
required/default/requested components and dependencies, and writes a new
`product.bundle.json` and `payload.zip` containing only the selected files.

```text
python tools/usk_bundle_selection.py finalize --bundle <compiled>/product.bundle.json --select <optional-component-id> --output-dir <empty-selected-output>
python tools/usk_bundle_selection.py inspect --source-bundle <compiled>/product.bundle.json --output-dir <selected-output>
```

Omit `--select` for the required/default selection. Repeat it for additional
components. `selection.receipt.json` binds the derived unsigned bytes to the
full compiled bundle and records the exact closure; retain it as authoring
evidence. Both commands refuse unknown selections, source or derived byte
changes, and changed receipt contents. They do not install, sign, or qualify a
publisher. The finalized bundle can be passed to the existing inspect-only
prefab envelope builder; the current envelope does not package the selection
receipt.
