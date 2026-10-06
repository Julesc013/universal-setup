# AIDE Release Bundle Model

Q47 defines local release-bundle generation for the portable
`aide-lite-pack-v0` export pack.

The release bundle model writes local artifacts under `.aide/release/dist/`:

- `aide-lite-pack-v0.zip`
- `aide-lite-pack-v0.tar.gz`
- `aide-lite-pack-v0.checksums.json`
- `SHA256SUMS.txt`
- `manifest.yaml`
- `install.md`
- changelog and release-note preview copies
- provenance, asset, and validation reports

The model is local-only. It does not create Git tags, create GitHub Releases,
upload assets, publish packages, mutate branches, install CI, mutate target
repositories, or apply install/repair/upgrade/rollback/uninstall actions.

Generated release outputs are evidence and local artifacts. They are not public
release publication and are not exported as target truth.
