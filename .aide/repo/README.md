# AIDE Repo Intelligence Index

`.aide/repo/` contains deterministic repo-intelligence schemas and generated
index outputs.

Portable source files:

- `*-schema.json`
- `README.md`

Source-generated local evidence:

- `file-inventory.json`
- `ownership-map.json`
- `dependency-map.json`
- `test-map.json`
- `doc-link-map.json`
- `generated-map.json`
- `orphan-candidates.json`
- `latest-repo-intelligence.md`

Generated repo intelligence outputs describe the repository that produced them.
They are evidence for review and planning, not target-repo truth and not
deletion advice. Target repositories must run `aide_lite.py repo inventory` to
produce their own indexes after import.
