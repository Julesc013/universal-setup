# Root Recycling Framework

`.aide/roots/` stores generated Q40 root inventory, classification, risk, and
no-apply recycling plan artifacts for the current repository.

These files are evidence and planning outputs, not applied migrations. Target
repositories must generate their own root inventories after importing AIDE
support. Q40 does not move roots, delete files, rewrite references, apply path
aliases, absorb tools, or retire exceptions.

Portable framework inputs live in:

- `.aide/policies/root-recycling.yaml`
- `.aide/policies/root-inventory.yaml`
- `.aide/policies/root-fates.yaml`
- `.aide/policies/root-exceptions.yaml`
- `.aide/policies/root-risk.yaml`
- `.aide/refactors/root-*.schema.json`

Generated source-repo outputs include:

- `.aide/roots/latest-root-inventory.json`
- `.aide/roots/latest-root-classification.json`
- `.aide/roots/latest-root-recycling-plan.json`
- `.aide/roots/root-exceptions.json`
- `.aide/roots/root-risk-summary.md`

Use:

```text
py -3 .aide/scripts/aide_lite.py roots inventory
py -3 .aide/scripts/aide_lite.py roots classify
py -3 .aide/scripts/aide_lite.py roots plan
py -3 .aide/scripts/aide_lite.py roots validate
```

Q41 Existing Tool Absorption v0 is the next phase that will use this framework
to classify existing tool roots before any future move, salvage, or alias plan.
