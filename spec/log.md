# Specification history

## 2026-09-20T12:00:00Z — 0.1.0-draft.1

Authored the proposed Universal Setup engineering baseline and knowledge/tooling layer. Imported no live grants, queues or runtime outcomes. Preserved historical disagreements in the reconciliation register. Pinned repository, OKF and AIDE observations; prepared a separate root-admission patch. Validation results are recorded separately in `verification/tooling-results.json` after actual tool execution.

## 2026-09-21T13:51:34Z — repository operations correction

Separated task context inputs, writable paths, explicit read-only paths and forbidden paths across all 33 inactive WorkUnit templates; added rejection of contradictory effective scopes; preserved inactive/no-authority export behavior; projected the repository's existing `USK-WU-001` adoption record separately from imported manifest provenance; and added a required CI specification job with the reviewed `jsonschema` development pin. No runtime, queue, grant, signing, protected-reference or publication state was changed.
