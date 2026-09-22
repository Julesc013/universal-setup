---
type: "Tooling Guide"
title: "Specification tools and reproducible maintenance"
description: "Exact commands, trust limits, generated artifacts and validation scope."
tags: ["universal-setup","tools"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current specification-authoring request"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TOOLS","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "tooling","depends_on": ["USK-S-OKF","USK-S-CONTEXT"]}
---

# Specification tools and reproducible maintenance

## Requirements
Use Python 3.9+ for the bundled offline tools. The delivered run was tested on Python 3.13.5, not every possible Python/OS combination. Core commands use the standard library. `schema-check` and exact external AIDE schema validation require the optional `jsonschema` development package; CI installs the reviewed 4.26.0 pin from `spec/tools/requirements-ci.txt`. No endpoint setup runtime depends on these tools.

The nested `.gitattributes` keeps specification text at LF in Git checkouts so exact hashes remain stable across platforms. Add explicit binary rules for future binary assets.

The frontmatter reader intentionally supports this bundle's JSON-valued YAML subset. It is not a general YAML parser or a full generic OKF validator. Unknown concept types and inert metadata keys are preserved. External schema references are refused, so full schema validation cannot implicitly fetch network content.

## Command reference
Run from the repository or extracted package root:

```text
python spec/tools/specctl.py validate
python spec/tools/specctl.py schema-check
python spec/tools/specctl.py index
python spec/tools/specctl.py index --check
python spec/tools/specctl.py status
python spec/tools/specctl.py next
python spec/tools/specctl.py search "publication"
python spec/tools/specctl.py show USK-S-PUB
python spec/tools/specctl.py show USK-R-PUB-001
python spec/tools/specctl.py impact --path runtime/setup/transaction/publisher.cpp
python -B -m unittest discover -s spec/tools/tests -v
```

`validate` checks concept metadata, references, dependency cycles, JSON integrity, non-contradictory task scopes and requirement/acceptance/task traceability. It does not validate the complete runtime design. `schema-check` checks proposed schemas/examples and metadata shapes, not native semantics. `status` separates imported package provenance from the repository adoption projection; it does not report live runtime readiness or queue completion. `next` reports dependency-ready proposals; `--completed` is an explicit hypothetical input, not proof those tasks are accepted.

## Context and AIDE exports
Use new/empty external output directories. Replace the illustrative output path with an actual authorized path.

```text
python spec/tools/specctl.py context USK-WU-005 --max-bytes 64000 --output-dir /external/task-context
python spec/tools/specctl.py context-check /external/task-context/context.json
python spec/tools/specctl.py context USK-WU-005 --full-closure --max-bytes 200000 --output-dir /external/full-context
python spec/tools/specctl.py aide-export USK-WU-001 --output-dir /external/aide-proposal
python spec/tools/specctl.py aide-export USK-WU-001 --aide-checkout /external/pinned-aide --output-dir /external/aide-checked-proposal
```

Default context embeds task-declared pages plus mandatory policy/workflow pages in full; transitive references are clearly listed as not embedded/not read. `--full-closure` includes all transitive pages. Byte budgets are not model token counts. Required content is never silently truncated.

AIDE exports carry correct inspected field families but remain planned, check-only and unauthorized. Without the pinned schemas they report `EXPORTED_SCHEMA_VALIDATION_NOT_RUN`. With an external exact checkout, the tool verifies each original schema's Git blob identity before validating shape. The local export report—not the task's operational completion field—records that result. No AIDE runtime, queue adapter, grant, scheduler or model is invoked.

## Indexes, publication and integrity
```text
python spec/tools/specctl.py render-docs --output-dir /external/docs-review
python spec/tools/specctl.py seal
python spec/tools/specctl.py seal --check
python spec/tools/specctl.py package --output /external/Universal-Setup-Spec.zip
```

Render docs into review output, then merge into the existing `docs/` publication structure deliberately. Root README and existing authored tutorials are never overwritten. The generated pages are proposed design references, not current product documentation claiming implemented capabilities.

`seal` writes an inventory of all distributed files except `integrity.json` itself. It is an integrity record, not a signature or proof of trusted authorship. `package` requires a matching seal, refuses output overwrite/symlinks and emits only `spec/` entries in deterministic order with fixed ZIP metadata. Byte reproducibility is tested within the recorded Python/compressor environment, not promised across all compressor versions.

The intended edit loop is: edit authoritative concepts or acceptance/task designs -> validate -> schema-check -> run self-tests -> index -> index --check -> review -> seal -> package. Regeneration does not approve the changes.

## Safety and limitations
No default command calls network, models, package managers, Git, native installers or arbitrary document command text. Commands listed in tasks are display/test-plan data. Explicit generated-index/seal writes stay inside `spec/`; context, AIDE and documentation output must be outside it and outside a detected Git checkout. Test caches are avoided with `python -B` and excluded from the distribution.

Full legacy-OS tests, actual installation, power-loss qualification, GUI inspection, AIDE runtime interoperability and independent design review have not been performed by this tooling package. Keep those as separately admitted implementation/qualification WorkUnits.
