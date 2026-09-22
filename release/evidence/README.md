# Release evidence receipts

This directory holds immutable, reviewable receipts used to advance current
programme predicates. A file hash alone is not evidence of a release claim.
`spec/tools/specctl.py` accepts only claim-specific
`universal.programme_evidence/1` JSON records here and cross-checks their
candidate, source, qualification, integration, publication, and maintenance
fields as applicable.

Effectful campaign tasks additionally require an admitted
`universal.effect_target_receipt.v1` record here. The campaign binding tool
checks its campaign, WorkUnit, target, environment, effect class, allowed
effects, and unexpired time window. Receipts do not widen a WorkUnit template,
create credentials, waive tests, or turn agent observations into human ones.
