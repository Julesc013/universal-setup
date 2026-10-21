# Managed Section Operations

Managed-section transaction records describe edits bounded by explicit begin and end markers. A valid managed-section operation records the target path, section id, marker strings, preimage hash, predicted postimage hash, staged replacement, rollback record, and safety gates.

AIDE-APPLY-00 can plan and verify managed-section records in fixtures only. It does not write managed sections to active repository files and does not remove managed sections.

Future managed-section patching must preserve manual content outside markers, reject missing or duplicated markers unless explicitly reviewed, record preimages before postimages, and create rollback records before any reviewed apply step.

AIDE-APPLY-01 implements the fixture-safe parser and patch planner for this
record shape. It recognizes canonical `AIDE-GENERATED` markers, computes exact
section and manual prefix/suffix hashes, blocks missing, duplicated, nested, and
malformed marker cases, and writes fixture-only reports through
`managed-section status`, `managed-section validate`, `managed-section
fixture-plan`, and `managed-section fixture-verify`.

AIDE-APPLY-01 still does not expose active repository apply behavior. The new
patcher is a reusable planning and verification primitive for later reviewed
install or upgrade phases, not an apply mode.
