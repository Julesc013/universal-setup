# Capability Reality Ledger

X-OS-02 adds a report-only capability reality ledger for AIDE Task OS. It classifies source-repository evidence into controlled capability states without treating docs, fixtures, dry-runs, no-call metadata, release drafts, or target-specific notes as live product behavior.

## Command Surface

- `py -3 .aide/scripts/aide_lite.py capability status`
- `py -3 .aide/scripts/aide_lite.py capability scan`
- `py -3 .aide/scripts/aide_lite.py capability ledger`
- `py -3 .aide/scripts/aide_lite.py capability overclaim-report`
- `py -3 .aide/scripts/aide_lite.py capability validate`

## Source Contracts

- `.aide/policies/capability-reality.yaml`: controlled states, evidence classes, modifiers, overclaim classes, and proof rules.
- `.aide/capabilities/capability-seeds.yaml`: current conservative seed records.
- `.aide/capabilities/capability-observation.schema.json`: generated observation report shape.
- `.aide/capabilities/capability-overclaim.schema.json`: generated overclaim report shape.
- `.aide/ledgers/capability-ledger.schema.json`: generated capability ledger shape.
- `.aide/capabilities/capability-evidence-bindings.schema.json`: optional derived
  binding projection; the v0 ledger shape and canonical seed authority remain unchanged.

## Generated Reports

- `.aide/reports/capability-command-status.md`
- `.aide/reports/capability-observations.json`
- `.aide/reports/capability-observations.md`
- `.aide/reports/capability-ledger.json`
- `.aide/reports/capability-ledger.md`
- `.aide/reports/capability-evidence-bindings.json`
- `.aide/reports/capability-overclaims.json`
- `.aide/reports/capability-overclaims.md`
- `.aide/reports/capability-validation.md`

## States

Capability records use `planned`, `specified`, `stubbed`, `implemented`, `tested`, `exposed`, `documented`, `deprecated`, `removed`, and `unknown`.

The dominant state is a conservative source classification constrained by the seed.
Missing evidence stays unknown. Implementation/exposure requires a code reference;
the seeded tested classification requires a test reference. Test-file presence
does not add an executed-test observation. These classifications and matching
source hashes are not evidence that tests ran or a host was qualified.

## Evidence Freshness and Explicit Refresh

`capability ledger` explicitly writes the ledger and its derived bindings.
Bindings cover the finite declared public file hints, seeds, policy, required
capability records and producer, plus the parsed ledger's deterministic digest.
They confer no additional authority and provide no cryptographic attestation.
The ledger classification uses the seed bytes and observed references from that
same captured snapshot. A source edit during generation therefore invalidates
the resulting bindings; old classifications cannot be rebound to newer inputs.

`capability status` reports `ledger_evidence_validity`:

- `CURRENT`: all bound public inputs are present and unchanged.
- `STALE`: a bound input changed, its presence changed, or the retained ledger
  no longer matches the binding. Status identifies changed references.
- `UNKNOWN`: legacy bindings are absent, malformed, incomplete, or unreadable.
  Missing, excluded and over-budget evidence remains unverified.

`capability validate` inspects retained evidence and writes its validation view.
It fails for stale or unknown ledger bindings. It does not regenerate the scan,
ledger or overclaim report. Refresh deliberately with `capability ledger`;
generate missing scan and overclaim reports using their own commands. Unrelated
file edits do not invalidate declared bindings. Other reports remain separate
classification views; this projection qualifies ledger freshness only.

The binding snapshot selects at most 128 references, reads at most 4 MiB per
file and 16 MiB in total, and preserves incomplete/truncated coverage as unknown.
It excludes private/secret-like paths, ignored files, external URIs, non-relative
paths, symlinks/reparse components, shared hard-link identities and nonordinary
files. No URI is fetched.
Read identity changes cause unknown observations. These conservative reader
checks are not filesystem confinement, a disk quota, or protection for another
unrestricted editor or plugin. The outer session still needs its own boundary.

The binding and ledger are separate writes. An interrupted pair cannot be called
current: a missing binding is unknown; a mismatched digest is stale. This repair
does not relabel existing immutable release assets as containing new source.

## Overclaim Rules

The ledger keeps these boundaries explicit:

- docs-only evidence is not implementation proof
- fixture-only evidence is not production behavior
- report-only commands are not apply behavior
- no-call provider metadata is not live provider integration
- release drafts are not publication
- dry-runs are not install, repair, upgrade, rollback, uninstall, or transaction apply
- source-generated state is not target truth
- target-pilot evidence is not product-general availability
- unknown state is not verified state

## Boundary

X-OS-02 does not execute tasks, repairs, branches, targets, releases, providers, models, network calls, schedulers, workers, Runtime, Hosts, Commander, Mobile, Gateway forwarding, MCP/A2A, UI, or app-surface behavior. Generated capability reports are source-side evidence only. Target repositories must generate their own capability reality evidence after import.
