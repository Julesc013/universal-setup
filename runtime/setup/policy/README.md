# Policy

`usk_target_policy` is the product-neutral M2 live-target authority boundary.
It consumes already inspected target evidence, binds every decision into a
deterministic digest, and refuses unless all of these are explicit:

- the target is an `operator_acceptance` or accepted `managed_portable` root;
- an absolute operator-supplied path is nonexistent or proven empty;
- the filesystem is local and identity-bound;
- every ancestor is stable and no mount redirection is present;
- no protected, cloud-synchronized, Steam, or foreign-owned root matched;
- required space is available and source and target are distinct objects; and
- every persistent effect is available for operator review.

The evaluator performs no I/O and grants no mutation by itself. WU2 must feed
it evidence produced by stable platform inspection and must re-evaluate the
same digest-bound inputs immediately before any apply operation.

`operator_acceptance_candidate` permits only the dedicated synthetic M2 lane.
`managed_portable` remains refused with `live_target_acceptance_required` until
a separate human M2 Pass promotes the activation to `accepted_live_portable`.
