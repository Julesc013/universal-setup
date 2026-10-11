# Authored plan to selected protected apply

`usk_bundle_apply_binding.py` connects a successful `usk_machine install_local.plan`
response to the existing restricted-service candidate. It writes an exact
`install_local.apply` request and its digest-bound service envelope in a new
operator-owned directory. The selected profile currently requires a dedicated
NTFS drive root, `publication/destination/visible` as its target, and
`setup-state` as its state root. The tool checks those paths, selected components,
archive identity, native plan digest and required commit authority before
writing either file. The service independently revalidates the binding.

The hosted Windows probe uses this tool with an authored, finalized bundle,
then submits the generated request through `usk_publisher_client` to the
restricted service. Service provisioning, ACL admission, cleanup and
independent state observation remain explicit parts of that probe. This
candidate path does not qualify ordinary customer installation or enable the
public strict publisher gate.
