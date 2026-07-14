# Setup Kernel

Context, response lifetime, command descriptors, bounded introspection, and
setup command dispatch live here.

The built-in descriptor registry is authoritative for both lookup and graph
projection. M2 public lifecycle handlers are built in and product-neutral; the
registry is not a plugin host and accepts no product-provided executable
handlers. Recovery apply and audit query/export remain declared but
non-executable until their bounded implementations land.

`usk_config_v1` accepts its original prefix, the M1 allocator layout, or the
complete structure. The complete form adds `authorized_acceptance_root` and
`target_policy_activation`; public lifecycle commands also require
`state_root`. Configuration strings are copied into the context. Legacy and
unconfigured contexts remain ABI-valid but lifecycle work fails closed.

Projected graph responses and copied configuration use the caller allocator;
package, archive, and lifecycle responses retain their originating allocator
provenance. All response views are borrowed until the next command call or
context destruction.
