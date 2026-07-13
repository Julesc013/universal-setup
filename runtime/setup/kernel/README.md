# Setup Kernel

Context, response lifetime, command descriptors, bounded introspection, and
setup command dispatch live here.

The built-in descriptor registry is authoritative for both lookup and graph
projection. Planned M1 commands are declared but non-executable until their
versioned contracts and lifecycle implementations land. The registry is not a
plugin host and accepts no product-provided executable handlers.

`usk_config_v1` accepts its original prefix or a complete structure containing
an optional allocator. Projected graph responses use that allocator; package
verification responses retain their verifier allocator provenance. Both are
borrowed until the next command call or context destruction.
