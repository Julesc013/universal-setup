# Ownership

Installed-file ownership records and refusal checks. Setup may mutate only
state that a manifest, transaction, and ownership record authorize.

WU5 ownership manifests are canonical, digest-bound, and no-clobber. Their file
entries bind normalized relative paths, SHA-256, and size. Their directory list
must contain the complete parent closure for every file. Duplicate paths,
file/directory overlap, missing parents, unsafe paths, and digest drift are
refused before the record can authorize later repair or uninstall work.
