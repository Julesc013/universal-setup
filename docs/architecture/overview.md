# Architecture Overview

Universal Setup is a deterministic setup control plane. It parses install
manifests, resolves component graphs, executes setup transactions, records
installed state, supports repair/uninstall/rollback, and emits audit logs.

Platform frontends and package formats are thin adapters over the same setup
kernel.
