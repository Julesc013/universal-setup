# Managed Portable Lifecycle

This module composes setup-owned planning, transaction, state, ownership, and
audit primitives into fixture-backed local portable install, verify, repair,
move, uninstall, and visible-target recovery journeys.

It is an internal proof consumer. The native kernel command descriptors still
mark lifecycle apply commands unavailable, so ordinary CLI, GUI, and SDK
clients cannot invoke this mutation layer. Product recipes and archive decoding
remain outside this module.
