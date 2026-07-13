# Package

Local archive and future package-manager/bundle handoff helpers live here. This
module does not define product-specific installer behavior.

M1-WU3 implements read-only classic ZIP inspection for
`install_local.inspect`. It opens a stable source handle, hashes the exact
archive, validates central and local header agreement, normalizes an ASCII-only
portable path subset, applies count/size/depth/ratio/elapsed budgets, and emits
a deterministic planned entry-set digest.

The WU3 ZIP profile deliberately refuses ZIP64, multi-disk, streamed,
encrypted, patched, AES, alternate-Unicode-path, non-ASCII-path, preamble,
unclaimed-byte, link/device/reparse-like, and unsupported-compression input.
Later WorkUnits may widen formats or Unicode support only with equivalent
normalization and collision proof.

Inspection never extracts an entry, creates setup state, or touches a target.
