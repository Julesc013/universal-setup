# Package

Local archive and future package-manager/bundle handoff helpers live here. This
module does not define product-specific installer behavior.

M1-WU3 implements read-only classic and ZIP64 inspection for
`install_local.inspect`. It opens a stable source handle, hashes the exact
archive, validates central and local header agreement, normalizes an ASCII-only
portable path subset, applies count/size/depth/ratio/elapsed budgets, and emits
a deterministic planned entry-set digest. Callers select a positive elapsed
budget up to the provider's finite ten-minute ceiling; the provider continues
to fail closed when that budget expires.

The request codec uses the shared bounded strict JSON parser and requires exact
closed root and `budgets` objects. Duplicate, missing, unexpected, misplaced,
wrongly typed, out-of-range, invalid-UTF-8, and trailing request content is
refused before the archive source is opened. In addition to JSON Schema's
character limit, `archive_path` has a declared 32768-byte UTF-8 envelope. The
path must be absolute, local, and already lexically normalized. UNC and device
namespaces are refused. The codec converts strict UTF-8 explicitly through the
host-native filesystem representation and requires the same UTF-8 identity on
output; it never relies on locale-dependent narrow path conversion.

The ZIP profile accepts only single-disk ZIP64 end records and exact ZIP64
extra fields required by sentinel metadata. It rejects missing, duplicate,
unnecessary, truncated, or inconsistent ZIP64 metadata, plus multi-disk,
streamed, encrypted, patched, AES, alternate-Unicode-path, non-ASCII-path,
preamble, unclaimed-byte, link/device/reparse-like, and
unsupported-compression input. Later WorkUnits may widen formats or Unicode
support only with equivalent normalization and collision proof.

Inspection never extracts an entry, creates setup state, or touches a target.

The private stored-payload successor performs a second stable-handle identity
and source-digest check, incrementally verifies each selected entry through a
caller-bounded buffer, and returns size/hash/CRC metadata plus bounded readers.
The public install and repair lifecycle consumes those readers directly through
transaction streaming. Classic and single-disk ZIP64 stored entries share this
path. Deflate remains inspectable but is refused for lifecycle streaming because
the provider has no reviewed decompressor dependency.
