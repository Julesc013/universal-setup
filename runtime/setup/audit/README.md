# Setup Audit

The WU5 audit repository stores immutable canonical events in one explicitly
initialized directory per audit chain. Filenames encode a zero-based sequence;
each event binds the previous event digest. There is no mutable head file.

Append first revalidates the complete bounded chain, then attempts a durable
no-clobber write for the next sequence. Competing writers therefore cannot
silently overwrite one another. Reads reject gaps, reordering, unknown files,
non-canonical JSON, identity drift, and broken payload or previous-event
digests.
