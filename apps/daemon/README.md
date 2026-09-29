# Daemon

Universal Setup daemon/job-runner entrypoint. Mutation authority remains in `runtime/setup/`.

On Windows x64, `usk_publisher_service_control` configures the selected
restricted-service publisher without using a campaign VM identity or a lab
receipt path. Registration takes an already protected dedicated NTFS volume,
a reviewed plan envelope, its exact SHA-256, the authorized caller SID, and
the expected SHA-256 of the publisher executable. Registration streams the
executable into a newly created, protected per-service file under
`Program Files/Universal Setup/Publisher`, verifies its digest and flushes it
before creating the LocalSystem service. Later commands take that installed
path. The source executable may be in an untrusted staging directory, but its
expected digest must come from the reviewed package identity:

```text
usk_publisher_service_control --register USK_PUB_<32 lowercase hex> SOURCE_SERVICE_EXE VOLUME_GUID_ROOT ENVELOPE_JSON ENVELOPE_SHA256 CALLER_SID SERVICE_EXE_SHA256 [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --recover USK_PUB_<same name> INSTALLED_SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --verify USK_PUB_<same name> INSTALLED_SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --start USK_PUB_<same name> INSTALLED_SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --unregister USK_PUB_<same name> INSTALLED_SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
```

The second command changes only a stopped, matching own-process LocalSystem
service with a restricted service SID. It keeps that service name and SID for
source-free recovery. The optional observer flag permits a specifically bound
non-admin caller to verify the service process; it grants no installed payload
access. The separate `--grant-client-read` mode binds the authorized caller SID
into the durable reviewed snapshot and grants only read and execute access to
the completed visible payload. Use the same mode for source-free recovery and
installed verification; the latter requires every visible object to retain
the exact grant. Start requests require a stopped service and recheck its own-process,
restricted-SID, executable, volume, caller, and observer configuration. A
successful start request does not claim the setup operation succeeded; the
authenticated client must inspect its terminal response. Registration and
reconfiguration do not start the service or qualify the volume. The publisher
itself revalidates the reviewed source, held volume,
protected root and authenticated request when started. This selected profile
is still a candidate; the general product host and public capability gate
remain unfinished.

A reviewed plan may select an ASCII final directory name beneath the dedicated
volume's protected `publication/destination` parent. Recovery and verification
bind that name to the durable reviewed snapshot before opening the directory.
A different parent or a noncanonical final name is refused. Arbitrary product
target roots are not yet admitted.

Unregister requires the service to be stopped and rechecks its generated name,
executable path, volume, authorized caller, access mode, own-process account,
and restricted service SID. Its `removal_requested` reply means Windows accepted
the deletion request; callers must independently wait until the service is
absent before reclaiming its owned volume or installed executable. A failed
registration removes only the per-service executable it created.
Registration, configuration, start, and removal hold one empty per-service
lock file beneath the protected `Program Files/Universal Setup/PublisherControl`
directory. The controller verifies its owner, protected ACL, and ordinary-file
shape. The lock file remains after a deletion request so another controller
cannot enter a different lock domain while Windows still retains the service.

The packaged request client may be started as soon as `--start` returns. It
waits within its transport deadline while the same restricted own-process
service reports `START_PENDING`, then pins the running process before opening
its authenticated pipe. A service that stops, changes type, or never becomes
ready refuses before a request is sent.

The registered service handles one authenticated request. After writing its
terminal reply, it holds the pipe until that client disconnects, then stops.
This lets the same service be reconfigured for verification or recovery after
the caller has received the reply. A vanished or unresponsive client cannot
keep it running beyond the bounded transport wait. A disconnected client may
still have an unknown operation outcome and must use the existing retry or
source-free recovery path; service shutdown is not an install success signal.

The separate `usk_publisher_lab_service_fault` target exists only when tests
are enabled. Its extra receipt-backed poststage gate lets a disposable hosted
VM stop the registered service after a durable snapshot and staged tree, then
exercise the normal source-free recovery command. A controlled service stop is
recorded as process cancellation, not as power-loss evidence. The ordinary
`usk_publisher_lab_service` executable does not accept that gate grammar.

`usk_publisher_client` returns 0 only for a complete `pass` response. It returns
3 for a complete `failed` or `recovery_required` response, 5 when a submitted
request or its response/output has an unknown outcome, and 2 for local
validation or pre-send refusal. On exit 5, reconnect with the same reviewed
request or use source-free recovery; the exit code does not establish that no
publication effects occurred. The packaged machine client uses the same
unknown-outcome distinction.
