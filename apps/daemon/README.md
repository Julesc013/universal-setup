# Daemon

Universal Setup daemon/job-runner entrypoint. Mutation authority remains in `runtime/setup/`.

On Windows x64, `usk_publisher_service_control` configures the selected
restricted-service publisher without using a campaign VM identity or a lab
receipt path. Registration takes an already protected dedicated NTFS volume,
a reviewed plan envelope, its exact SHA-256, and the authorized caller SID:

```text
usk_publisher_service_control --register USK_PUB_<32 lowercase hex> SERVICE_EXE VOLUME_GUID_ROOT ENVELOPE_JSON ENVELOPE_SHA256 CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --recover USK_PUB_<same name> SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --verify USK_PUB_<same name> SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
usk_publisher_service_control --start USK_PUB_<same name> SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer|--grant-client-read]
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
