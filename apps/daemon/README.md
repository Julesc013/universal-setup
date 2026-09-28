# Daemon

Universal Setup daemon/job-runner entrypoint. Mutation authority remains in `runtime/setup/`.

On Windows x64, `usk_publisher_service_control` configures the selected
restricted-service publisher without using a campaign VM identity or a lab
receipt path. Registration takes an already protected dedicated NTFS volume,
a reviewed plan envelope, its exact SHA-256, and the authorized caller SID:

```text
usk_publisher_service_control --register USK_PUB_<32 lowercase hex> SERVICE_EXE VOLUME_GUID_ROOT ENVELOPE_JSON ENVELOPE_SHA256 CALLER_SID [--admit-client-observer]
usk_publisher_service_control --recover USK_PUB_<same name> SERVICE_EXE VOLUME_GUID_ROOT CALLER_SID [--admit-client-observer]
```

The second command changes only a stopped, matching own-process LocalSystem
service with a restricted service SID. It keeps that service name and SID for
source-free recovery. The optional observer flag permits a specifically bound
non-admin caller to verify the service process; it grants no installed payload
access. Registration and reconfiguration do not start the service or qualify
the volume. The publisher itself revalidates the reviewed source, held volume,
protected root and authenticated request when started. This selected profile
is still a candidate; the general product host and public capability gate
remain unfinished.
