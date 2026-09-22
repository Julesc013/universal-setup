# Windows NTFS publication profile — candidate only

`windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is a proposed publication design. It has no implementation, availability is false, qualification is `not_run`, and support is `unsupported`. This page is neither a runtime claim nor authority to mutate an endpoint.

## Eligibility and nonclaims

The profile is eligible only for Windows NT x64 on the same live, local NTFS volume, observed through bound directory and file handles. A dedicated publisher service uses `SERVICE_SID_TYPE_RESTRICTED`; it creates protected staging and destination DACL anchors owned by `SYSTEM`. Eligibility refuses case-sensitive or reparse ancestors, ADS, multiple links, pre-opened hostile handles, remote/non-NTFS/cross-volume paths, or any SID/DACL setup failure.

Caller booleans, path strings, hashes, and journal IDs are assertions, not evidence. They cannot make this unavailable candidate eligible, qualified, or supported. It excludes administrators, `SYSTEM`, publisher compromise, kernel/filter compromise, offline storage manipulation, denial of service, and unqualified power loss.

## Adversary matrix

| Actor or condition | Candidate disposition |
|---|---|
| Unprivileged other user / same-user hostile process | In scope; handle, SID, DACL, and closure protections are the proposed mechanism. |
| Identical or changed staged substitution; insertion | In scope; refuse unless bound identity and closure remain exact. |
| Reparse, hardlink, ADS, parent substitution, destination precreation | Refuse before visibility. |
| DACL/owner mutation or hostile pre-opened handle | Refuse and retain. |
| Administrator, SYSTEM, service compromise, kernel/filter, offline storage, DoS, unqualified power loss | Explicitly outside the claim. |

## Invariants and protocol

The publisher uses handles, never a re-resolved path, for preflight, protected-stage creation, materialization, closure observation, and destination binding. Closure size, depth, component name, and bytes are bounded. The service durably records `publish_prepared` before visibility, renames with `SetFileInformationByHandle(FileRenameInfo)` and `ReplaceIfExists=FALSE` relative to the bound destination parent, then checks visible `FILE_ID_INFO` and the full closure. Only after that does it durably record `visible_bound` and attempt metadata.

The visible identity and closure must equal the verified identity and closure before completion. A foreign object never completes. Availability false produces no-effect refusal. `publish_prepared` precedes rename, and one generation may complete once only.

## Crash, recovery, and replacement visibility

Before rename, failure retains staging. After rename but before metadata, result is `recovery_required`, with no manufactured completion and no deletion of ambiguous material. Recovery is retain-only until an independent operator/evidence process establishes ownership.

Replacement is not atomic exchange: it is a journaled two-rename sequence and has a reader visibility gap. This profile therefore makes no continuous-reader or atomic-replacement promise.

## Refusal corpus and evidence needed

The deterministic oracle corpus covers protected success, concurrent loser, identical/changed substitution, insertion, reparse/hardlink/ADS, parent substitution, destination precreation, ACL/owner mutation, hostile open handle, SID failure, non-NTFS/remote/cross-volume, crash prefixes, metadata failure, and a privileged attacker outside the claim. It does not establish platform behavior.

Evidence still required: admitted Windows attack execution on the exact implementation candidate; exact target and NTFS configuration receipt; independent technical/security review. These obligations keep OD-001 open and block WU-006.

## WU-006 handoff

WU-006 must consume the candidate only after the missing target-bound evidence exists. It must not treat this specification, deterministic model, fixture, or a caller assertion as a resolved platform-security decision.
