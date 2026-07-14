<!-- SPDX-FileCopyrightText: 2026 Jules C -->
<!-- SPDX-License-Identifier: MIT -->

# M2-WU4 Live Synthetic Install Acceptance

Status: automated lifecycle findings complete; human verdict `pending`.

This record binds the first retained run of the bounded M2 acceptance CLI. It
is an implementation and machine-observation result, not a human `Pass`, an
ordinary live-apply promotion, a Factorio archive acceptance, or execution
authority.

## Run identity

| Evidence | Identity |
| --- | --- |
| Universal Setup runner revision | `6209385f25db1824bcbb7ec599cf2152606be89b` |
| consumer revision | `a8b298a35cd1587cea566886b5a3891153a2b7f2` |
| acceptance root | `D:\FacMan-Live-Acceptance\M2` |
| exclusive run ID | `m2wu4-20260714-01` |
| summary SHA-256 | `0d42f22f40aa2b92df49b8bd872db9ad2367c5000d615a6d982f25e4ee0a0507` |
| synthetic archive SHA-256 | `02bed514abfac0145cb8e57008aeff3f2107715ea8a3f57ebed78ce456b2ddbf` |
| audit chain | `audit.synthetic.m2.m2wu4-20260714-01` |
| audit head | `8228808f068e7e929d7490ce05c1e2c56e3d4155cfdfad88cd354cc070db2dc1` |
| audit events | `5` |
| audit tree SHA-256 | `dbcb3067189b7c0f5ddbdb2f843a00d6db51d0b912d2f186ec955a5bdf5d3c19` |

The archive contains three harmless text/data files and no executable code.
The source archive remains preserved after uninstall.

## Lifecycle result

1. A digest-bound install plan exposed the exact source, target, filesystem,
   file-count, byte-count, effects, and refusal policy.
2. Apply committed a new target without clobbering and verification passed.
3. Deliberate modification of an owned configuration file was detected as the
   expected verification failure.
4. Repair used the exact bound source and restored a passing closure.
5. Same-volume move verified the new root and retained the old root for later
   acceptance, as required by the move state machine.
6. Cross-volume move was not attempted because no second volume was authorized.
7. An introduced unknown file caused `foreign_content_review_required`; setup
   retained it and performed no uninstall mutation.
8. The runner recorded its exact external removal of that one foreign file as
   outside setup ownership, then clean uninstall removed the current owned root.
9. The final installed state is `retired`, committed closure is `removed`, and
   recovery status is `not_required`.

The old pre-move root remains under the run root by design. The moved/current
root is absent. This is the truthful `new_committed_old_retained` move policy,
not a global filesystem transaction claim.

## Immutable operation packets

| Operation | Packet digest | Stored file SHA-256 |
| --- | --- | --- |
| install | `b0142866654c5fcff24d4c04d8665cfc55f1e107f1cc4454f59e6e139913b225` | `9b0dfa22fbaa8dfa5af4b70e0ef29587f94c7fbb8b1152f0c02a6361a4ab38b1` |
| repair | `14eec52ae99058d93f1ad6f56ddb9cb97452503c64f92521de06a66349029ea6` | `4d1dcb0be02e22bf430d8ec9f8bdfc8cf3d5bfbeb1025a56a72286660ccc8739` |
| move | `7b01758b510e65a3007681c196cfd4703c1e83c6614f8edde806d9613673ef8d` | `4417b8ac0cbd35c3c4d0eb6ceff5905354a5be8c138d79b54708e76b496c383b` |
| uninstall | `1f4960afad49f519f191b2d6d5e33fb3f13adb90b4bd65fe058a43b80b798b0b` | `a0de7a6773249f349c364365762181ec9f110ee5a570431d30618deb3b0b6a2e` |

The final packet binds installed-state digest
`180c9962db0346442cfdb5a404765ac8d3c8d5a01f0d4c65ad1e3f497d2a7dd0`
and ownership digest
`ccd52536ea44b75f58e44b6c6035d7e213ad3724c30bd8f746c6f3a33d41ba5c`.
Every packet retains `operator_verdict.status = pending`.

## Retained authority boundary

- ordinary `managed_portable` apply remains unavailable;
- `recovery.apply` remains unavailable pending M2-WU5;
- no existing installation or Steam path was touched;
- no network, credential, registry, shortcut, elevation, package-manager,
  installer, product executable, signing, or publication behavior occurred;
- no H1 or Safe-beta inference is made.
