### Lite release profiles and compatibility

**Status:** the multi-profile contract is prepared source, not a qualified Lite 1.2 archive or new support claim. Lite 1.1 remains the published Windows-profile product. The [accepted development lifecycle](https://github.com/Julesc013/aide/blob/1e5193b0f1e7e8e3c14f30ba0124e8f44b799c9d/.aide/queue/AIDE-LITE-POSIX-LIFECYCLE-01/REPORT.md) is applicable evidence for unchanged behavior; the source repository's `AIDE-LITE-MULTIPROFILE-CONTRACT-01` WorkUnit owns this increment and its exact verification.

**One product, explicit profiles.** ZIP and TAR.GZ carry one Lite payload and product version. A profile identifies an exact OS/kernel/build, architecture and runtime recipe, its candidate support posture, capability labels and command contract. It does not create a separate OS fork, importer, authority, task history or version for each script. The existing stable release owner interprets `.aide/release/successor-candidate.json` in the source checkout; extracted release archives embed the declarations in `stable-release.json`. Project-owned profile/customization records remain separate and neither source-maintainer record is imported as target authority.

| Identity | Meaning |
| --- | --- |
| `aide.stable-successor-candidate.v1` | Historical single-profile Windows candidate format; existing behavior remains valid. |
| `aide.stable-successor-candidate.v2` | Adds bounded, explicit per-environment profile declarations. |
| `aide.stable-release-identity.v1` | Frozen historical Windows package identity; never relabelled using current policy. |
| `aide.stable-release-identity.v2` | Shared `aide-lite-local-cli` package identity with exact profile declarations. |
| Product SemVer | Versions the independently shipped Lite public contract, separately from the profile/schema formats. |

The existing 56 Windows forms remain in the proposed 1.2 contract. The original Windows 10 build 19045 profile retains all 56. The Windows Server 2025, Ubuntu 24.04 and macOS 15 candidates initially declare 49 forms, with seven managed setup/inspect/run/recover/wait forms unqualified. Lifecycle tests do not qualify Windows Job/token enforcement on another OS or automatically qualify every execution recipe on another Windows build. The final archive phase must verify each declared form and applicable refusal on its exact environment.

| Command disposition | Meaning |
| --- | --- |
| `supported_cli_forms` | Proposed public behavior for this profile; activation requires exact archive/consumer evidence and release acceptance. |
| `refused_cli_forms` | Proposed observable refusal contract; must be established by applicable negative tests before publication. |
| `unqualified_cli_forms` | Behavior remains outside this profile's promise. A route might exist or refuse; no successful operation or safe refusal is inferred. |

The three lists must be unique, disjoint and cover the package's complete public-form set. A missing entry is not treated as irrelevant or silently supported. Current additional-profile candidates leave the seven managed forms **unqualified**; they do not invent negative test results or claim those commands are always unavailable. Independent qualified inspection and lifecycle work can proceed without completing an optional managed execution backend.

**Strict, bounded data.** The existing ordinary-file reader rejects oversized, duplicate-key and malformed metadata. Candidate schemas and profile fields are explicit. Profiles include exact environment/runtime values, candidate support tier/state/mode/capability level, named capabilities, command dispositions and limitations. Unknown fields/schemas, duplicate IDs, invalid types, contradictory command sets, missing historical assets and inconsistent lineage refuse before archive writes. Candidate support values are declarations, not new grants or measured capability.

**Compatibility follows the owning profile.** Every preserved artifact retains its original schema, public forms, source, tag, hashes and policy identity. A multi-profile successor keeps the original Windows companion profile and its complete predecessor behavior. Future multi-profile predecessors cannot silently lose profiles, supported forms, explicit refusals or capabilities; a different exact environment gets a distinct profile identity. Adopting v2 from v1 requires a minor release even when global forms stay unchanged, as does additional profile behavior. A refusal cannot become unqualified or supported within this same-major helper. Incompatible changes require an explicit major-version migration/refusal decision.

**Qualification and publication remain separate.** Contract fixtures establish parser, lineage, marker and archive behavior using synthetic environments. They do not establish OS support. Later versioned-archive checks bind the declared forms to actual environments, direct edits/customization, the published 1.1 predecessor, real conflicts, recovery, safe exit and exact frozen hashes. Publication and acquired-byte acceptance need separately reviewed effects. Historical qualification and valid unchanged evidence remain attached to their original subjects.

**Native execution and native host integration are different axes.** The POSIX binding uses real Linux/macOS filesystem operations. Lite remains an adjacent CLI, represented as `companion` integration; that label does not mean emulation or completion of a native IDE extension. A future Extension, harness, service or application receives its own release only when independently shipped, using its own exact host/backend profile and the shared work/authority/evidence contracts. Legacy native ports retain their staged target/toolchain evidence requirements; a companion route does not complete them.
