ChatGPT Pro




























5-setup-multicraft-on-windows-server.jpg
14-multicraft-setup-wizard.jpg
allthings.how-how-to-get-minecraft-on-windows-11-image-23.png
minecraft-installer.jpg
minecraft-launcher-setup-window.jpg
0aee6206-2b69-4999-a242-781084146da0.png
GPT-5.2 MASTER PROMPT — DOMINIUM / DOMINO SETUP & INSTALLATION SYSTEM
Cross-Platform Installers, Package Managers, and Distribution Pipelines

You are acting as a systems architect and build/distribution engineer for the Dominium / Domino ecosystem.

This chat is NOT about the launcher UI.
This chat is about setup, installation, packaging, distribution, and uninstallation across all supported platforms.

Assume:

The launcher architecture is already designed and implemented (Plan 8 + launcher prompts).

The engine, launcher, packs, tools, and artifacts exist as installable payloads.

Your task is to design a fully modular, deterministic, cross-platform setup system that mirrors the launcher’s architectural rigor.

0. LEGAL / IP CONSTRAINTS (ABSOLUTE)

Do NOT copy Microsoft, Apple, Steam, or Linux distro branding, text, logos, or UI assets.

You MAY emulate structural installer patterns:

Windows MSI-style wizard

macOS .pkg / .dmg style installer

Linux package manager conventions

Steam install/update semantics

All UI text must be original and generic.

1. CORE PHILOSOPHY (LOCK THIS IN)

The setup system is:

A deployment control plane, not a UI gimmick

Deterministic and auditable

Reversible (clean uninstall / rollback)

Scriptable and headless-capable

Modular and future-proof (decades-long support)

The setup system is NOT:

Just a GUI wizard

A monolithic OS-specific mess

A background service

A store or DRM mechanism

2. GLOBAL NON-NEGOTIABLE CONSTRAINTS
Architecture

One common setup core, shared across all platforms

Platform-specific front-ends (MSI, PKG, deb/rpm, Steam, etc.) are thin adapters

No business logic duplicated per OS

Language & Boundaries

Setup core: C or C++ (C89/C++98 compatible preferred)

Platform adapters may use:

Windows Installer tooling

macOS Installer / pkgbuild

Linux packaging tools

SteamPipe

Clear ABI/API boundaries

Determinism

Same input manifests → same installed layout

Installation decisions must be logged and inspectable

No silent behavior

Persistence & Metadata

Use versioned manifests (TLV or equivalent):

install plan

installed state

component list

rollback info

Skip-unknown, forward-compatible

3. SETUP SYSTEM ROLE IN THE ECOSYSTEM

The setup system is responsible for:

Installing:

launcher

engine/runtime

tools

base packs

optional packs

Registering:

file associations

start menu / app entries

Steam metadata (if applicable)

Uninstalling and repairing

Upgrading and side-by-side installs

Integrating with OS and package managers

Producing installed-state manifests that the launcher consumes

The launcher does not install itself.

4. COMMON SETUP CORE (MANDATORY)

Design a Setup Core analogous to the Launcher Core.

Responsibilities

Parse install manifests

Resolve component graph

Execute install transactions

Record installed state

Support:

install

upgrade

repair

uninstall

Emit audit logs

Must support

GUI-driven install

CLI/headless install

Package-manager-driven install (Linux)

Steam-driven install

5. INSTALL MANIFEST MODEL

Define an Install Manifest schema:

Contents

product id

version

target platform(s)

components:

launcher

engine/runtime

tools

packs

install locations (with defaults + overrides)

optional components

dependencies

conflicts

post-install hooks (data-only, declarative)

uninstall rules

Rules

Deterministic resolution

No executable scripts unless strictly sandboxed

Skip-unknown support

6. INSTALL TRANSACTION ENGINE

Just like the launcher:

stage → verify → commit → rollback

no in-place mutation of live installs

uninstall must reverse install cleanly

upgrade must preserve user data unless explicitly removed

Support:

side-by-side installs

version pinning

rollback on failure

7. PLATFORM-SPECIFIC ADAPTERS

Design thin adapters for each platform that call the common setup core.

7.1 Windows

Support:

MSI-style wizard UI

Silent install (/quiet)

Per-user vs system installs

Registry entries

Add/Remove Programs integration

Adapter responsibilities:

UI + elevation

calling setup core with parameters

7.2 macOS

Support:

.pkg installer

.dmg distribution

Gatekeeper-friendly layout

Codesigning hooks (design only)

Adapter responsibilities:

UI flow

sandbox-safe file placement

calling setup core

7.3 Linux

Support:

tarball (portable)

deb

rpm

pacman (optional)

Flatpak/AppImage (optional design)

Respect:

FHS paths

package manager ownership

headless installs

7.4 Steam

Support:

SteamPipe content layout

Steam install/update/uninstall lifecycle

launcher invoked as Steam “game”

Steam does NOT bypass setup core logic

Steam adapter:

maps Steam install events to setup core operations

records installed state identically

8. CLI INSTALLER (MANDATORY)

Provide a headless installer CLI:

Examples:

dominium-setup install

dominium-setup uninstall

dominium-setup repair

dominium-setup upgrade

dominium-setup list-installed

dominium-setup verify

Rules:

Scriptable

Deterministic output

No UI dependency

9. INSTALLED STATE & HANDOFF TO LAUNCHER

Define how setup hands off to launcher:

Installed-state manifest location

Component versions + hashes

Paths and permissions

First-run markers

Launcher must:

Read installed state

Refuse to run if corrupted or incomplete

Never assume installation succeeded

10. UNINSTALL, REPAIR, AND FORENSICS

Design for:

Clean uninstall

Repair install

Partial install recovery

“What did this installer touch?” reporting

No orphaned files unless explicitly documented.

11. TESTING STRATEGY

Plan tests for:

Fresh install

Upgrade

Repair

Uninstall

Rollback on failure

Headless install

Steam install/update simulation

Linux package manager integration

Testing must be automatable.

12. DOCUMENTATION TO PRODUCE

This chat must design documentation for:

Setup architecture

Install manifest schema

Platform adapter behavior

CLI usage

Steam integration

Troubleshooting and recovery

13. STRUCTURE OF THIS CHAT

Proceed in phases, similar to the launcher work:

Setup Core architecture

Install manifest schema

Transaction engine

Platform adapters (Win/macOS/Linux)

Steam integration

CLI installer

Uninstall/repair model

Testing + docs

Do not jump ahead.
Do not collapse steps prematurely.

FINAL INSTRUCTION

Speak with engineering precision, not marketing tone.
No filler. No hype. No assumptions.
Design for decades-long support and hostile environments (offline, broken systems, old OSes).

Begin with Phase 1: Setup Core Architecture.

Okay let's start from scratch with an empty /source/setup/ directory.
I want to create a windows setup using VS 2026 that will compile for Windows NT in 32 and 64 bit.
I want to create another windows setup using watcom or alternatives for Windows 9x.
I want to create an installer for Mac OS X 10.4 to current Mac OS release using Xcode, for Intel and ARM in 32 and 64 bit.
And I will want to create an installer for Linux systems from roughly 2000 onwards and package managers and steam and epic games and web and consoles and retro/legacy etc.
How should I best approach this, allowing me to use the native IDEs for easy of programming and integration, while maintaining modularity, extensibility, and robustness.
Make sure the directory structure is simple, not too deep, and logical and intuitive, and consistent with industry practices for this type of product and code.

I will read the generated package files from the sandbox and render a navigable in-chat reader version without creating another package.

I’ll preserve the package’s stable IDs, labels, caveats, and uncertainty markings while converting its contents into the requested readable report.

Thought for 11m 42s
GPT-5.5 Pro — 2026-05-27 15:37:52

IN-CHAT REPORT READER — Dominium Setup Handoff
0. Reader Navigation
This is a readable, navigable rendering of the already-generated Dominium Setup Handoff report package. I inspected the generated package files directly from /mnt/data and used the package contents as the primary source.

Table of contents
Section	Purpose	Best for
1. Package Overview	Metadata, confidence, caveats	First read
2. Generated File Index	Explains every generated file	Understanding the package
3. Executive Summary	500–1,000 word overview	Fast full-context orientation
4. Plain-English Package Explanation	How this chat fits the larger project	Spec-book planning
5. Workstreams / Projects / Plans	Every workstream with IDs	Navigation and follow-up
6. Decisions Already Made	Decision register	Preventing repeated debate
7. Pending Tasks and Next Actions	Task register and order	Resuming work
8. Constraints and Requirements	Hard/soft requirements	Avoiding violations
9. User Preferences	Explicit/inferred preferences	Assistant behavior
10. Open Questions	Unknowns and verification needs	Before implementation
11. Rejected / Superseded Options	Ruled-out paths	Avoiding old mistakes
12. Artifact Ledger	Files, prompts, outputs, plans	Preservation and aggregation
13. Risks and Failure Modes	Failure register	Risk control
14. Verification Queue	What must be checked	Repo/build validation
15. Timeline	Chronological reconstruction	Understanding evolution
16. Spec Book Contribution	Future Project Spec Book mapping	Aggregation
17. Top Things to Preserve	Highest-priority carry-forward items	Quick preservation
18. Things Future Assistants Must Not Assume	Non-established facts	Avoiding overreach
19. Question Menu	Questions you can ask next	Interactive inspection
20. Recommended Next Questions	Best next queries	Follow-up
21. Compact Copyable Summary	800–1,500 word capsule	Copy/paste elsewhere
22. Final Reader Status	Final status	End state
Most important IDs to remember
ID type	Meaning
WORKSTREAM-*	Workstreams/plans/projects
DECISION-*	Decisions already made or accepted
TASK-*	Pending or carry-forward tasks
CONSTRAINT-*	Hard/soft requirements
QUESTION-*	Open questions
ARTIFACT-*	Files/prompts/outputs/references
RISK-*	Risks and failure modes
REJECTED-*	Rejected/superseded/deprioritised options
VERIFY-*	Manual verification items
You can ask targeted questions such as: “Explain DECISION-07,” “Which VERIFY-* items are highest priority?” or “Show only workstreams related to setup schemas.”

1. Package Overview
Field	Value
Chat label	Dominium Setup Handoff
Date anchor	2026-05-27 Australia/Melbourne
Source scope	THIS CHAT ONLY, with project-level context explicitly marked as PROJECT-CONTEXT where pasted from other chats
Files/package available?	yes; generated package files were inspected from /mnt/data
Extraction confidence	4 / 5
Staleness risk	medium
Complete?	usable with caveats
Safe for aggregation?	yes, with caveats
Main caveats	Actual repository state after the two applied Codex prompts is unverified; several implementation details must be checked in the repo before acting; some large prompts are summarized; assistant proposals are preserved as INFERENCE rather than decisions unless accepted or canonized.
2. Generated File Index
File	Purpose	What it contains	When I should read it	Importance
dominium_setup_handoff__01_full_chat_report.md	Main human-readable report	Full metadata, executive summary, preferences, workstreams, timeline, decisions, tasks, constraints, questions, artifacts, risks, verification queue, spec-book notes	When you want the complete readable record	Highest
dominium_setup_handoff__02_spec_sheet.yaml	Structured data for aggregation/spec-book generation	Normalized YAML containing all registers and metadata	When feeding this chat into automation or a master spec book	Highest
dominium_setup_handoff__03_aggregator_packet.md	Compact merger packet	Cross-chat summary, compact registers, duplicate/conflict warnings	When combining this chat with other old-chat packages	Highest
dominium_setup_handoff__04_registers.md	Standalone normalized tables	Workstream, decision, task, constraint, preference, question, artifact, rejected-option, risk, verification, timeline, spec-book registers	When you need fast lookup by ID	High
dominium_setup_handoff__05_reader_brief.md	Short human-readable brief	Quick overview of what the chat was about, main decisions, tasks, questions, artifacts	When you want a fast orientation	Medium-high
dominium_setup_handoff__06_verification_and_audit.md	Quality-control record	Audit of the original transfer packet, reliability ratings, verification checklist, residual risks, re-extraction triggers	Before trusting or aggregating the report	High
dominium_setup_handoff__manifest.md	Package manifest	File list, item counts, storage recommendations, final status	When confirming package contents and counts	High
dominium_setup_handoff__handoff_package.zip	Archive bundle	ZIP of the generated report package files	For external storage/sharing, not needed for this in-chat reader	Medium
Plain-language explanation of each file
Full Chat Report is the main readable source. It tells the story of the chat and contains the most complete human-oriented synthesis.

Spec Sheet YAML is the machine-friendly form. It is the best file for future aggregation into a Project Spec Book because it has stable IDs and normalized fields.

Aggregator Packet is a compressed merger input for a future chat that will combine many old-chat reports. It preserves enough detail for cross-chat deduplication without the full prose.

Registers is the lookup table file. If you want to inspect every DECISION-* or TASK-*, this is the fastest file.

Reader Brief is the quick version. It is useful for understanding the package in minutes.

Verification and Audit explains how reliable the package is, what was corrected from the previous context transfer, and what still needs manual checking.

Manifest confirms the files created and item counts.

3. Executive Summary of This Chat
FACT: This old chat was primarily about the Dominium / Domino Setup system: a deterministic, auditable, reversible, cross-platform installer/updater/verifier/rollback authority. The chat began with setup architecture for Windows, macOS, Linux, Steam/Epic, legacy platforms, package managers, offline/online installs, and uninstall/repair/update/downgrade flows. It then evolved into canonical repository alignment, build-system enforcement, engine purity, setup/launcher schema contracts, application-layer canon, and finally a maximum-fidelity handoff/report package.

FACT: The most important decision is that setup/ is the sole authority for installation, upgrade, downgrade, verification, repair, uninstall, rollback, and packaging layout enforcement. The launcher may invoke setup and consume setup outputs, but it may not reimplement install, repair, update, or verification logic. The engine must not know setup exists. Setup may depend only on libs/ and schema/.

FACT: The chat went through multiple directory-structure iterations. Early proposals used setup/core, setup/adapters, setup/packaging, and core/source-style directories. Those are now historical and superseded. The user later locked a canonical repository structure with top-level products: engine/, game/, client/, server/, launcher/, setup/, tools/, libs/, schema/, sdk/, docs/, ci/, and legacy/. The canonical setup layout is now setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages/{client,server,tools,scripts}, setup/platform/{win/{win9x,winnt},linux,bsd,mac/{classic,osx}}, setup/tests, setup/ui, and setup/CMakeLists.txt.

FACT: Two major Codex prompts were pasted by the user as already applied. One covered one-pass repo refactor, repair, Visual Studio 2026/CMake readiness, buildability, and target boundary enforcement. The second covered final engine purity and contract ownership repair, including moving cross-product contracts to libs/contracts/include/dom_contracts. These prompts are treated as authoritative, but the actual post-prompt repository state was not visible in this chat and remains UNCERTAIN / UNVERIFIED.

FACT: The chat produced an additional actionable prompt titled “Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass.” This prompt is one of the most important artifacts. It instructs Codex to inventory setup, normalize schemas, harden public setup APIs, audit platform adapters, audit UI frontends, harden packaging/reproducibility, align tests, and create final setup baseline documentation. It explicitly says not to redesign setup and to treat existing implementation as authoritative unless it violates locked rules.

FACT: The chat clarified that setup can support offline installation, network installation, update checking, individual package/component customization, repair, uninstall, upgrade, downgrade, and rollback. The boundaries are important: network is optional transport, update checking is non-mutating unless an explicit update is invoked, repair is explicit and never silent, uninstall is based on setup-owned installed-state manifests, and rollback is journaled.

FACT / PROJECT-CONTEXT: Later, the user pasted application-layer canon from other chats. This established that applications are content-agnostic orchestration shells, CLI is canonical, GUI/TUI are views over the same command graph, UI is data via UI IR, tools are read-only by default, RepoX/TestX enforce canon and build metadata, and BUILD-ID-0 governs version/release identity. These are visible in this chat but originated as project-level context.

INFERENCE: The best next action is to verify the actual repository state after the two applied Codex prompts, then either execute the generated setup hardening prompt or audit its outputs if already executed. A future assistant must not resurrect obsolete layouts like setup/adapters, adapter-local packaging, or setup/core/source as canonical.

4. Plain-English Explanation of the Whole Package
This package is a per-chat continuity and aggregation package. It does not try to describe the entire Dominium / Domino project. It describes what this old chat contributed, especially around the setup system and the transition from early setup planning to canonical repository enforcement.

Its unique contribution is the setup-system lineage: it records the initial installer architecture, the Plan S plan-of-plans, the old and superseded directory structures, the canonical setup layout, the applied Codex refactor prompts, the setup schema handoff, the setup capability model, and the final setup hardening prompt.

It also captures a change of direction: the chat began as if setup was being designed from scratch, then later treated the existing implementation and refactored repository as authoritative. This matters because future work must not restart setup design. It must audit and finish the existing code.

This chat overlaps with other chats on:

application-layer canon,

RepoX/TestX,

BUILD-ID-0,

engine purity,

UI IR,

CMake enforcement,

Project Spec Book aggregation.

Those overlapping topics should not be merged blindly. The package marks them as PROJECT-CONTEXT where they were pasted from other chats rather than developed fully inside this one.

Before using this package for implementation, verify:

actual setup/ tree,

actual schema/ tree,

libs/contracts,

CMake configure/build/test,

setup/launcher CLI smoke tests,

enforcement scripts,

whether the setup hardening prompt has already been executed.

The package is useful for a future Project Spec Book because it contains formal requirements candidates:

setup sole authority,

schema-only setup/launcher handoff,

canonical setup layout,

CMake as build authority,

engine purity,

no hidden repair/update mutation,

offline/online support,

rollback-first setup model,

report packaging workflow.

Do not merge assistant-only proposals like a specific libs/appcmd path or exact UI IR path into canon unless confirmed elsewhere.

5. Workstreams / Projects / Plans
ID	Name	Status	Objective	Current state	Desired end state	Priority	Confidence	Label
WORKSTREAM-01	Dominium Setup / Installer System	active	Finish deterministic setup product	Plans developed; canonical setup layout superseded old trees; repo state unverified	Buildable, auditable, schema-backed setup product under canonical setup/	highest	4	FACT
WORKSTREAM-02	Canonical Repository Structure and CMake/VS2026 Build Enforcement	active / needs verification	Ensure repo builds via CMake/VS2026 with boundaries enforced	Two applied prompts require presets, include dirs, smoke tests	Root CMake/presets build libs, engine, setup, launcher, tools; CTest passes	highest	3	FACT
WORKSTREAM-03	Engine Purity and Neutral Contract Ownership	active / claimed applied / needs verification	Remove setup/launcher/tools/game contamination from engine	Final purity prompt listed prior violations and required moves	Engine contains only include/domino, modules, render, tests, CMakeLists; contracts in libs/contracts	highest	3	FACT
WORKSTREAM-04	Setup Schemas and Setup ↔ Launcher Handoff	active	Enforce schema-only setup/launcher communication	Phase 3 schema definitions produced; actual files unverified	All setup I/O backed by schema/setup/*; launcher reads artifacts only	high	4	FACT
WORKSTREAM-05	Application Layer Canon	active / authoritative project context	Implement apps as content-agnostic orchestration shells	User pasted application-layer canon from other chats	Setup/launcher/client/server/tools obey APP canon	high	4	FACT / PROJECT-CONTEXT
WORKSTREAM-06	Packaging, Reproducibility, Offline and Network Acquisition	active / design accepted unless contradicted	Support reproducible packaging, offline/net fetch, updates/customization	Capability mapped architecturally; implementation unverified	setup/packages/*; content-addressed verified payload acquisition	high	4	FACT
WORKSTREAM-07	CLI/TUI/GUI Command Model and UI IR	active / details tentative	CLI canonical; GUI/TUI views; UI declarative	Canon locked; assistant proposed app command spine/UI IR path	Shared command graph, deterministic output, accessibility/localization, binding validation	medium-high	3	FACT / INFERENCE
WORKSTREAM-08	RepoX/TestX/BUILD-ID-0 Governance	active / needs repo verification	Enforce canon, schemas, changelogs, build metadata, releases	Latest canon defines rules; tooling uninspected	Apps display RepoX metadata; incompatible versions refuse loudly	high	3	FACT / PROJECT-CONTEXT
WORKSTREAM-09	Legacy Platform Support	active but lower immediate urgency	Preserve support for WinNT, Win9x, macOS X, classic macOS, Linux, stores, retro	Early goal; canonical layout includes legacy platform dirs	Isolated legacy targets, documented constraints, no accidental unsupported builds	medium	4	FACT
WORKSTREAM-10	Context Transfer and Report Packaging	active in package-generation step	Produce durable per-chat reports for aggregation/spec book	Context packet and final report package produced	Seven files plus ZIP; stable IDs and labels	highest for package	5	FACT
WORKSTREAM-01 — Dominium Setup / Installer System
What it is: The deterministic setup product responsible for install, upgrade, downgrade, verify, repair, uninstall, rollback, and package layout enforcement.

Why it matters: It is the only product allowed to mutate installed files or installation/system state.

Current state: Plans were developed and later realigned to canonical setup/; actual repo state after Codex prompts is unverified.

Desired end state: Buildable, auditable, schema-backed setup with fetch, verify, install, rollback, public APIs, platform services, UI, packages, and tests.

Key decisions: DECISION-01, 02, 03, 04, 05, 14, 17, 18, 19, 20.

Pending tasks: TASK-01 through TASK-13 are most relevant.

Constraints: CONSTRAINT-01, 02, 04, 05, 06, 27, 28, 29, 30.

Dependencies: libs/, schema/, libs/contracts, CMake, RepoX/TestX where applicable.

Risks: RISK-01, 03, 04, 06, 09.

Open questions: QUESTION-01, 02, 03, 04, 06, 10, 11.

Artifacts: ARTIFACT-02, 03, 04, 11, 12, 13, 17, 18.

Next action: Verify actual repo state and execute/audit the setup hardening prompt.

What to ask for more detail: “Explain WORKSTREAM-01 and list its must-pass tests.”

WORKSTREAM-02 — Canonical Repository Structure and CMake/VS2026 Build Enforcement
What it is: The build and repository-enforcement workstream.

Why it matters: CMake and scripts are the mechanical enforcement layer for architecture boundaries.

Current state: Two Codex prompts were said to be applied; actual build status unverified.

Desired end state: VS2026/CMake presets configure/build/test; setup/launcher CLIs run; target include dirs enforce boundaries.

Key decisions: DECISION-03, 04, 12, 21, 26.

Pending tasks: TASK-01, 03, 04, 05, 06.

Constraints: CONSTRAINT-10, 11, 12, 13.

Dependencies: Root CMake, CMakePresets, scripts, CI.

Risks: RISK-03, 05, 14.

Open questions: QUESTION-01, 07, 14.

Artifacts: ARTIFACT-14.

Next action: Inspect current build files and run configure/build/test.

What to ask: “Which CMake checks does this chat require?”

WORKSTREAM-03 — Engine Purity and Neutral Contract Ownership
What it is: Boundary repair ensuring engine remains reusable and application-agnostic.

Why it matters: Engine contamination would break long-term architecture.

Current state: Final purity prompt listed concrete old violations; user said prompt was applied.

Desired end state: Engine only exports engine/include/domino/**; cross-product contracts live under libs/contracts/include/dom_contracts.

Key decisions: DECISION-08, 09.

Pending tasks: TASK-05, 06.

Constraints: CONSTRAINT-03, 07, 08, 09.

Dependencies: libs/contracts, include scanner, tree sanity scripts.

Risks: RISK-05.

Open questions: QUESTION-05, 07.

Artifacts: ARTIFACT-15.

Next action: Verify engine tree and include scanning results.

What to ask: “What exact engine purity violations were listed?”

WORKSTREAM-04 — Setup Schemas and Setup ↔ Launcher Handoff
What it is: The schema and contract layer between setup and launcher.

Why it matters: It prevents launcher from duplicating setup logic or inferring install state.

Current state: Schema families were proposed; actual files unverified.

Desired end state: schema/setup/install_plan, installed_state, verify_report, audit_log; launcher reads schema artifacts and exit/status contracts.

Key decisions: DECISION-07, 16, 18, 27.

Pending tasks: TASK-07.

Constraints: CONSTRAINT-29, 31.

Dependencies: schema/, libs/contracts.

Risks: RISK-04, 06.

Open questions: QUESTION-04.

Artifacts: ARTIFACT-16.

Next action: Inspect schema/ and normalize setup I/O.

What to ask: “What schemas does setup need?”

WORKSTREAM-05 — Application Layer Canon
What it is: Project-level rules for setup, launcher, client, server, and tools as applications.

Why it matters: Prevents apps from embedding gameplay logic, hidden defaults, or authority bypasses.

Current state: User pasted canon from other chats; marked PROJECT-CONTEXT.

Desired end state: All apps are content-agnostic orchestration shells.

Key decisions: DECISION-10, 11, 22, 23, 24.

Pending tasks: TASK-16, 17, 18 relate indirectly.

Constraints: CONSTRAINT-14 through 24.

Dependencies: APP-CANON0/1, APP-AUTO-0, APP-UI-BIND-0, RepoX/TestX.

Risks: RISK-07, 10, 13.

Open questions: QUESTION-08, 09, 13, 15.

Artifacts: ARTIFACT-19, 20.

Next action: Verify against CANON_INDEX.md before implementing app-layer paths.

What to ask: “Which application-layer items are project-context rather than chat-native?”

WORKSTREAM-06 — Packaging, Reproducibility, Offline and Network Acquisition
What it is: Distribution and payload acquisition model for setup.

Why it matters: Setup must work offline, online, reproducibly, and safely.

Current state: Capabilities accepted architecturally; implementation unverified.

Desired end state: setup/packages/* declarative recipes; setup/core/fetch supports local/cache/network acquisition; verification is first-class.

Key decisions: DECISION-06, 15, 16.

Pending tasks: TASK-11, 14, 15.

Constraints: CONSTRAINT-31, 32.

Risks: RISK-08, 09.

Open questions: QUESTION-10, 11.

Artifacts: ARTIFACT-18.

Next action: Audit setup/core/fetch, package scripts, and operation matrix.

What to ask: “How does offline vs online setup work?”

WORKSTREAM-07 — CLI/TUI/GUI Command Model and UI IR
What it is: App frontend model where CLI is canonical and UI is declarative.

Why it matters: Prevents GUI/TUI behavior drift and supports accessibility/localization.

Current state: Rule is canon; exact app command spine path is not established.

Desired end state: Shared command graph, deterministic output, UI IR, binding validation.

Key decisions: DECISION-10, 11.

Pending tasks: TASK-16, 17.

Constraints: CONSTRAINT-17 through 20.

Risks: RISK-07.

Open questions: QUESTION-08, 09.

Artifacts: ARTIFACT-21.

Next action: Verify existing command/UI architecture before adding a new path.

What to ask: “Which UI command model details are tentative?”

WORKSTREAM-08 — RepoX/TestX/BUILD-ID-0 Governance
What it is: Release/build/canon enforcement.

Why it matters: Build identity, changelogs, schema validation, and compatibility warnings depend on it.

Current state: Rules pasted as project-context; tooling unverified.

Desired end state: Apps consume RepoX metadata; no manual changelog editing; invalid states fail gates.

Key decisions: DECISION-22, 23.

Pending tasks: TASK-18.

Constraints: CONSTRAINT-22, 23, 24.

Risks: RISK-10, 14.

Open questions: QUESTION-13, 15.

Artifacts: ARTIFACT-20.

Next action: Inspect RepoX/TestX docs/tools/CI.

What to ask: “What did BUILD-ID-0 require?”

WORKSTREAM-09 — Legacy Platform Support
What it is: Long-term support for Windows NT, Windows 9x/OpenWatcom, macOS X, classic macOS, Linux, stores, web/consoles/retro.

Why it matters: Setup architecture must not assume only modern platforms.

Current state: Goals discussed; canonical platform directories include some legacy splits.

Desired end state: Legacy code isolated, documented, and not accidentally built unsupported.

Key decisions: DECISION-13, 14.

Pending tasks: TASK-14, 15 and verification for platform support.

Constraints: CONSTRAINT-25, 26.

Risks: RISK-11.

Open questions: QUESTION-12.

Artifacts: ARTIFACT-06, 07.

Next action: Verify immediate priority before implementing legacy targets.

What to ask: “Which legacy targets are design-only versus immediate?”

WORKSTREAM-10 — Context Transfer and Report Packaging
What it is: Per-chat knowledge preservation.

Why it matters: This chat is being retired and must remain usable for aggregation/spec-book construction.

Current state: Package created and now rendered in-chat.

Desired end state: Stable IDs, labels, registers, and verification queues available to future assistants.

Key decisions: Preserve uncertainty and artifacts; do not compress aggressively.

Pending tasks: TASK-19, 20 are storage/aggregation tasks.

Constraints: CONSTRAINT-35.

Risks: RISK-02, 12, 13, 15.

Open questions: none blocking.

Artifacts: ARTIFACT-22, 23.

Next action: Use this in-chat reader for inspection; later aggregate with other packages.

What to ask: “Which items should the aggregator preserve?”

6. Decisions Already Made
ID	Decision	Status	Rationale	Implications	Related workstream	Confidence	Label
DECISION-01	Setup is sole authority for installation, upgrade, downgrade, verification, rollback, repair, uninstall, and packaging layout enforcement.	locked	Prevents launcher/engine bypass and preserves auditability	Launcher may invoke setup only; setup writes state	WORKSTREAM-01, 04	high	FACT
DECISION-02	Use one common setup core shared across all platforms.	locked	Avoid duplicated OS logic	Platform code remains thin	WORKSTREAM-01, 09	high	FACT
DECISION-03	Canonical setup layout is setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages, setup/platform, setup/tests, setup/ui.	locked	Filesystem is fixed ground truth	Earlier adapters/packaging/source layouts are superseded	WORKSTREAM-01, 02	high	FACT
DECISION-04	Setup may depend only on libs/ and schema/.	locked	Enforces isolation	No engine/launcher/game internals in setup	WORKSTREAM-01, 02	high	FACT
DECISION-05	setup/include/dsk owns public setup kernel API; setup/include/dsu owns execution/platform interfaces.	locked	Stable boundaries	Internal setup headers stay under setup/core/**	WORKSTREAM-01	high	FACT
DECISION-06	All packaging outputs and recipes are produced from setup/packages/.	locked	Separates packaging from platform/UI adapters	Old adapter-local packaging must be moved/quarantined	WORKSTREAM-06	high	FACT
DECISION-07	Setup ↔ launcher handoff occurs only through manifests, schemas, installed-state snapshots, and exit/status contracts.	locked	Prevents private coupling	Launcher must not infer install success from filesystem heuristics	WORKSTREAM-04	high	FACT
DECISION-08	Engine must be pure and unaware of setup/launcher/tools.	locked	Keeps engine reusable	Forbidden engine paths/includes must fail CI	WORKSTREAM-03	high	FACT
DECISION-09	Cross-product contracts belong under libs/contracts/include/dom_contracts.	locked	Moves shared contracts out of engine/game internals	Engine must not include dom_contracts	WORKSTREAM-03	high	FACT
DECISION-10	CLI is canonical; GUI/TUI are views over the same command graph.	locked	Ensures parity/scriptability	UI cannot contain business logic	WORKSTREAM-07	high	FACT / PROJECT-CONTEXT
DECISION-11	UI is declarative data / UI IR, not logic.	locked	Supports accessibility/localization/binding validation	UI backends must be interchangeable	WORKSTREAM-07	high	FACT / PROJECT-CONTEXT
DECISION-12	CMake is authoritative; VS/Xcode projects are generated and not authoritative source files.	accepted	Prevents IDE drift	No hand-written .vcxproj/.xcodeproj as build truth	WORKSTREAM-02	medium-high	FACT
DECISION-13	Use Visual Studio Desktop Development with C++ for setup; do not use .NET for authoritative setup execution.	accepted	Legacy/offline/ABI requirements	C/C++ setup; .NET only for optional non-authoritative tooling	WORKSTREAM-01, 09	medium-high	FACT / INFERENCE
DECISION-14	Setup core language should be C/C++ with stable C ABI; C89/C90 and C++98 compatibility where targeted.	locked	Long-term ABI/toolchain support	No C++ ABI leakage across boundaries	WORKSTREAM-01	high	FACT
DECISION-15	Offline and network installation are both supported; network is optional transport, not dependency.	accepted	Air-gapped installs and online fetch share fetch abstraction	Payloads must be content-addressed/verified	WORKSTREAM-06	medium-high	FACT / INFERENCE
DECISION-16	Update checking is non-mutating plan/state comparison unless explicit update is invoked.	accepted	Prevents hidden mutation	Launcher can display reports but setup applies changes	WORKSTREAM-06, 04	medium-high	FACT / INFERENCE
DECISION-17	Repair is explicit and never silent.	locked	Avoid hidden mutations	Repair command must be invoked deliberately	WORKSTREAM-01	high	FACT
DECISION-18	Uninstall is ownership-based using installed-state manifests.	locked	Clean uninstall and user-data preservation	Launcher/client cannot delete owned install files	WORKSTREAM-01, 04	high	FACT
DECISION-19	Rollback is journal-driven and first-class.	locked	Resilience to partial installs	Fault-injection tests required	WORKSTREAM-01	high	FACT
DECISION-20	Existing implementation is authoritative unless it violates locked rules.	locked	Avoids redesign after refactor	Audit/repair rather than restart	WORKSTREAM-01, 02	high	FACT
DECISION-21	Do not delete code during refactors; quarantine under legacy/ with README.	locked	Preserves history and behavior	Legacy content moved, not erased	WORKSTREAM-02	high	FACT
DECISION-22	RepoX-generated changelogs only; no manual changelog editing.	locked	Release data reproducibility	Apps display RepoX output	WORKSTREAM-08	high	FACT / PROJECT-CONTEXT
DECISION-23	BUILD-ID-0 version model is locked: SemVer + build kind + GBN/BII + channel rules.	locked	Consistent distributed artifact identity	Mismatch refuses loudly	WORKSTREAM-08	high	FACT / PROJECT-CONTEXT
DECISION-24	Tools are read-only by default.	locked	Prevents accidental mutation	Mutating tools must be explicit/gated	WORKSTREAM-05	high	FACT / PROJECT-CONTEXT
DECISION-25	Do not reintroduce generic source/ directories under setup canonical layout.	locked	Preserves module clarity	Old core/source pattern superseded	WORKSTREAM-01	medium-high	FACT
DECISION-26	Top-level products are locked as engine, game, client, server, launcher, setup, tools, libs, schema, sdk, docs, ci, legacy.	locked	Future paths must align	Old source/setup-only assumptions superseded	WORKSTREAM-02	high	FACT
DECISION-27	Schema is the canonical data-format location; setup must not invent private formats.	locked	Enables validation and launcher handoff	Ad-hoc JSON/TLV must map to schema	WORKSTREAM-04	high	FACT
Decision Explanations
The highest-impact decisions are DECISION-01 through DECISION-09. Together, they define authority and ownership: setup owns installation mutation, launcher consumes setup outputs, engine remains pure, and cross-product APIs belong in neutral contracts.

DECISION-10 and DECISION-11 are application-layer canon from pasted project context. They affect future UI implementation: CLI is the command truth, and GUI/TUI cannot embed business logic.

DECISION-12 through DECISION-14 define build/toolchain direction: CMake is the authority, generated IDE projects are allowed, and setup execution should be C/C++ with stable C ABI constraints.

DECISION-15 through DECISION-19 define setup operations: offline/online install support, explicit update/repair/downgrade, ownership-based uninstall, and journaled rollback.

DECISION-20 and DECISION-21 matter for current implementation: do not redesign or delete; audit, repair, and quarantine.

DECISION-22 through DECISION-24 are project-context governance rules: RepoX changelogs, BUILD-ID-0 releases, and read-only tools.

DECISION-25 through DECISION-27 prevent structural regression: no generic setup source/ directories, locked top-level products, and schema-owned data formats.

7. Pending Tasks and Next Actions
ID	Task	Priority	Urgency	Owner	Dependencies	Expected output	Next step	Label
TASK-01	Verify actual repo state after the two applied Codex prompts.	highest	immediate	New chat / Codex / user	Repo access	Confirmed state vs canonical layout	Inspect setup/, schema/, libs/contracts/, CMake, scripts	FACT / INFERENCE
TASK-02	Execute or verify the generated Setup final spec alignment prompt.	highest	immediate	Codex	Repo state, prompt artifact	Setup gaps closed or audited	Run phases A–H if not already done	FACT
TASK-03	Validate setup/ canonical layout.	high	immediate	Codex	Repo tree	Pass/fail against canonical layout	Compare with setup/core, include, packages, platform, tests, ui	FACT
TASK-04	Run CMake configure/build/test and smoke commands.	high	immediate	Codex	CMakePresets, toolchain	Build/smoke baseline	Run VS2026 preset and setup --help / launcher --help	FACT
TASK-05	Verify engine purity and include ownership.	high	soon	Codex	Scripts, repo tree	No engine contamination	Run enforcement scripts; inspect engine include dirs	FACT
TASK-06	Verify libs/contracts exists and is used correctly.	high	soon	Codex	Repo tree, CMake	Neutral contracts enforce boundary	Inspect libs/contracts/include/dom_contracts	FACT
TASK-07	Normalize setup schemas under schema/setup/.	high	soon	Codex	Schema files, setup I/O	Schema-backed setup I/O	Execute prompt Phase B	FACT
TASK-08	Audit setup/include/dsk and setup/include/dsu.	high	soon	Codex	Setup headers	No internal header exposure	Execute prompt Phase C	FACT
TASK-09	Audit setup/platform adapters.	medium-high	soon	Codex	Platform code	Adapters provide OS services only	Execute prompt Phase D	FACT
TASK-10	Audit setup/ui and canonical CLI.	medium-high	soon	Codex	CLI/UI files	CLI help/status/version and operation commands	Execute prompt Phase E	FACT
TASK-11	Audit setup/packages reproducibility.	high	soon	Codex	Package scripts/templates	Reproducible package flow	Execute prompt Phase F	FACT
TASK-12	Align setup tests with spec requirements.	high	soon	Codex	Test files	Partial/corrupt/idempotent/uninstall/rollback tests	Execute prompt Phase G	FACT
TASK-13	Create/verify setup baseline docs and freeze marker.	high	soon	Codex	Docs	Stable baseline for future planning	Execute prompt Phase H	FACT
TASK-14	Verify offline and network acquisition implementation.	medium	later	Setup developer	Schema baseline, fetch code	Offline/local/cache and optional network path documented	Audit after schema baseline	INFERENCE
TASK-15	Verify update/downgrade CLI and schema semantics.	medium	later	Setup developer	CLI/schema/tests	Explicit update/downgrade flows documented/testable	Audit operation matrix	INFERENCE
TASK-16	Define or verify app command spine for CLI/TUI/GUI parity.	medium	later	Application-layer developer	APP canon, existing code	Shared command graph, deterministic output	Inspect existing libs/tools; create only if absent and canon permits	INFERENCE
TASK-17	Define or verify UI IR schema and binding validation.	medium	later	Application/UI developer	CANON_INDEX, APP-UI-BIND-0	Declarative UI with accessibility/localization metadata	Consult CANON_INDEX.md then inspect schema	INFERENCE
TASK-18	Verify RepoX/TestX/BUILD-ID integration.	high	later	Build/release developer	RepoX/TestX docs/tools	Apps display generated metadata and refuse mismatches	Inspect CANON_INDEX.md and tooling	PROJECT-CONTEXT
TASK-19	Preserve old-chat report package and store with future chat packages.	highest	current	Assistant/user	Generated package files	Reusable report package	Store package with stable filenames and labels	FACT
TASK-20	Aggregate this package with other old-chat packages later.	medium	later	Future aggregator chat	Other packages	Project Spec Book and Master Living State File	Use aggregator prompt once all packages are collected	FACT
7.1 Best Task Order
TASK-01 — Verify actual repo state.

TASK-03 — Validate canonical setup/ layout.

TASK-04 — Run CMake configure/build/test and CLI smoke tests.

TASK-05 — Verify engine purity.

TASK-06 — Verify libs/contracts.

TASK-02 — Execute or audit setup hardening prompt.

TASK-07 through TASK-13 — Complete setup schema/kernel/platform/UI/packages/tests/docs hardening.

TASK-14 through TASK-18 — Verify extended setup/app governance capabilities.

TASK-20 — Aggregate with other reports later.

7.2 Blocked Tasks
Task	Blocker
TASK-02	Need know whether hardening prompt already executed
TASK-07	Need inspect current schema files
TASK-14	Need inspect setup/core/fetch
TASK-16	Need know current app command architecture
TASK-17	Need canon-confirmed UI IR path
TASK-18	Need RepoX/TestX tooling state
7.3 Quick Wins
Inspect setup/, schema/, libs/contracts/.

Run setup --help and launcher --help.

Check whether docs/SETUP_GAPS.md exists.

Search for obsolete setup/adapters, .vcxproj, .xcodeproj, and generic source/ dirs.

Run tree/include sanity scripts.

7.4 Questions I Can Ask About Tasks
“Explain TASK-02.”

“Which tasks are blocked?”

“Turn TASK-01 through TASK-13 into a Codex prompt.”

“Which tasks belong in the master spec book?”

“Which tasks are urgent versus merely important?”

“Which tasks require repo access?”

8. Constraints and Requirements
ID	Constraint	Type	Hard/soft	Practical implication	Violation risk	Confidence	Label
CONSTRAINT-01	Setup is sole authority for installation/system state mutation.	Architectural	hard	No launcher/client/tools install logic	high	5	FACT
CONSTRAINT-02	Launcher may invoke setup but must not reimplement setup logic.	Architectural	hard	Launcher reads reports and calls setup	high	5	FACT
CONSTRAINT-03	Engine must not know setup exists.	Architectural	hard	No setup headers/links/concepts in engine	high	5	FACT
CONSTRAINT-04	Setup may depend only on libs/ and schema/.	Dependency	hard	No engine/game/launcher internals	high	5	FACT
CONSTRAINT-05	Public setup APIs live only under setup/include/dsk and setup/include/dsu.	Include ownership	hard	No setup exports elsewhere	medium-high	5	FACT
CONSTRAINT-06	Setup internal headers stay under setup/core/**.	Include ownership	hard	No platform/ui private leaks	medium	5	FACT
CONSTRAINT-07	No setup headers may be included by engine or game.	Include ownership	hard	CMake/scripts must fail violations	high	5	FACT
CONSTRAINT-08	engine/include exports only Domino engine ABI.	Include ownership	hard	No dsu/dui/dominium in engine include	high	5	FACT
CONSTRAINT-09	Cross-product contracts live in libs/contracts/include/dom_contracts.	Architecture	hard	Launcher/setup/tools/game use neutral contracts; engine not	medium-high	5	FACT
CONSTRAINT-10	No global include_directories except minimal config headers.	Build	hard	All includes are target-scoped	medium	4	FACT
CONSTRAINT-11	CMake is authoritative; generated IDE projects are not source-of-truth.	Build	hard	No hand-authored IDE project authority	medium	4	FACT
CONSTRAINT-12	Keep repo buildable after each commit in Codex phases.	Process	hard	Small commits and smoke tests	high	5	FACT
CONSTRAINT-13	Do not delete code; quarantine obsolete code under legacy/ with README.	Process	hard	Preserve history and behavior	medium	5	FACT
CONSTRAINT-14	Do not redesign settled architecture or simulation rules.	Scope	hard	Implementation/audit only	high	5	FACT / PROJECT-CONTEXT
CONSTRAINT-15	Applications are content-agnostic and contain no gameplay logic.	Application	hard	No pack/rule assumptions in apps	high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-16	Applications must run with zero content packs installed.	Application	hard	Missing content is diagnostic/raw keys, not crash/defaults	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-17	CLI is canonical; GUI/TUI are views over same command graph.	Application/UI	hard	No UI-specific behavior drift	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-18	UI is declarative IR/data; no business logic embedded.	UI	hard	Binding validation required	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-19	Accessibility requirements apply to GUIs.	UI	hard	Keyboard, screen-reader tags, font/contrast, no color-only semantics	medium	4	FACT / PROJECT-CONTEXT
CONSTRAINT-20	Localization strings externalized; raw-key fallback if locale missing.	UI	hard	Locale packs normal packs; no hardcoded UI strings	medium	4	FACT / PROJECT-CONTEXT
CONSTRAINT-21	Tools are read-only by default.	Application	hard	Mutating tools explicit and gated	medium	4	FACT / PROJECT-CONTEXT
CONSTRAINT-22	RepoX is source of truth for changelogs and compatibility/build metadata.	Release	hard	No manual changelog editing	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-23	BUILD-ID-0 versioning model is locked.	Release	hard	SemVer + build kind + GBN/BII; mismatch refuses loudly	high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-24	No distributed artifact without GBN.	Release	hard	Release gating required	high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-25	Engine is C89; game is C++98.	Language	hard	Application choices must not impose newer requirements	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-26	No C++ ABI leakage across public boundaries.	ABI	hard	Stable C ABI preferred where needed	medium-high	4	FACT / PROJECT-CONTEXT
CONSTRAINT-27	Setup manifests must avoid arbitrary executable scripts; actions are declarative/sandboxed.	Security	hard	Deterministic and safe installs	medium	4	FACT
CONSTRAINT-28	No silent repair or hidden mutation.	Behavior	hard	Repair/update/downgrade are explicit	high	5	FACT
CONSTRAINT-29	Installed-state is setup-written and launcher-read-only.	State	hard	No launcher state mutation	high	5	FACT
CONSTRAINT-30	Transactions use preflight/stage/install/verify/commit/rollback and avoid live in-place mutation.	Behavior	hard	Journaled rollback and fault tests	high	5	FACT
CONSTRAINT-31	Package scripts/templates must not decide install logic.	Packaging	hard	Packages assemble artifacts only	medium-high	4	FACT
CONSTRAINT-32	Offline installs must not require network.	Distribution	hard	Network is optional fetch transport	medium	4	FACT / INFERENCE
CONSTRAINT-33	External/world-current facts and tool versions require verification before future use.	Evidence	hard	VS2026/toolchain details may change	medium	5	FACT
CONSTRAINT-34	Do not copy third-party installer branding/text/logos/assets.	Legal/IP	hard	Original generic UI text/assets only	medium	5	FACT
CONSTRAINT-35	Report package must label important items as FACT/INFERENCE/UNCERTAIN/PROJECT-CONTEXT.	Output	hard	Aggregation can preserve provenance	medium	5	FACT
Constraint explanation
Hard requirements dominate this package. The most important are setup authority, engine purity, schema-only handoff, CMake boundary enforcement, and no hidden mutation.

Soft preferences are mostly around style and organization: shallow logical directory structures, engineering precision, and reusable report packaging.

Technical constraints include C/C++ ABI stability, C89/C++98 compatibility where applicable, target-scoped includes, and avoiding authoritative IDE project files.

Legal/IP constraints include not copying third-party installer branding or UI assets.

Evidence constraints require verifying stale or current-world facts before acting.

Future assistants should avoid redesigning canon, resurrecting superseded trees, weakening rollback/verification, or turning assistant proposals into decisions.

9. User Preferences Visible in This Chat
9.1 Explicit Preferences
ID	Preference	Area	Strength	Implication	Label
PREF-01	Responses should start with GPT-X.Y — YYYY-MM-DD HH:MM:SS local time.	Formatting	high	Preserve prefix unless higher-priority rules conflict	FACT
PREF-02	Optimize for epistemic accuracy, decision utility, long-term correctness.	Reasoning	high	Use labels, verification queues, avoid unsupported claims	FACT
PREF-03	Separate FACT, INFERENCE, ESTIMATE/UNCERTAIN where relevant.	Factuality	high	Preserve provenance in registers	FACT
PREF-04	Engineering precision, no marketing tone.	Style	high	Use concrete file-level plans/checklists	FACT
PREF-05	Do not restart locked plans; continue and amend.	Process	high	Respect canon and existing implementation	FACT
PREF-07	Shallow, logical, industry-practice directory structures.	Architecture	medium-high	Avoid unnecessary nesting/generic source dirs	FACT
PREF-08	Downloadable, reusable report packages for old chats.	Knowledge management	high	Create package files when requested/available	FACT
9.2 Inferred Preferences
ID	Preference	Basis	Confidence	Risk if wrong	Label
PREF-06	User values direct copy-paste prompts for Codex.	User asked for prompts and applied prompts	medium-high	Non-actionable prompts may be less useful	INFERENCE
9.3 Preferences Not Established
Exact app command spine path.

Exact UI IR schema path.

Exact current repo state.

Immediate priority of legacy platform implementation.

Exact preferred future GUI toolkit beyond native/CMake-aligned constraints.

Exact tolerance for report length, though the visible request strongly favors completeness over compression.

10. Open Questions and Unresolved Issues
ID	Question / issue	Why it matters	Known	Unknown	Resolution path	Priority	Label
QUESTION-01	Were the two applied Codex prompts completed successfully in the actual repo?	Determines whether to audit outputs or execute fixes	User says they were applied	Build/test/file state not shown	Inspect commits, tree, CMake, scripts	highest	UNCERTAIN / UNVERIFIED
QUESTION-02	Has the generated Setup final spec alignment prompt been executed?	Determines immediate next action	Prompt was generated	No execution result visible	Check for docs/SETUP_GAPS.md and related files/commits	highest	UNCERTAIN / UNVERIFIED
QUESTION-03	What is the current exact setup/ tree?	Avoids acting on stale paths	Canonical layout known	Actual file state unknown	Inspect tree /f setup	highest	UNCERTAIN / UNVERIFIED
QUESTION-04	What schema files exist under schema/setup/?	Setup I/O must be schema-backed	Schema families were planned	Actual files unknown	Inspect schema/ and schema docs	high	UNCERTAIN / UNVERIFIED
QUESTION-05	Does libs/contracts exist and compile?	Neutral contracts are mandatory	Final purity prompt mandates it	Actual headers/CMake unknown	Inspect libs/contracts and build graph	high	UNCERTAIN / UNVERIFIED
QUESTION-06	Do setup --help and launcher --help run?	Smoke test for application products	Prompts require CLI stubs minimum	Build output not shown	Run built executables	highest	UNCERTAIN / UNVERIFIED
QUESTION-07	Do verify_tree_sanity and verify_includes_sanity reflect current invariants?	Enforcement must match canon	Prompts require hardened scripts	Script contents/results unknown	Run/inspect scripts	high	UNCERTAIN / UNVERIFIED
QUESTION-08	Is app command spine already implemented?	Needed for CLI/TUI/GUI parity	Application canon requires shared command graph	Exact implementation/path unknown	Inspect libs/tools/application code; consult CANON_INDEX.md	medium	UNCERTAIN / UNVERIFIED
QUESTION-09	Where exactly should UI IR live?	Avoids inventing schema path	UI IR required by canon	Exact path not locked here	Consult CANON_INDEX.md / APP-UI-BIND-0	medium	UNCERTAIN / UNVERIFIED
QUESTION-10	How mature is setup/core/fetch network support?	Affects offline/online install claims	Architecture supports it	Implementation unknown	Inspect setup/core/fetch and tests	medium	UNCERTAIN / UNVERIFIED
QUESTION-11	Are update/downgrade operations represented in CLI, schema, tests?	Required capabilities may be stubs	Design supports them	Implementation unknown	Inspect CLI help, schemas, tests	medium	UNCERTAIN / UNVERIFIED
QUESTION-12	How much legacy Win9x/macOS Classic work is expected now?	Avoids overbuilding low-priority targets	Legacy support desired	Immediate priority unclear	Ask user or inspect roadmap/docs	medium-low	UNCERTAIN / UNVERIFIED
QUESTION-13	Are RepoX/TestX/BUILD-ID tools present and wired into CI?	Release/app metadata governance depends on them	Canon requires them	Actual tool state unknown	Inspect ci/, tools/, docs, scripts	high	UNCERTAIN / UNVERIFIED
QUESTION-14	Are old IDE artifacts removed/quarantined?	Prevents build divergence	Old tree had .sln, .vcxproj, .xcodeproj	Post-refactor state unknown	Inspect repo for project files and legacy READMEs	medium	UNCERTAIN / UNVERIFIED
QUESTION-15	Does documentation status header policy exist and pass checks?	CLEAN-2/canon management requires status headers	Latest canon says docs have status headers	Actual docs unknown	Inspect docs and RepoX checks	medium	UNCERTAIN / UNVERIFIED
Most important questions
Highest priority: QUESTION-01, 02, 03, 04, 05, 06, 07.

Those directly determine whether implementation can continue safely.

Questions that can wait: QUESTION-08 through 12, unless doing application UI or legacy-platform work immediately.

Questions requiring external/repo verification: all questions in this register.

11. Rejected, Superseded, or Deprioritised Options
ID	Option	Status	Reason	Final or tentative?	Reconsider conditions	Label
REJECTED-01	Put setup business logic in per-OS installers/adapters.	rejected	Violates one common setup core and no duplicated OS logic	final	Only if canon changes	FACT
REJECTED-02	Launcher directly installs, repairs, or updates files.	rejected	Violates setup authority	final	Never under current canon	FACT
REJECTED-03	Engine references setup/launcher/tools APIs.	rejected	Violates engine purity	final	Never under current canon	FACT
REJECTED-04	Use .NET for authoritative setup execution path.	rejected	Runtime/legacy/offline/ABI risk; C/C++ recommended and continued	final for setup execution	Only for non-authoritative developer/management tools	FACT / INFERENCE
REJECTED-05	Hand-authored VS/Xcode projects as authoritative build files.	rejected	Causes IDE drift; CMake is authority	final	Generated build-dir projects allowed	FACT
REJECTED-06	Store packaging under adapters/platform directories.	superseded	Canonical model uses setup/packages/	final	Only if canonical layout changes	FACT
REJECTED-07	Old setup/adapters/** tree as active layout.	superseded	Canonical setup/platform + setup/ui superseded it	final	Only as legacy/quarantine	FACT
REJECTED-08	Old top-level setup/packaging/** layout.	superseded	Canonical setup/packages/** superseded it	final	Only if canon changes	FACT
REJECTED-09	Generic source/ directories under canonical setup layout.	rejected	User prohibited reintroducing generic source directories	final	Never under setup canon	FACT
REJECTED-10	Top-level components/ proposal.	superseded	User later locked top-level products instead	final	Only if repo canon changes	FACT / INFERENCE
REJECTED-11	shared/foundation proposal as named structure.	superseded	Canon uses libs/ and schema/ instead	tentative	Could reappear as specific libs module if canon permits	INFERENCE
REJECTED-12	Arbitrary executable scripts in install manifests.	rejected	Security/determinism risk; declarative actions only	final	Only sandboxed/declarative equivalents	FACT
REJECTED-13	Silent repair or hidden mutation.	rejected	Violates auditability and explicit operation rules	final	Never	FACT
REJECTED-14	Manual changelog editing.	rejected	RepoX is source of truth	final	Never under current canon	FACT / PROJECT-CONTEXT
REJECTED-15	Tools mutating by default.	rejected	Tools are read-only by default	final	Explicit/gated mutation tools only	FACT / PROJECT-CONTEXT
Preserving these matters because many were plausible earlier design paths. Without the rejected/superseded register, a future assistant might repeat old work: resurrect setup/adapters, put package scripts back under platform adapters, or accidentally give launcher installation authority.

12. Artifact Ledger
ID	Artifact / file / prompt / output	Type	Purpose	Status	Carry forward?	Label
ARTIFACT-01	Initial six installer reference images	image attachments	Visual setup/installer references	historical	low	FACT
ARTIFACT-02	Initial GPT-5.2 master setup prompt	prompt	Original setup scope and constraints	superseded structurally; core invariants persist	yes	FACT
ARTIFACT-03	Phase 1 Setup Core Architecture output	assistant plan	Core module architecture	conceptually useful; paths superseded	yes	FACT
ARTIFACT-04	Plan S	assistant plan	Plan of plans S-0..S-15	conceptually useful; paths updated by later canon	yes	FACT
ARTIFACT-05	Early /source/setup directory skeletons	assistant/user trees	Early structure exploration	superseded	historical only	FACT
ARTIFACT-06	VS workload and language recommendation	assistant output	Toolchain decision support	still relevant unless canon changes	yes	FACT / INFERENCE
ARTIFACT-07	VS/Xcode CMake workflow guidance	assistant output	IDE integration model	still relevant	yes	FACT
ARTIFACT-08	Second setup master prompt	prompt	Restarted setup planning from scratch	superseded by existing implementation/canonical repo	partial	FACT
ARTIFACT-09	Old/current setup directory tree from Windows tree output	repo snapshot text	Evidence of outdated/redundant setup files	historical; actual state now unverified	yes	FACT
ARTIFACT-10	Assistant analysis of old tree	assistant output	Structural diagnosis	partially superseded	yes	FACT
ARTIFACT-11	Canonical repo/setup structure prompt	prompt	Locked top-level and setup filesystem/dependencies	current authoritative	critical	FACT
ARTIFACT-12	Plan S amendments for canonical repo	assistant output	Updated setup plan to canonical structure	current where consistent	yes	FACT
ARTIFACT-13	Phase 2 authoritative setup directory tree	assistant output	Concrete canonical setup file tree	useful reference; actual repo unverified	yes	FACT
ARTIFACT-14	Applied Codex Prompt 1 — One-pass refactor + repair + VS2026/CMake/Codex	prompt	Repo build/refactor enforcement	authoritative and said applied	critical	FACT
ARTIFACT-15	Applied Codex Prompt 2 — Final purity + contract ownership repair	prompt	Engine purity and contract relocation	authoritative and said applied	critical	FACT
ARTIFACT-16	Phase 3 schema definitions assistant output	assistant plan	Install plan/state/verify/audit schema proposal	useful; implementation unverified	yes	FACT
ARTIFACT-17	Generated prompt — Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass	prompt	Setup code/docs final hardening	critical next action if not executed	critical	FACT
ARTIFACT-18	Offline/net/update/customization capability mapping	assistant output	Capability decision explanation	accepted unless contradicted	yes	FACT / INFERENCE
ARTIFACT-19	Application-layer canon prompt	prompt	Application layer rules	authoritative project context pasted here	critical	FACT / PROJECT-CONTEXT
ARTIFACT-20	Latest other-chat project/application/release canon prompt	prompt	Full project status and release governance	authoritative project context pasted here	critical	FACT / PROJECT-CONTEXT
ARTIFACT-21	Assistant app-layer spine proposal	assistant output	Potential implementation next steps	proposal, not fully locked	carry with caution	INFERENCE
ARTIFACT-22	Maximum-fidelity Context Transfer Packet	assistant output	Retired-chat handoff	input to report package	critical	FACT
ARTIFACT-23	Final report package	generated files	Shareable report bundle	created	critical	FACT
Most important artifacts
ARTIFACT-11 is the most important structural artifact because it locks canonical repo/setup layout.

ARTIFACT-14 and ARTIFACT-15 are the most important implementation-governance artifacts because the user said they were already applied.

ARTIFACT-17 is the most actionable next prompt if setup docs/code still need gap closure.

ARTIFACT-19 and ARTIFACT-20 are important project-context artifacts, but their origin is broader than this chat.

ARTIFACT-23 is the package being rendered here.

13. Risks and Failure Modes
ID	Risk / failure mode	Consequence	Likelihood	Severity	Mitigation	Label
RISK-01	Future assistant follows obsolete adapters/packaging/source layout.	Canonical setup structure may be corrupted	medium	high	Always start from latest canonical setup layout	FACT / INFERENCE
RISK-02	Assistant suggestions are mistaken for user decisions.	Spec may harden tentative ideas incorrectly	medium	high	Preserve FACT/INFERENCE labels	FACT
RISK-03	Repo state differs from this packet.	Implementation may target missing/moved files	high	high	Inspect repo before acting	UNCERTAIN / UNVERIFIED
RISK-04	Launcher duplicates setup update/repair logic.	Authority and audit guarantees break	medium	high	Use setup invocation + schema reports only	FACT
RISK-05	Engine purity regresses.	Engine becomes unreusable/contaminated	medium	high	Run tree/include sanity checks in CI	FACT
RISK-06	Ad-hoc setup formats drift from schema.	Launcher/setup incompatibility and unverifiable state	medium	high	Execute schema normalization phase	FACT / INFERENCE
RISK-07	GUI/TUI embeds business logic.	CLI parity/determinism broken	medium	medium-high	Use command graph + UI IR validation	FACT / PROJECT-CONTEXT
RISK-08	Network install becomes required unintentionally.	Offline/air-gapped support fails	medium	medium-high	Test offline path; network is transport only	FACT / INFERENCE
RISK-09	Rollback is under-tested.	Partial installs may corrupt state	medium	high	Fault-injection tests for every transaction phase	FACT
RISK-10	Build metadata/changelog manually edited.	Release traceability lost	medium	medium-high	Use RepoX-generated outputs only	FACT / PROJECT-CONTEXT
RISK-11	Legacy platform goals impose modern constraints on engine/game.	Toolchain compatibility breaks	medium	medium	Keep app toolchains isolated from engine/game	FACT
RISK-12	Context package omits exact old prompt wording.	Future re-execution may miss nuance	medium	medium	Use artifact ledger; request original prompt if exact replay needed	UNCERTAIN / UNVERIFIED
RISK-13	Future aggregation deduplicates conflicting chats too aggressively.	Contradictions erased	medium	high	Preserve provenance and contradictions	FACT
RISK-14	Dates/tool versions become stale.	Build instructions may fail later	medium	medium	Verify external/toolchain facts before use	FACT
RISK-15	Generated report files are edited manually and diverge.	Aggregation data integrity weakens	low	medium	Keep Markdown/YAML/ZIP together; note edits	FACT
Highest-risk failure modes
The highest-risk issue is RISK-03: the repo may differ from the package. This package is excellent for continuity, but it cannot prove the current repository state.

The next highest risks are authority violations: launcher duplicating setup logic, engine purity regression, and ad-hoc schema drift. These would undermine the whole design.

Aggregation risk is also high. A future aggregator must not collapse assistant proposals into decisions or erase contradictions between reports.

14. Verification Queue
ID	Item requiring verification	Why verification is needed	Suggested source/type	Priority	Label
VERIFY-01	Current setup/ tree	Determine actual post-refactor state	tree /f setup or repo inspection	highest	UNCERTAIN / UNVERIFIED
VERIFY-02	Current schema/ tree	Setup I/O must be schema-backed	tree /f schema, schema docs	highest	UNCERTAIN / UNVERIFIED
VERIFY-03	libs/contracts existence and CMake target	Neutral contracts mandatory	tree /f libs/contracts, CMake build	high	UNCERTAIN / UNVERIFIED
VERIFY-04	CMake configure/build/test	Build claims require proof	cmake --preset, build, ctest	highest	UNCERTAIN / UNVERIFIED
VERIFY-05	setup --help and launcher --help	Required smoke tests	Run built executables	highest	UNCERTAIN / UNVERIFIED
VERIFY-06	verify_tree_sanity and verify_includes_sanity scripts	Boundary enforcement must work	Run/inspect scripts	high	UNCERTAIN / UNVERIFIED
VERIFY-07	docs/SETUP_GAPS.md and related setup docs	Shows hardening prompt executed	Docs inspection	high	UNCERTAIN / UNVERIFIED
VERIFY-08	setup/core/fetch offline/network behavior	Capability accepted but implementation unknown	Source/tests inspection	medium	UNCERTAIN / UNVERIFIED
VERIFY-09	Update/downgrade operation semantics	Required flows need schemas/tests	CLI/schema/tests inspection	medium	UNCERTAIN / UNVERIFIED
VERIFY-10	UI IR and binding validation path	Canon requires UI as data	CANON_INDEX.md, APP-UI-BIND-0, schema/	medium	UNCERTAIN / UNVERIFIED
VERIFY-11	RepoX/TestX/BUILD-ID tooling status	Release governance depends on it	RepoX/TestX docs/tools/CI	high	UNCERTAIN / UNVERIFIED
VERIFY-12	Legacy platform support status	Avoid assuming implementation exists	platform/win9x, mac/classic, docs	medium-low	UNCERTAIN / UNVERIFIED
VERIFY-13	Old IDE artifacts quarantined/non-authoritative	Prevents IDE build drift	Find .sln, .vcxproj, .xcodeproj; inspect legacy READMEs	medium	UNCERTAIN / UNVERIFIED
VERIFY-14	Docs status-header policy	CLEAN-2/canon management requires it	Docs and RepoX checks	medium	UNCERTAIN / UNVERIFIED
VERIFY-15	Package contents after generation	Ensure package saved correctly	Inspect generated files/package	high	FACT
Verification groups
Current-world/tool facts: VERIFY-04, VERIFY-11, VERIFY-13.
Technical assumptions: VERIFY-01 through VERIFY-10.
Missing files/artifacts: VERIFY-02, VERIFY-03, VERIFY-07.
Dates/deadlines: no project deadline was established in this chat.
Personal assumptions: preferences are mostly explicit; only PREF-06 is inferred.
Legal/institutional/rule facts: third-party branding/IP constraints should be preserved; external platform/package-manager rules require current verification before use.

15. Timeline of the Chat
Sequence	Event / topic	What changed or was decided	Why it mattered	Current relevance	Confidence
1	Initial setup master prompt	User defined setup scope, legal/IP limits, common core, manifests, transaction model, adapters, CLI, tests/docs	Established initial setup architecture	Historical but foundational	high
2	Phase 1 setup core architecture	Assistant designed modules and transaction/determinism model	Created baseline conceptual architecture	Conceptually relevant; paths superseded	high
3	Plan S requested and produced	User asked for plan-of-plans; assistant produced S-0..S-15	Organized future setup design	Conceptually relevant	high
4	Empty /source/setup implementation discussion	User wanted VS2026, Watcom, Xcode, Linux/storefront/legacy support	Drove early toolchain/directory thinking	Superseded structurally	high
5	Early directory trees/refinements	User/assistant iterated on setup/core/adapters/packaging/tests/docs and macosc	Produced historical layouts	Superseded by canonical repo	high
6	Improvement suggestions	Assistant proposed ABI headers, platform iface split, policy, bridge common, declarative packaging	Some ideas carried forward conceptually	Partially relevant	medium-high
7	Step-by-step skeleton and CMake	Assistant gave early skeleton and minimal core/CLI steps	Early implementation path	Superseded	medium
8	VS workload/language question	Assistant recommended C++ desktop workload and C/C++, not .NET execution	Toolchain rationale	Still relevant	medium-high
9	VS/Xcode project location	Assistant recommended generated projects via CMake	Build authority direction	Still relevant	high
10	New setup master prompt	User reset setup planning with core/adapters/schemas/tests philosophy	Drove another Phase 1	Later superseded	medium-high
11	User posted old setup tree	User showed redundant/outdated setup implementation	Concrete evidence of drift	Historical risk source	high
12	Old tree analysis	Assistant recommended moving packaging, removing IDE artifacts, clarifying DSK/DSU	Fed later canonical model	Partially superseded	medium-high
13	Future components/nested source critique	User questioned nested source and future components	Raised scalability concerns	Superseded by canonical top-level products	medium
14	Canonical repo/setup prompt	User locked top-level products, setup authority, layout, dependencies, includes	Changed ground truth	Current critical	high
15	Plan S amendments	Assistant realigned setup plan to canonical repo	Updated phase mapping and enforcement	Current relevant	high
16	Phase 2 canonical directory tree	Assistant produced expected setup tree/target naming	Reference for checks	Useful; repo unverified	high
17	Two applied Codex prompts	User stated refactor/build and purity prompts were applied	Established new baseline assumptions	Critical; verify actual repo	high
18	Phase 3 schema definitions	Assistant defined schema families and launcher handoff	Continued plan under new constraints	Useful; implementation unverified	medium-high
19	Generated setup hardening prompt	Assistant produced phases A–H	Actionable next implementation pass	Critical if not executed	high
20	Capability question	User asked about offline/net/update/customization/etc.; assistant mapped support	Clarified setup capabilities	Current relevant	medium-high
21	Application-layer canon pasted	User provided app scope/UI/RepoX/SRZ rules	Expanded context to apps	Current project context	high
22	Latest other-chat canon pasted	User provided full project status/versioning/automation	Reinforced no redesign/release governance	Current project context	high
23	Context Transfer Packet requested and produced	User retired chat; assistant created maximum-fidelity packet	Baseline for report package	Input to package	high
24	Final report package requested	User asked to export package	Created report package	Current output source	high
25	In-chat reader requested	User asked to render package contents inside chat	Current response renders package	Current	high
Major changes of direction
From greenfield setup design to existing implementation audit.
Early “assume nothing exists” framing was superseded by “existing implementation is authoritative unless violating canon.”

From old setup/adapters tree to canonical setup/platform/ui/packages layout.
This is the most important structural shift.

From setup-only to broader application-layer context.
Later pasted canon introduced launcher/client/server/tools/UI/RepoX constraints.

From design output to preservation/aggregation.
The final part focused on reusable report packaging.

16. Spec Book Contribution
Spec-book area	Contribution from this chat	Source IDs	Confidence	Notes
Setup System Architecture	Setup sole authority, deterministic transaction model	WORKSTREAM-01, DECISION-01, 02, 17, 19	high	Formal requirement candidate
Repository Layout	Canonical setup and top-level repo layout	WORKSTREAM-02, DECISION-03, 26	high	Verify actual repo
Contracts and Schemas	Setup/launcher schema-only handoff	WORKSTREAM-04, DECISION-07, 27	high	Needs schema file verification
Architecture Boundaries	Engine purity, neutral contracts	WORKSTREAM-03, DECISION-08, 09	high	Verify scripts/CMake
Build System	CMake/VS2026 build enforcement	WORKSTREAM-02, DECISION-12	medium-high	Toolchain facts may stale
Distribution and Setup Operations	Offline/online/update/repair/downgrade support	WORKSTREAM-06, DECISION-15, 16, 18	medium-high	Implementation unverified
Application Layer	CLI canonical, UI as data, content-agnostic apps	WORKSTREAM-05, 07, DECISION-10, 11	high for canon, medium for exact paths	Project-context overlap likely
Release Governance	RepoX/TestX/BUILD-ID-0	WORKSTREAM-08, DECISION-22, 23	medium-high	Project-context; verify tooling
Platform Support	WinNT, Win9x, macOS X/classic, Linux, stores/legacy	WORKSTREAM-09	medium-high	Priority unclear
Knowledge Management	Per-chat report package workflow	WORKSTREAM-10	high	Useful for aggregation process
Formal requirements candidates
Setup sole authority.

Schema-only setup/launcher handoff.

CMake authoritative build.

No engine contamination.

CLI canonical; UI as data.

No manual changelog editing.

No hidden repair/update mutation.

Rollback is first-class.

Offline installs do not require network.

Background context candidates
Early directory explorations.

Initial Plan S pre-canonical structure.

Installer reference images.

Old redundant setup tree.

Needs user confirmation before becoming spec
Exact app command spine path.

Exact UI IR path.

Priority of legacy platform implementation.

Whether setup hardening prompt has already been executed.

17. Top Things to Preserve
Priority	Item	Type	Related ID	Why it matters	Risk if lost	Label
1	Setup is sole install/system-state mutation authority.	Requirement	DECISION-01	Central architecture boundary	Launcher/engine may bypass setup	FACT
2	Canonical setup layout supersedes old trees.	Structure	DECISION-03	Prevents path regression	Work targets obsolete files	FACT
3	Setup depends only on libs/ and schema/.	Dependency	DECISION-04	Maintains isolation	Coupling to engine/launcher	FACT
4	Launcher consumes setup outputs and invokes setup only.	Contract	DECISION-07	Prevents duplicated setup logic	Broken audit/rollback	FACT
5	Engine purity and neutral contracts are mandatory.	Boundary	DECISION-08, 09	Keeps engine reusable	Engine contamination	FACT
6	Existing implementation is authoritative unless violating canon.	Process	DECISION-20	Prevents redesign	Lost implementation work	FACT
7	Do not delete code; quarantine legacy code.	Process	DECISION-21	Preserves history/buildability	Accidental behavior loss	FACT
8	Generated setup hardening prompt is a critical artifact.	Artifact	ARTIFACT-17	Provides next implementation phases	Gap closure skipped	FACT
9	Actual repo state is unverified.	Caveat	VERIFY-01 through 07	Prevents false confidence	Broken implementation assumptions	UNCERTAIN / UNVERIFIED
10	CLI canonical; GUI/TUI views.	Application rule	DECISION-10	Ensures parity/scriptability	UI drift	FACT / PROJECT-CONTEXT
11	UI is data/UI IR, not logic.	UI rule	DECISION-11	Enables validation/accessibility/localization	Business logic in UI	FACT / PROJECT-CONTEXT
12	RepoX/TestX/BUILD-ID govern release metadata.	Governance	DECISION-22, 23	Release traceability	Manual/stale metadata	FACT / PROJECT-CONTEXT
13	Offline and online installs are both supported.	Capability	DECISION-15	Air-gapped + online distribution	Network dependency	FACT / INFERENCE
14	Update check is non-mutating.	Capability	DECISION-16	Prevents hidden mutation	Unsafe update behavior	FACT / INFERENCE
15	Repair is explicit, rollback journaled.	Operation	DECISION-17, 19	Recovery safety	Silent corruption	FACT
16	Packaging belongs under setup/packages/.	Structure	DECISION-06	Keeps packaging declarative	Logic leaks into adapters	FACT
17	Schema is canonical data-format location.	Contract	DECISION-27	Enables validation	Ad-hoc format drift	FACT
18	Preserve labels in aggregation.	Knowledge mgmt	CONSTRAINT-35	Prevents false merging	Assistant suggestions harden into spec	FACT
19	Reject old setup/adapters active layout.	Rejected path	REJECTED-07	Avoids obsolete architecture	Repeated refactor	FACT
20	Verify build and smoke tests before acting.	Verification	VERIFY-04, 05	Confirms implementation reality	Build failures ignored	UNCERTAIN / UNVERIFIED
18. Things Future Assistants Must Not Assume
Do not assume the actual repo matches the canonical layout until inspected.

Do not assume the two applied Codex prompts succeeded fully.

Do not assume the generated setup hardening prompt has been executed.

Do not assume schema/setup/* files exist.

Do not assume libs/contracts compiles.

Do not assume setup --help or launcher --help works.

Do not assume libs/appcmd exists or is the canonical command-spine path.

Do not assume UI IR lives at a specific path.

Do not assume legacy Win9x/macOS Classic implementation is immediate priority.

Do not assume .NET is acceptable for setup execution.

Do not assume old setup/adapters or setup/packaging trees are current.

Do not assume project-level pasted canon originated in this chat; preserve PROJECT-CONTEXT.

Do not assume external tool/version facts remain current.

Do not treat assistant proposals as decisions unless accepted or canonized.

Do not merge contradictory old-chat reports without preserving provenance.

19. Question Menu for This Chat
19.1 Understanding the Chat
“Explain this chat in simpler terms.”

“What are the most important things from this chat?”

“What should I read first?”

“What changed from the earlier setup plan to the canonical plan?”

“Which parts are FACT versus PROJECT-CONTEXT?”

19.2 Workstreams
“Explain WORKSTREAM-01 in detail.”

“Which workstreams are active?”

“Which workstreams should go into the master spec book?”

“Which workstreams depend on repo verification?”

“Which workstreams are mostly historical?”

19.3 Decisions
“Explain DECISION-07 and its implications.”

“Which decisions are tentative?”

“Which decisions might conflict with other chats?”

“Which decisions are hard canon?”

“Which decisions came from assistant recommendation rather than direct user prompt?”

19.4 Tasks
“What should I do next from this chat?”

“Which tasks are blocked?”

“Turn TASK-01 through TASK-13 into a checklist.”

“Which tasks should be converted into a Codex prompt?”

“Which tasks are urgent versus merely important?”

19.5 Artifacts
“Explain ARTIFACT-17.”

“Which files/prompts should I preserve?”

“Which artifacts are required for the future spec book?”

“Which artifacts are superseded?”

“Which artifacts need verification?”

19.6 Verification
“What should I verify before trusting this chat?”

“Which facts may be stale?”

“Which assumptions are weakest?”

“Group verification items by repo/build/schema/application.”

“Make a Windows command checklist for VERIFY-01 through VERIFY-07.”

19.7 Aggregation
“What should the aggregator preserve from this chat?”

“What might conflict with other chat reports?”

“Summarise this chat for the master Project Spec Book.”

“Which items should not be merged prematurely?”

“Which items overlap with application-layer canon from other chats?”

20. Recommended Next Questions
“Which VERIFY-* items should I check first, and what exact commands should I run?”

“Explain the generated setup hardening prompt and why it matters.”

“Which old setup directory structures are superseded and must not be reused?”

“Turn the setup verification queue into a Codex-ready prompt.”

“Which decisions are hard canon versus assistant-derived inference?”

“What should go into the Project Spec Book from this chat?”

“What are the highest-risk misunderstandings from this package?”

“Explain the setup ↔ launcher handoff model.”

“Explain offline/net/update/downgrade support boundaries.”

“Create a compact aggregator note from this in-chat reader.”

21. Compact Copyable Summary
Chat label: Dominium Setup Handoff. Date anchor: 2026-05-27 Australia/Melbourne. This old chat focused on the Dominium / Domino Setup system and then expanded into repository, build, application-layer, and report-packaging continuity.

The most important fact is that setup/ is the sole authority for install, upgrade, downgrade, verification, repair, uninstall, rollback, and packaging layout enforcement. Launcher may invoke setup and consume setup outputs, but must not reimplement setup logic. Engine must not know setup exists. Setup may depend only on libs/ and schema/.

The chat began with a cross-platform setup architecture: common setup core, thin platform adapters, deterministic manifests, installed-state, audit logs, transaction phases, CLI/headless support, Windows/macOS/Linux/Steam/Epic/legacy support, and clean uninstall/repair/rollback. It then produced Plan S, a plan-of-plans for setup. Early directory trees used setup/adapters, setup/packaging, and core/source; these are now superseded.

The canonical repository structure was later locked: engine/, game/, client/, server/, launcher/, setup/, tools/, libs/, schema/, sdk/, docs/, ci/, and legacy/. The canonical setup structure is setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages/{client,server,tools,scripts}, setup/platform/{win/{win9x,winnt},linux,bsd,mac/{classic,osx}}, setup/tests, setup/ui, and setup/CMakeLists.txt. Old setup/adapters, adapter-local packaging, and generic setup source/ directories are rejected or superseded.

The user pasted two Codex prompts as already applied. One covered VS2026/CMake refactor and build repair; the other covered engine purity and contract ownership. These require CMake as build authority, target-scoped includes, no hand-authored IDE projects as authoritative build files, smoke tests, engine purity, and cross-product contracts under libs/contracts/include/dom_contracts. Actual repo state after these prompts is UNCERTAIN / UNVERIFIED.

A key generated artifact is “Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass.” It should be executed or audited next unless already completed. It contains phases for setup gap inventory, schema completion, kernel API hardening, platform adapter audit, UI audit, packaging/reproducibility hardening, test alignment, and baseline docs/freeze marker. It explicitly says not to redesign setup and to treat existing implementation as authoritative unless it violates locked rules.

The chat clarified setup capabilities: offline installs, network installs, update checking, component/package customization, repair, uninstall, upgrade, downgrade, and rollback are all architecturally supported. Network is optional transport, update checking is non-mutating unless explicit update is invoked, repair is explicit, uninstall is installed-state/ownership-based, and rollback is journaled.

Later user-pasted application-layer canon is marked PROJECT-CONTEXT: applications are content-agnostic shells; CLI is canonical; GUI/TUI are views; UI is data via UI IR; tools are read-only by default; RepoX/TestX and BUILD-ID-0 govern validation, changelogs, build identity, and releases.

Highest-priority tasks: verify actual repo state, validate setup/, inspect schema/ and libs/contracts, run CMake configure/build/test, run setup --help and launcher --help, inspect sanity scripts, then execute/audit the setup hardening prompt.

Highest risks: future assistants may reuse obsolete layouts, confuse assistant proposals with user decisions, assume repo state without verification, let launcher duplicate setup logic, let engine purity regress, or merge this report with other chats too aggressively.

Best next action: verify the current repo tree/build state, then execute or audit the generated setup hardening prompt.

22. Final Reader Status
Reader Status
Chat label: Dominium Setup Handoff

Report package readable in chat: yes

Files inspected or reconstructed from visible context: generated package files inspected from /mnt/data: manifest, full chat report, YAML spec sheet, aggregator packet, registers, reader brief, verification/audit; visible chat context used only where needed to preserve provenance.

Most important section to read: Sections 5–8 for workstreams/decisions/tasks/constraints; Section 14 for verification before implementation.

Best question to ask next: “Which VERIFY-* items should I check first, and what exact commands should I run?”

Safe for aggregation: with caveats

Main caveats: actual repository state remains unverified; some application-layer material is PROJECT-CONTEXT; assistant proposals such as exact app command spine/UI IR path are INFERENCE, not locked decisions.


You are GPT-5.5 Pro using extended deep reasoning.

I do not want another machine-readable handoff, YAML spec sheet, register dump, or file index.

I want a human-readable, intuitive, detailed report that explains this entire chat in plain language.

Your task is to read the visible conversation in this chat and produce a clear narrative report explaining:
- what we discussed,
- why we discussed it,
- what problems or goals we were trying to solve,
- what decisions were made,
- why those decisions were made,
- what changed over time,
- what remains unresolved,
- what future work follows from this chat,
- and what I need to remember so I do not have to re-read the whole chat.

This should feel like a careful human briefing document, not a database export.

If this chat previously generated downloadable files, handoff packets, reports, registers, spec sheets, or summaries, you may use them as supporting material, but do not make the response about the files. The main goal is to explain the substance of the conversation itself.

CRITICAL STYLE REQUIREMENTS:
1. Write primarily in clear prose.
2. Use headings to make the report navigable.
3. Use tables only when they genuinely help; do not turn the whole response into tables.
4. Explain context, motivation, and reasoning in natural language.
5. Do not merely list items. Explain what they mean and why they matter.
6. Do not produce YAML, JSON, manifests, or machine-oriented schemas.
7. Do not focus on download links or file packaging.
8. Do not invent facts.
9. Do not silently infer. When something is inferred, say so.
10. Distinguish:
   - FACT: explicitly stated or clearly established in this chat.
   - INFERENCE: reasonably inferred from the conversation.
   - UNCERTAIN / UNVERIFIED: unclear, stale, incomplete, or not directly established.
11. Do not treat assistant suggestions as user decisions unless the user accepted them.
12. Do not treat brainstorms as final decisions.
13. Preserve rejected, superseded, or deprioritised ideas if they matter.
14. Preserve contradictions, changes of direction, and uncertainty.
15. Include visible rationale for decisions, but do not claim access to hidden chain-of-thought.
16. If the answer becomes long, continue in labelled parts rather than compressing aggressively.

DATE ANCHOR:
Use 2026-05-27 Australia/Melbourne as the date anchor unless this chat clearly provides a different relevant date.

OUTPUT:

# Human-Readable Chat Report — [Infer a short descriptive title for this chat]

## 1. One-Page Orientation

Start with a clear, readable overview of this chat.

Explain:
- what this chat was mainly about,
- what the user was trying to accomplish,
- why the topic mattered,
- what the main outcomes were,
- what the future relevance of the chat is,
- and what someone should understand before reading the rest of the report.

This should be 500–900 words and written as prose, not bullets.

## 2. The Story of the Conversation

Explain the conversation chronologically.

Do not just list turns. Tell the story of how the discussion developed.

Cover:
- how the chat began,
- what the initial goal or problem was,
- how the user refined or changed the goal,
- what major ideas were explored,
- what outputs or plans were created,
- what disagreements, corrections, or changes happened,
- what the final state of the conversation became.

Use subsections if helpful.

## 3. Main Topics We Discussed

Explain each major topic in this chat.

For each topic, include:
- what the topic was,
- why it came up,
- what was discussed,
- what conclusions were reached,
- what remains uncertain,
- and how it connects to future work.

Use this format:

### Topic 1 — [Name]
[Detailed prose explanation]

### Topic 2 — [Name]
[Detailed prose explanation]

Continue for all major topics.

## 4. What We Were Trying to Achieve

Explain the underlying goals behind the chat.

Separate:
- explicit goals the user stated,
- inferred goals,
- goals that changed over time,
- goals that remained unresolved.

For each goal, explain why it mattered and how the conversation addressed it.

## 5. Decisions Made and Why

This is one of the most important sections.

Explain every important decision that was made in the chat.

For each decision, include:
- what was decided,
- whether it was final, tentative, or uncertain,
- who made or accepted the decision,
- what alternatives were considered,
- why this decision made sense at the time,
- what assumptions it depended on,
- what it affects going forward,
- and what might cause the decision to be revisited.

Use prose first. A short table at the start is acceptable, but each important decision must be explained in detail afterwards.

## 6. Ideas Considered but Rejected, Superseded, or Deprioritised

Explain ideas that were explored but not carried forward.

For each:
- what the idea was,
- why it was considered,
- why it was rejected, superseded, or deprioritised,
- whether that rejection is final or only temporary,
- and when it might become relevant again.

This section matters because it prevents future chats from repeating old work.

## 7. Important Reasoning and Rationale

Explain the visible reasoning behind the major conclusions.

Focus on:
- tradeoffs discussed,
- constraints that shaped the choices,
- why one path was preferred over another,
- what risks were being managed,
- what assumptions were made,
- and what the user seemed to care about most.

Do not provide hidden chain-of-thought. Give an audit-ready explanation of the visible rationale and conclusions.

## 8. Plans, Future Work, and Next Steps

Explain all future-oriented material from this chat.

Include:
- future plans,
- pending tasks,
- recommended next actions,
- things to prepare,
- things to verify,
- dependencies,
- blockers,
- and the best order to proceed.

For each major next step, explain:
- what it is,
- why it matters,
- what must happen before it,
- what output it should produce,
- and what could go wrong.

## 9. Constraints, Preferences, and Non-Negotiables

Explain the constraints and preferences that shaped the conversation.

Include:
- user communication preferences,
- formatting preferences,
- evidence and citation preferences,
- technical constraints,
- time or resource constraints,
- accuracy requirements,
- safety/legal/ethical constraints if relevant,
- and things future assistants should avoid.

Separate explicit constraints from inferred ones.

## 10. Files, Artifacts, Outputs, and Prompts Mentioned or Created

Explain any important files, outputs, prompts, documents, code, links, reports, plans, or generated artifacts associated with this chat.

Do not merely list filenames.

For each artifact, explain:
- what it is,
- why it was created or mentioned,
- what it contains,
- how it should be used,
- whether it should be preserved,
- whether it should feed into a larger future report/spec book,
- and whether anything about it is uncertain.

If no artifacts were created or mentioned, say that clearly.

## 11. Open Questions and Unresolved Issues

Explain what remains unresolved.

For each unresolved issue:
- what the question is,
- why it matters,
- what is currently known,
- what is unknown,
- what would resolve it,
- whether the user needs to decide something,
- and whether external verification is needed.

## 12. Risks, Failure Modes, and Things Future Chats Might Get Wrong

Explain the main ways a future assistant could misunderstand or mishandle this chat.

Include risks such as:
- forgetting important context,
- over-compressing the chat,
- treating tentative ideas as final,
- repeating rejected suggestions,
- ignoring user preferences,
- relying on stale information,
- losing files or artifacts,
- merging this chat incorrectly with other chats,
- or inventing missing details.

For each risk, explain how to avoid it.

## 13. What This Chat Contributes to the Larger Project

Explain how this chat fits into the larger project or future spec book.

Include:
- what unique value this chat contributes,
- what sections of a future spec book it should inform,
- what should become formal requirements,
- what should remain background context,
- what likely overlaps with other chats,
- what might conflict with other chats,
- and what needs verification before being merged.

## 14. What I Should Remember

Write a clear, human-readable memory section.

This should be a concise but detailed explanation of the most important carry-forward points from the chat.

Use bullets here if useful, but make each bullet explanatory.

Include:
- the most important conclusions,
- the most important decisions,
- the most important next actions,
- the most important unresolved issues,
- the most important risks,
- and the most important artifacts or outputs.

## 15. Best Questions I Can Ask Next in This Chat

Give me a practical list of follow-up questions I can ask inside this old chat.

The questions should help me:
- understand the chat more deeply,
- inspect decisions,
- clarify unresolved issues,
- prepare for aggregation with other chats,
- extract material for a future spec book,
- or verify weak points.

Make the questions specific to this chat’s actual content, not generic.

## 16. Final Plain-English Summary

End with a compact but substantial 800–1,500 word summary.

This should be the version I can read later if I only have a few minutes.

It should explain:
- what this chat was about,
- what mattered most,
- what was decided,
- why it was decided,
- what remains to do,
- what to preserve,
- and what the next assistant should understand.

End with:

# Reader Status

- Chat title:
- Report type: human-readable explanatory report
- Main value of this chat:
- Most important decision:
- Most important unresolved issue:
- Most important next action:
- Safe to use for later aggregation: yes / no / with caveats
- Main caveats:

I’ll convert the package and visible chat into a plain-language briefing, preserving uncertainty, rationale, and changes of direction without reverting to register-style output.

Thought for 6m 10s
GPT-5.5 Pro — 2026-05-27 17:05:46

Human-Readable Chat Report — Dominium Setup Architecture and Handoff
1. One-Page Orientation
This chat was mainly about designing, correcting, and preserving the Dominium / Domino Setup system: the installer, updater, verifier, rollback, repair, uninstall, packaging, and distribution layer for the larger Dominium project. The key point is that this was not a launcher UI chat, not an engine-design chat, and not a gameplay/simulation-design chat. It focused on the application-layer product called setup/, whose job is to install and maintain the rest of the software safely and deterministically.

The user’s goal evolved over the conversation. At first, the discussion was broad and architectural: how should a cross-platform installer work for Windows, macOS, Linux, Steam/Epic, package managers, and legacy platforms? The user wanted a setup system that could support modern Windows through Visual Studio, Windows 9x through Watcom or similar legacy toolchains, macOS X and classic macOS, Linux package managers, Steam/Epic-style distribution, web installers, consoles, retro systems, offline installs, network installs, update checking, package customization, repair, uninstall, downgrade, and rollback. The goal was not just to make an installer executable; it was to define a deployment control plane with deterministic behavior, audit logs, reversible transactions, clean installed-state ownership, and long-term survivability.

As the chat progressed, the discussion moved from early directory sketches to a much stricter canonical repository model. Earlier ideas used structures like setup/adapters/, setup/packaging/, core/source/, and platform-specific subtrees. Those were useful exploration steps, but they were later superseded. The user introduced a locked repository structure with top-level products such as engine/, game/, client/, server/, launcher/, setup/, tools/, libs/, schema/, docs/, ci/, sdk/, and legacy/. Under that model, the setup product has a fixed layout: setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages, setup/platform, setup/tests, and setup/ui. That canonical structure became the ground truth.

The most important decision in the chat is this: setup is the only component allowed to install files, modify installation state, verify installed artifacts, repair installs, uninstall, downgrade, upgrade, and own installed-file metadata. The launcher may invoke setup, but it may not duplicate setup logic. The engine must not know setup exists. Setup communicates with the launcher only through manifests, schemas, installed-state snapshots, reports, and exit/status contracts.

Another major outcome was that the user pasted two large Codex prompts that had already been applied elsewhere. Those prompts were intended to repair the repository, enforce Visual Studio 2026 and CMake build structure, clean up engine purity, move cross-product contracts into libs/contracts, and prevent setup/launcher/tool contamination of the engine. This chat then treated those prompts as authoritative but also marked the actual repository state as UNCERTAIN / UNVERIFIED, because the build results and final tree were not visible here.

Near the end, the chat shifted into preservation mode. The user asked for a maximum-fidelity context transfer packet, then for a downloadable report package, then for an in-chat reader version of that package. Those outputs preserved the decisions, tasks, constraints, artifacts, rejected options, and verification queue for future assistants or aggregation into a larger Project Spec Book.

What future readers must understand is that this chat is both a setup-system design record and a transition record. It shows how the setup architecture moved from exploratory design into canonical repository alignment. It also records what must not be repeated: do not resurrect old adapter layouts, do not let the launcher install things, do not let the engine include setup headers, do not treat assistant brainstorms as decisions, and do not continue implementation until the actual repo state has been verified.

2. The Story of the Conversation
The chat began with a setup-system master prompt
The first major input was a detailed master prompt for the Dominium / Domino Setup & Installation System. It said this chat was about setup, installation, packaging, distribution, and uninstallation across supported platforms. It explicitly excluded launcher UI work. The setup system was described as a deterministic deployment control plane, not a simple GUI wizard or a store/DRM mechanism.

The user specified that there should be one common setup core shared across platforms, with thin platform-specific frontends. The setup core had to parse manifests, resolve component graphs, execute transactions, record installed state, support install/upgrade/repair/uninstall, and emit audit logs. It also had to support GUI-driven, CLI/headless, package-manager-driven, and Steam-driven installs.

The assistant responded with Phase 1: Setup Core Architecture, proposing modules such as manifest parsing, resolution, planning, transaction execution, filesystem/path policy, installed-state, logging, and a platform interface. This was the first conceptual baseline.

The user asked for “Plan S”
The user then asked for a “plan of plans” called Plan S, with subplans S-1, S-2, S-3, and so on. The assistant produced a structured setup roadmap. It covered governance, setup core architecture, manifest schema, installed-state schema, transaction engine, filesystem policy, audit logging, CLI, Windows/macOS/Linux adapters, Steam integration, distribution pipeline, side-by-side upgrades, tests, and documentation.

At that stage, the plan was still mostly abstract and platform-oriented. It was useful because it separated the work into durable phases, but later repository changes made some of its directory assumptions obsolete.

The conversation moved into concrete directory layout and IDE/toolchain decisions
The user then asked how to start from an empty /source/setup/ directory and build setup applications for:

Windows NT 32/64 via Visual Studio 2026,

Windows 9x via Watcom or alternatives,

macOS X 10.4 through current macOS via Xcode,

Intel and ARM, 32-bit and 64-bit,

Linux from roughly 2000 onward,

package managers,

Steam/Epic/web/consoles/retro/legacy distribution.

The assistant recommended a common C/C++ setup core with CMake for modern IDE integration, plus isolated legacy build scripts for targets like Windows 9x. The assistant generated several directory trees. The user suggested modifications, such as using source instead of src, using winnt rather than win_nt, adding macosc for classic Mac OS, and renaming integrate to integration.

These directory trees were not final, but they mattered because they exposed the user’s preference for simple, shallow, logical structures and native IDE workflows that do not become the source of truth.

The user also asked whether to use Visual Studio’s Desktop development with C++ workload or .NET Desktop Development, and whether setup should use C/C++ or C#/.NET. The assistant recommended Desktop development with C++ and C/C++ for the authoritative setup execution path. The reasoning was that setup must support legacy systems, offline installs, stable ABI boundaries, and deterministic behavior. The assistant treated .NET as acceptable only for optional non-authoritative tools, not for setup’s core execution path.

The user later asked where to create Visual Studio and Xcode apps after opening the repo as a folder. The assistant advised that Visual Studio and Xcode projects should be generated through CMake, not hand-authored or treated as authoritative source files. This decision became consistent with later Codex prompts.

The user showed an existing setup tree with redundancy and drift
A major turn occurred when the user pasted a Windows tree output of the current setup directory. It showed many outdated or redundant files: platform adapters under adapters/, packaging scripts inside platform adapter folders, committed Visual Studio and Xcode project files, multiple duplicate CLI/main files, mixed dsu_* and dsk_* namespaces, and an empty schemas directory.

The assistant analyzed that tree and identified several problems:

setup logic and packaging were mixed together,

IDE artifacts were in-tree,

duplicate entrypoints existed,

dsu_* and dsk_* boundaries were unclear,

platform-specific files and packaging scripts were too entangled,

core and adapter boundaries were not enforceable enough.

At that moment, the conversation was still framed around improving the existing structure, but the user soon introduced a more authoritative repository layout.

The canonical repository structure replaced earlier setup trees
The user then gave a strict system-role prompt saying the repository had undergone a major structural refactor and that the filesystem was now canonical ground truth. This superseded earlier structures. The locked top-level products became:

engine/

game/

client/

server/

launcher/

setup/

tools/

libs/

schema/

sdk/

docs/

ci/

legacy/

The canonical setup layout was defined as:

setup/core/fetch

setup/core/verify

setup/core/install

setup/core/rollback

setup/include/dsk

setup/include/dsu

setup/packages/client

setup/packages/server

setup/packages/tools

setup/packages/scripts

setup/platform/win/{win9x,winnt}

setup/platform/linux

setup/platform/bsd

setup/platform/mac/{classic,osx}

setup/tests

setup/ui

setup/CMakeLists.txt

This became a decisive turning point. Earlier setup/adapters, setup/packaging, and core/source structures became historical and superseded. The assistant amended Plan S to match the new canonical structure and later produced an authoritative Phase 2 directory tree under that model.

Two applied Codex prompts changed the implementation baseline
The user later pasted two large prompts and stated that they had already been applied. The first prompt was a broad one-pass refactor and repair prompt for Visual Studio 2026, CMake, Codex, buildability, launcher/setup/tools/engine targets, and smoke tests. The second prompt was a final purity and contract ownership repair prompt. It required removing non-engine content from engine/, moving setup and UI headers to their correct owners, introducing libs/contracts/include/dom_contracts, and enforcing boundaries with scripts and CMake.

This changed the status again: the setup system was no longer being treated as purely theoretical or greenfield. The current implementation was to be treated as authoritative unless it violated locked constraints.

The assistant then produced a Phase 3 schema plan under the new assumptions, covering install plan schemas, installed-state schemas, verification reports, audit logs, and the schema-only setup/launcher handoff.

The user asked for a final setup-spec alignment prompt
The user then asked for a prompt to get setup code and documentation up to spec before restarting and regenerating future plans. The assistant generated a Codex prompt titled “Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass.” This prompt is one of the most important outputs of the chat. It instructs Codex to inventory setup, identify gaps, normalize schemas, harden public APIs, audit platform adapters, audit UI frontends, harden packaging and reproducibility, align tests, and create final documentation/freeze markers.

This prompt is important because it bridges the gap between architectural planning and implementation cleanup. It says: do not redesign setup; finish, document, and align what exists.

The user clarified setup capabilities
The user asked whether setup could support offline and network installation, update checking, individual package/install customization, repair, uninstall, update, downgrade, and similar operations. The assistant answered yes, but with important boundaries:

offline and network installs are both supported by a fetch abstraction,

network is an optional transport, not a dependency,

update checking is non-mutating,

applying updates/downgrades requires explicit setup invocation,

component customization is driven by install plans,

repair is explicit and not silent,

uninstall uses installed-state ownership,

rollback is journal-driven.

This clarified the operation model and preserved the setup authority rule.

The chat absorbed application-layer canon from other chats
Near the end, the user pasted large project-level application canon from another chat. This material said that architecture is closed, canon is locked, applications are orchestration shells, CLI is canonical, GUI/TUI are views, UI is data via UI IR, tools are read-only by default, setup is the only install mutation authority, launcher is the reference application, RepoX/TestX enforce metadata and validation, and BUILD-ID-0 governs versioning.

This material was visible in the chat, but it came from broader project context. In the later report package it was preserved as PROJECT-CONTEXT where relevant.

The chat ended by producing and then explaining a report package
Finally, the user retired the chat and asked for a maximum-fidelity context transfer packet. The assistant produced one. The user then asked for a downloadable shareable report package. The assistant created Markdown/YAML/report files and a ZIP. The user then asked for an in-chat reader version of the package, and the assistant rendered the package contents directly into the conversation.

The current request asks for something different: not a file index or register dump, but a human-readable narrative explanation of the conversation. This report is that narrative.

3. Main Topics We Discussed
Topic 1 — The Setup System as a Deterministic Deployment Authority
The central topic was the setup system itself. It was discussed because the user needed a robust installer/updater/verifier capable of supporting many platforms, distribution channels, legacy environments, package managers, and future update flows.

FACT: The setup system was repeatedly defined as the only component allowed to install files, modify system/installation state, own installed-file metadata, repair installs, verify artifacts, uninstall, downgrade, upgrade, and roll back. This is the most important architectural rule from the chat.

The reason this mattered is that Dominium / Domino is a long-lived deterministic system. If launchers, engines, tools, package scripts, or platform installers each had their own install logic, the result would be untestable, non-deterministic, and difficult to audit. The setup system needed to be a central authority so that installed state, ownership, rollback, and verification all remain coherent.

The conclusion was that setup should have a common core and thin platform-specific services. The core decides what to install and records state; platform code only supplies OS services such as registry entries, desktop integration, privilege handling, package manager glue, and native UI entrypoints.

What remains uncertain is the actual current implementation state in the repository after the applied Codex prompts. The design is clear, but the repo must still be inspected.

Topic 2 — Directory Structure and Repository Ownership
A large part of the chat explored directory structure. This came up because the user wanted a setup layout that was simple, intuitive, shallow, modular, extensible, and compatible with native IDEs.

Initially, assistant and user explored structures with setup/core, setup/adapters, setup/packaging, tests, and docs. The user suggested refinements like winnt, macosc, and source. Later, those ideas were superseded when the user introduced a canonical repository structure.

FACT: The final canonical repository structure has top-level products such as engine/, game/, client/, server/, launcher/, setup/, tools/, libs/, schema/, docs/, ci/, sdk/, and legacy/.

FACT: The final canonical setup layout uses setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages, setup/platform, setup/tests, and setup/ui.

This matters because the filesystem is not just organization; it enforces ownership. Setup logic belongs in setup. Engine code belongs in engine. Cross-product contracts belong in neutral libraries. Schemas belong in top-level schema/. Packaging belongs under setup packages, not hidden inside adapters.

The unresolved part is whether the actual repository now matches this canonical layout.

Topic 3 — Visual Studio, Xcode, CMake, and Toolchains
The user asked whether to use Visual Studio 2026’s C++ workload or .NET workload, and whether setup should use C/C++ or C#/.NET.

FACT: The assistant recommended C/C++ and Visual Studio Desktop Development with C++ for setup execution. The reasoning was based on the user’s stated requirements: legacy Windows, Windows 9x support, macOS/Linux portability, offline installs, stable ABI, deterministic behavior, and long-term survivability.

The assistant also advised that Visual Studio and Xcode projects should be generated by CMake, not hand-authored as authoritative build files. This fit later Codex prompts, which required CMakePresets and Visual Studio 2026 readiness.

This topic matters because the setup system needs to be buildable and maintainable over decades. IDE-specific projects can be useful views, but if they become the authoritative source, they drift from CI, command-line builds, and other platforms.

UNCERTAIN / UNVERIFIED: Exact Visual Studio 2026 behavior and toolchain details should be verified in the current environment before relying on them.

Topic 4 — Engine Purity and Contract Ownership
The user later introduced prompts that had been applied to repair engine purity. These prompts said the engine had contamination such as engine/include/dsu, engine/include/dui, engine/launcher_core_launcher, engine/setup_core_setup, engine/source, and engine/external/xxhash.

FACT: The target state was that engine should contain only engine-owned public headers under engine/include/domino, engine modules, render code, tests, and CMake. Cross-product contracts should move to libs/contracts/include/dom_contracts.

This mattered because the engine must remain reusable and independent. If setup, launcher, tools, or game-specific APIs leak into engine, then the engine can no longer be treated as a pure reusable layer.

UNCERTAIN / UNVERIFIED: The user stated the prompts were applied, but this chat did not show the final repository tree or build results.

Topic 5 — Setup Schemas and Launcher Handoff
The setup/launcher handoff was another core topic. The user repeatedly emphasized that the launcher consumes setup output and does not install itself or repair installations.

The assistant defined the setup handoff as schema-based: install plans, installed-state snapshots, verification reports, audit logs, and exit/status contracts. The installed-state manifest is the key artifact because it tells the launcher what is installed, where, with what hashes and versions, and under what ownership rules.

This matters because it prevents the launcher from guessing. It should not inspect arbitrary filesystem paths and infer that installation succeeded. It should read setup-produced state.

UNCERTAIN / UNVERIFIED: The actual schema files under schema/setup/ need to be checked.

Topic 6 — Offline, Network, Update, Repair, Downgrade, and Rollback Support
The user explicitly asked whether the setup system could support offline and network installation, update checking, package customization, repair, uninstall, update, downgrade, and related operations.

The conclusion was yes, with boundaries. The setup architecture supports these operations if they are expressed through install plans, fetch/verify/install/rollback modules, installed-state, and explicit CLI/API operations. Update checking is not the same as applying an update; checking can produce a report without mutation. Repair is explicit. Downgrade is plan-driven and should require explicit request and compatibility checks.

This topic matters because it clarifies the future feature surface without weakening setup authority.

Topic 7 — Application-Layer Canon
Near the end, the user pasted broader application-layer canon. It stated that applications are orchestration shells, content-agnostic, rule-agnostic, authority-agnostic, and must not contain gameplay logic. CLI is canonical. GUI and TUI are views over the same command graph. UI is data via UI IR. Tools are read-only by default. RepoX/TestX and BUILD-ID-0 govern metadata, validation, changelogs, and releases.

This material was not invented in this chat, but it was visible here and must be preserved as project context. It affects setup because setup is one of the application-layer products, and it affects launcher because launcher may invoke setup but cannot bypass setup guarantees.

Topic 8 — Report Packaging and Knowledge Preservation
The final part of the chat was about preserving the conversation itself. The user asked for a maximum-fidelity context transfer packet, then a downloadable report package, then an in-chat reader version, and now this human-readable narrative report.

This matters because the user is building a large project across multiple chats and wants to later combine old-chat reports into a full Project Spec Book. This chat contributes setup architecture, canonical layout history, repository enforcement context, and warnings about superseded options.

4. What We Were Trying to Achieve
The explicit goal at the beginning was to design a cross-platform setup and installer system for Dominium / Domino. The user wanted it to handle many platforms and distribution models while preserving determinism, auditability, modularity, and long-term support. The setup system had to be robust enough for modern systems, old systems, package managers, Steam/Epic-like distribution, offline installs, and future rollback/repair/update flows.

Another explicit goal was to make the directory structure simple, logical, intuitive, and consistent with industry practice. The user was dissatisfied with structures that felt too deep or counterintuitive, especially nested source directories or platform-specific sprawl. This goal changed over time when the canonical repository structure was introduced. Once that happened, directory discussion stopped being open-ended design and became alignment to fixed law.

A third explicit goal was to support native IDE workflows without letting IDEs own the project. The user wanted to use Visual Studio 2026 and Xcode for ease of programming and integration, but without sacrificing modularity or robustness. The resulting approach was CMake as authority, with Visual Studio/Xcode as generated views.

A later explicit goal was to bring existing setup code and documentation up to spec, not redesign it. This is why the generated setup hardening prompt is important. It says: inventory what exists, normalize schemas, document gaps, audit adapters/UI/packages/tests, and freeze the baseline.

An inferred goal is that the user wants to prevent future assistants from undoing settled decisions. The repeated requests for context packets, reports, registers, and in-chat readers show a concern about continuity loss, over-compression, and accidental redesign. This report is meant to support that goal.

Several goals remain unresolved because the actual repo was not inspected here. We do not know whether the applied Codex prompts fully succeeded, whether setup builds, whether schemas exist, whether libs/contracts is complete, or whether setup/launcher CLI smoke tests pass.

5. Decisions Made and Why
The decisions in this chat can be grouped into five major categories: setup authority, repository structure, build/toolchain policy, operation semantics, and application-layer rules.

Setup is the sole installation authority
FACT: The chat repeatedly established that setup is the only component allowed to install, upgrade, downgrade, repair, verify, uninstall, roll back, and own installed-file metadata.

This decision is final under the current canon. The user made it explicit in multiple prompts. It was made because installation is a high-risk mutation activity. If the launcher, engine, or tools could each modify installation state independently, then rollback, repair, verification, and audit logs would become unreliable.

This affects everything going forward. Launcher can request setup operations, but cannot perform them. Engine cannot know setup exists. Tools cannot silently mutate installs. Package scripts cannot decide install logic.

It would only be revisited if the user explicitly changed the project canon, which the chat repeatedly says is locked.

One common setup core with thin platform services
FACT: The setup architecture uses one common core shared across platforms. Platform-specific code is thin and supplies OS services only.

This decision was made to avoid duplicated business logic. It also supports deterministic behavior, because install planning, verification, state writing, and rollback are centralized. Windows, macOS, Linux, Steam, Epic, and legacy adapters should not each invent their own installation rules.

The assumption is that platform-specific differences can be expressed through platform interfaces and packaging glue without changing the setup core’s authority.

Canonical setup layout replaces earlier layouts
FACT: The final setup layout is setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages, setup/platform, setup/tests, and setup/ui.

This decision superseded earlier directory trees. It was made because the repository had undergone a larger refactor, and the user explicitly said the filesystem was fixed ground truth.

This matters because future work must not refer to old structures like setup/adapters as canonical. Those may exist as legacy or historical content, but they should not be used as the active architecture.

Setup depends only on libs/ and schema/
FACT: Setup may depend only on libs/ and schema/.

This decision was made to enforce product boundaries. Setup should not include engine internals, launcher internals, game logic, or tools internals. It should operate from schemas, manifests, packages, and shared libraries.

This affects CMake include directories, dependency graphs, and enforcement scripts.

dsk and dsu have distinct public meanings
FACT: Under canonical setup, setup/include/dsk is the public setup kernel API, and setup/include/dsu is the public setup execution/platform interface layer.

This decision clarifies ownership. Internal headers stay under setup/core/**, not in public include paths. The decision helps prevent accidental API leakage.

Packaging belongs under setup/packages
FACT: All installers and package recipes are produced from setup/packages/.

This was decided because earlier trees placed packaging under adapters, which mixed concerns. Packaging should assemble artifacts and templates, not contain install logic. Install logic remains in setup core.

Setup and launcher communicate through schemas and contracts only
FACT: Launcher consumes setup output through manifests, schemas, installed-state snapshots, reports, and exit/status contracts.

This decision prevents launcher from guessing installation state. It also keeps setup as the writer of installed-state and launcher as a reader.

Engine purity and neutral contracts are mandatory
FACT: The user pasted prompts requiring engine purity and libs/contracts/include/dom_contracts.

The decision is that cross-product contracts must not live in engine or game internals. Engine must not include setup, launcher, tools, or dom_contracts.

This protects the engine’s long-term reusability.

CMake is the build authority
FACT: The assistant recommended and later prompts reinforced that CMake should be authoritative; Visual Studio and Xcode projects should be generated, not hand-authored as the source of truth.

This decision was made because generated projects keep IDE workflows aligned with CI and command-line builds.

C/C++ is preferred for setup execution, not .NET
FACT with some assistant-originated rationale: The assistant recommended Visual Studio Desktop Development with C++ and C/C++ for setup execution. The user did not reject this and continued from it.

This decision was based on legacy platform support, stable ABI, deterministic behavior, offline installs, and avoiding runtime dependencies. It is strong, but because the user did not explicitly restate it as canon in the same way as setup authority, it should be treated as accepted guidance rather than a project-wide immutable law.

Offline and network install are both supported
FACT / INFERENCE: The assistant answered that setup can support both offline and network installation. The user did not object.

The reasoning is that fetch can treat network as one transport among others. Offline install uses local bundles or cache. Network install fetches content-addressed payloads and then verifies them.

Implementation still needs verification.

Update checking is non-mutating
FACT / INFERENCE: The assistant clarified that update checking compares current installed state with candidate plans and produces a report. It should not mutate installed files unless an explicit update operation is invoked.

This preserves auditability and avoids hidden behavior.

Repair is explicit; rollback is first-class
FACT: Repair is explicit and never silent. Rollback is journaled and first-class.

These decisions follow directly from deterministic setup principles. They prevent the system from hiding failures or altering state behind the user’s back.

Application-layer canon applies to setup and launcher
FACT / PROJECT-CONTEXT: The user pasted application-layer canon. It says CLI is canonical, GUI/TUI are views, UI is data, tools are read-only by default, and RepoX/TestX enforce metadata and validation.

This affects future application work, but some exact implementation paths remain unverified.

6. Ideas Considered but Rejected, Superseded, or Deprioritised
Earlier directory structures using setup/adapters/ were superseded. They were considered because they naturally grouped platform-specific setup code, but the canonical layout replaced them with setup/platform/ for OS services and setup/ui/ for frontends. This rejection is final unless the repository canon changes.

The old setup/packaging/ or adapter-local packaging model was superseded by setup/packages/. Packaging under adapters was considered because installers are platform-specific, but it mixed packaging with platform services. The canonical model keeps packaging recipes under setup’s package area and prevents packaging scripts from owning install logic.

Generic nested source/ directories under setup were rejected. The user explicitly found them counterintuitive, and the later canonical setup layout removed them. This rejection is final for setup under the current canon.

Using .NET for authoritative setup execution was rejected or at least strongly deprioritized. It was considered because Visual Studio offers .NET Desktop Development, but it conflicts with legacy/offline/stable-ABI goals. It could still be reconsidered for non-authoritative developer tools or optional management utilities, but not for setup core execution.

Hand-authored Visual Studio or Xcode project files as authoritative build files were rejected. They were considered because the user wanted native IDE workflows, but the accepted model is that CMake generates IDE projects. Generated IDE projects are allowed; committed project files as build truth are not.

Launcher-side install/update/repair logic was rejected. It would be tempting to make launcher manage updates because launchers often do that, but in this architecture setup owns install mutation. Launcher can present information and invoke setup.

Engine-side setup awareness was rejected. The engine must remain pure and reusable.

Manual changelog editing was rejected by project-level application/release canon. RepoX is the source of truth.

Tools mutating by default were rejected. Tools are read-only unless explicitly designed and gated for mutation.

Several assistant proposals were superseded by later canon rather than formally rejected. Examples include a top-level components/ layer and a shared/foundation structure. They were reasonable during brainstorming, but the user later locked the actual top-level repository layout and libs//schema/ ownership model.

7. Important Reasoning and Rationale
The visible reasoning throughout the chat is dominated by four concerns: authority, determinism, long-term maintainability, and mechanical enforcement.

Authority matters because installation is not just copying files. It creates ownership, mutates system state, writes installed-state, registers OS integrations, and determines what rollback means. If that authority is split between launcher, engine, platform installers, package scripts, and tools, then no single component can produce reliable audit logs or repair state. This is why setup became the sole authority.

Determinism matters because Dominium / Domino is a long-lived deterministic simulation project. Even though setup is not simulation logic, it still participates in reproducibility. Installing the same manifest and payloads should produce the same installed layout and state. This is why manifests, schemas, hashes, state snapshots, audit logs, deterministic output, and explicit transaction phases matter.

Long-term maintainability matters because the user wants support across modern and legacy systems. The discussion repeatedly accounted for Windows NT, Windows 9x, macOS X, classic macOS, Linux, package managers, Steam/Epic, offline installs, and possibly web/consoles/retro. This drove the C/C++ and CMake choices and the rejection of runtime-dependent authoritative setup logic.

Mechanical enforcement matters because conventions are not enough. The user’s later prompts emphasize CMake include boundaries, verification scripts, tree sanity checks, CI gates, RepoX/TestX, and schema validation. The rationale is that if the architecture is only documented but not enforced, it will drift.

The major tradeoff was between ease of native IDE use and long-term build portability. The compromise was to use native IDEs as generated views through CMake, not as the source of truth.

Another tradeoff was between broad future support and current implementation scope. The architecture allows legacy platforms, storefronts, and offline/online acquisition, but many implementation details remain unverified. The chat preserved those as goals without pretending they are already implemented.

8. Plans, Future Work, and Next Steps
The immediate next step is not more design. It is verification.

First, the actual repository state must be inspected. This means checking the current setup/ tree, schema/ tree, libs/contracts, root CMake, setup CMake, CMake presets, and enforcement scripts. The user stated two Codex prompts were applied, but the chat did not show final build results.

Second, run the build and smoke tests. The expected checks are CMake configure, CMake build, CTest, setup --help, and launcher --help. The exact command names depend on the actual presets, but the earlier prompts referenced Visual Studio 2026 x64 debug presets.

Third, determine whether the generated Setup Final Spec Alignment, Gap Closure, and Hardening Pass prompt has already been executed. Evidence would include documents like docs/SETUP_GAPS.md, docs/SETUP_KERNEL.md, docs/SETUP_UI.md, docs/SETUP_PACKAGING.md, docs/SETUP_ARCHITECTURE.md, docs/SETUP_CONTRACTS.md, docs/SETUP_FAILURE_MODES.md, and docs/SETUP_BASELINE_FROZEN.md. If those do not exist, execute the prompt. If they do exist, audit them.

Fourth, normalize schemas. Setup I/O should be backed by schemas under schema/setup/, including install plans, installed-state snapshots, verification reports, and audit logs. If current setup code emits ad-hoc JSON or TLV, it should be mapped to schema fields.

Fifth, audit public setup APIs. setup/include/dsk and setup/include/dsu need to be minimal, stable, and intentional. Internal headers should not leak into public include paths.

Sixth, audit platform adapters, UI, packages, and tests. Platform code should provide OS services only. UI should be a thin frontend. Package scripts should be reproducible and declarative. Tests should cover partial installs, interrupted installs, corrupted payloads, idempotency, uninstall ownership, and rollback.

Seventh, only after the above is complete should higher-level planning restart. The user explicitly wanted setup code/docs brought up to spec before regenerating further plans.

What could go wrong is straightforward: acting on stale directory assumptions, assuming the repo matches the canonical structure without checking, treating a stub as a finished implementation, or turning assistant proposals into canon.

9. Constraints, Preferences, and Non-Negotiables
Explicit constraints
The hardest constraints are architectural:

Setup is the sole install mutation authority.

Launcher may invoke setup but must not duplicate setup logic.

Engine must not know setup exists.

Setup depends only on libs/ and schema/.

Setup public APIs live only under setup/include/dsk and setup/include/dsu.

Internal setup headers stay under setup/core/**.

Packaging belongs under setup/packages.

Launcher/setup handoff is schema/report/contract based.

Engine public headers are only engine ABI.

Cross-product contracts belong in libs/contracts.

CMake and scripts must enforce boundaries.

The setup behavior constraints are also strict:

No hidden mutation.

No silent repair.

Rollback is first-class.

Install transactions are staged, verified, committed, and rollback-capable.

Installed-state is setup-written and launcher-read-only.

Offline installs must be possible.

Network must be optional transport.

Package scripts must not own install logic.

The application-layer constraints from project context are:

Applications are content-agnostic.

CLI is canonical.

GUI/TUI are views over the same command graph.

UI is data, not logic.

Tools are read-only by default.

RepoX/TestX govern validation, changelogs, and metadata.

BUILD-ID-0 governs build identity and release numbering.

The user also has communication preferences: high accuracy, explicit uncertainty labels, minimal unsupported inference, engineering precision, no marketing tone, and complete preservation of decisions and artifacts.

Inferred preferences
It is reasonable to infer that the user values durable project memory, highly structured but human-readable reports, direct Codex prompts, and careful distinction between accepted decisions and assistant brainstorming. This is inferred from repeated requests for context packets, report packages, registers, and handoff material.

Things future assistants should avoid
They should avoid redesigning locked architecture, reviving old directory layouts, using .NET for setup execution, letting launcher install files, letting engine include setup/launcher/tool headers, ignoring verification items, or inventing current repo state.

10. Files, Artifacts, Outputs, and Prompts Mentioned or Created
This chat involved many artifacts. The most important are prompts and reports rather than source files.

The first major artifact was the initial setup master prompt. It established the setup system’s purpose, legal/IP limits, core philosophy, manifest model, transaction model, platform adapters, CLI, testing, and documentation expectations. It should be preserved as historical foundation, though later canonical paths supersede its directory assumptions.

The second major artifact was Plan S, the plan-of-plans. It organized setup work into subplans from governance through documentation. It remains useful conceptually but must be interpreted through the later canonical repository layout.

The user’s old setup directory tree is an important artifact because it shows the actual problems being solved: outdated files, redundant entrypoints, platform/package mixing, committed IDE artifacts, mixed DSK/DSU headers, and an empty schemas area. It is not current proof, but it explains why the later refactor and hardening prompts were necessary.

The canonical repo/setup prompt is one of the highest-value artifacts. It locked the current filesystem model and dependency rules.

The two applied Codex prompts are also critical. One handled broad VS2026/CMake/build/refactor work; the other handled engine purity and contract ownership. The chat treats them as applied, but their results must be verified.

The generated Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass prompt is the most actionable artifact for future work. It should be executed or audited. It is designed to finish setup code and docs without redesigning them.

The application-layer canon prompts are important project-context artifacts. They should inform application work but should not be confused with setup-specific decisions created entirely in this chat.

Finally, the chat generated a context transfer packet, downloadable report package, and in-chat reader. Those are preservation artifacts. They should be useful for future aggregation into a Project Spec Book, but this human-readable report is meant to explain the substance more naturally.

11. Open Questions and Unresolved Issues
The biggest unresolved issue is the actual repository state. The user said two Codex prompts were applied, but this chat did not inspect or display the final tree or build logs. That means many implementation claims remain unverified. The next assistant should not assume setup/, schema/, or libs/contracts are correct until they are inspected.

Another unresolved issue is whether the setup hardening prompt has already been executed. If documents like docs/SETUP_GAPS.md and docs/SETUP_BASELINE_FROZEN.md exist, then the next task is audit. If they do not, the next task is execution.

The schema state is unresolved. The chat defined install plan, installed-state, verification report, and audit log schemas conceptually, but it did not prove that these exist in schema/setup/.

The setup CLI state is unresolved. The system is supposed to support commands like help, version, status, install, verify, repair, uninstall, upgrade, downgrade, and rollback, but the current implementation status is unknown.

The build state is unresolved. We do not know whether CMake configure, build, and CTest pass in the current repo.

The exact UI IR path and application command-spine implementation are unresolved. The project canon requires CLI canonical behavior and UI-as-data, but this chat’s suggestions about libs/appcmd or schema/ui_ir are proposals unless confirmed elsewhere.

The priority of legacy platform support is also unresolved. The architecture preserves Windows 9x, classic macOS, and other legacy paths, but the chat does not establish how much of that should be implemented immediately.

12. Risks, Failure Modes, and Things Future Chats Might Get Wrong
A future assistant might accidentally follow obsolete directory layouts. This is likely because the chat contains several earlier trees. The mitigation is simple: use only the canonical repo/setup layout unless discussing history.

A future assistant might treat assistant proposals as user decisions. For example, libs/appcmd was proposed as a possible command-spine location, but the exact path was not locked in this chat. The mitigation is to preserve labels: FACT, INFERENCE, UNCERTAIN, and PROJECT-CONTEXT.

A future assistant might assume the repo is already correct because the user said prompts were applied. That would be unsafe. Applied prompts are important, but their results must be verified through tree inspection, CMake, tests, and smoke commands.

A future assistant might let launcher duplicate setup logic. This is one of the most serious mistakes because it would violate setup authority and break auditability.

A future assistant might let engine purity regress. The old tree had concrete engine contamination, so this must be enforced mechanically.

A future assistant might over-merge this chat with other old-chat reports. Because some project-level canon was pasted from other chats, aggregation must preserve provenance. It should not pretend all project canon was developed in this setup chat.

A future assistant might over-focus on generated package files instead of the substantive design. The files are useful, but the important content is setup authority, canonical structure, schema handoff, build enforcement, and verification.

13. What This Chat Contributes to the Larger Project
This chat contributes a detailed record of the setup system’s architectural role and its transition into the canonical repository. It should feed into future Project Spec Book chapters on:

Setup architecture,

Installation and rollback authority,

Repository structure,

Product boundaries,

Build and CMake enforcement,

Schema contracts,

Application-layer setup/launcher handoff,

Packaging and reproducibility,

Legacy platform support,

Context transfer/reporting process.

The most important formal requirements candidates are:

setup is sole installation authority,

launcher consumes setup output and invokes setup only,

engine is unaware of setup,

setup depends only on libs/ and schema/,

setup writes installed-state,

repair/update/downgrade are explicit,

rollback is journaled,

packaging recipes do not own install logic,

schemas are the canonical setup data format,

CMake is the build authority.

Background context that should not become formal requirements includes the superseded early directory trees, the old setup tree except as migration evidence, and assistant-only proposals that were never accepted as canon.

Likely overlaps with other chats include application-layer canon, RepoX/TestX, BUILD-ID-0, UI IR, engine purity, and project-wide architecture rules.

Potential conflicts may arise if other chats propose different directory layouts, different setup/launcher authority boundaries, or different command/UI architecture. The future aggregator must preserve provenance and resolve conflicts through the latest user-provided canon.

14. What I Should Remember
The main subject of this chat was Dominium Setup, not launcher UI, engine simulation, or game rules.

The most important rule is that setup is the sole authority for installation and installed-state mutation.

The launcher may invoke setup and read setup outputs, but it must not repair, install, update, or infer state itself.

The engine must remain pure and unaware of setup.

The final canonical setup layout is under setup/core, setup/include, setup/packages, setup/platform, setup/tests, and setup/ui.

Earlier setup/adapters, adapter-local packaging, and generic source directories are historical or superseded.

CMake is the authoritative build system; Visual Studio/Xcode are generated views, not source-of-truth project systems.

C/C++ is the right setup execution path because of legacy/offline/stable ABI requirements.

The two applied Codex prompts are important but their results must be verified in the repo.

The generated Setup Final Spec Alignment prompt is the key next-action artifact.

Setup supports offline and network installs, update checking, component customization, repair, uninstall, update, downgrade, and rollback, but actual implementation must be checked.

Project-level application canon says CLI is canonical, UI is data, tools are read-only, and RepoX/TestX/BUILD-ID-0 govern metadata and validation.

The biggest unresolved issue is actual repo state.

The biggest future mistake would be treating old brainstorms as canon or assuming implementation success without verification.

15. Best Questions I Can Ask Next in This Chat
“Give me the exact commands and file checks to verify the current repo against this chat.”

“Explain the Setup Final Spec Alignment prompt in plain language.”

“Which setup directory structures are superseded, and why?”

“Summarize the setup authority model for the future Project Spec Book.”

“What are the highest-risk violations of setup/launcher/engine boundaries?”

“Turn the unresolved setup verification items into a Codex prompt.”

“Which decisions in this chat are hard canon, and which are assistant suggestions?”

“Explain how offline install, online install, update check, repair, downgrade, and rollback should work.”

“What parts of this chat overlap with application-layer canon from other chats?”

“What should a future aggregator preserve from this chat and not merge prematurely?”

16. Final Plain-English Summary
This chat was about creating, refining, and preserving the architecture and implementation plan for the Dominium / Domino Setup system. Setup is the installer/updater/verifier/rollback product. It is not the launcher, not the engine, not game logic, and not a general tool. Its job is to install and maintain Dominium software safely, deterministically, and audibly.

The conversation began with a broad setup-system master prompt. The user wanted a setup system that could support Windows, macOS, Linux, package managers, Steam/Epic-style distribution, offline installs, network installs, repair, uninstall, update, downgrade, rollback, and long-term legacy support. The assistant responded by designing a setup core with manifest parsing, dependency resolution, plan construction, transaction execution, filesystem policy, installed-state writing, logging, and platform interfaces.

The user then asked for Plan S, a plan-of-plans for the setup system. That plan organized the work into phases: governance, core architecture, manifest schema, installed-state schema, transaction engine, filesystem/path policy, audit logging, CLI, platform adapters, Steam integration, distribution pipeline, compatibility, testing, and documentation.

The chat then moved into concrete directory structures and native IDE workflows. Early trees used setup/core, setup/adapters, setup/packaging, tests, and docs. The user wanted simple, shallow, logical structures and support for Visual Studio 2026, Watcom/OpenWatcom for Windows 9x, Xcode for macOS, and Linux package managers. The assistant recommended C/C++ for setup execution, CMake as the build authority, and generated Visual Studio/Xcode projects rather than hand-authored IDE projects. It also recommended Visual Studio’s C++ desktop workload, not .NET, for the authoritative setup path.

A major shift happened when the user pasted an existing setup tree showing drift: packaging inside adapters, duplicate CLI files, committed VS/Xcode project files, mixed DSK/DSU headers, and an empty schema area. The assistant identified these as structural problems.

Then the user introduced a new canonical repository structure. This superseded earlier directory designs. The final top-level products are engine, game, client, server, launcher, setup, tools, libs, schema, sdk, docs, ci, and legacy. The canonical setup layout became setup/core/{fetch,verify,install,rollback}, setup/include/{dsk,dsu}, setup/packages/{client,server,tools,scripts}, setup/platform/{win/{win9x,winnt},linux,bsd,mac/{classic,osx}}, setup/tests, setup/ui, and setup/CMakeLists.txt.

The most important architectural decision is that setup is the sole authority for installation and installed-state mutation. Launcher may invoke setup, but it cannot reimplement setup logic. Engine must not know setup exists. Setup depends only on libs and schema. Setup communicates with launcher only through schemas, manifests, installed-state snapshots, reports, and exit/status contracts.

The user later pasted two applied Codex prompts. One covered repository refactor, Visual Studio 2026/CMake readiness, build targets, smoke tests, and boundary enforcement. The other covered final engine purity and contract ownership, including moving cross-product contracts to libs/contracts/include/dom_contracts. This changed the chat from greenfield design to implementation alignment: existing implementation should now be treated as authoritative unless it violates canon.

The assistant generated a key future-work prompt titled “Dominium Setup: Final Spec Alignment, Gap Closure, and Hardening Pass.” This prompt tells Codex to inventory setup, document gaps, normalize schemas, harden public APIs, audit platform adapters, audit UI frontends, harden packaging, align tests, and create baseline documentation. It is probably the most important actionable artifact from the chat.

The user asked whether setup could support offline and network installs, update checking, customization, repair, uninstall, update, downgrade, and rollback. The answer was yes, with clear boundaries: network is optional transport; update check is non-mutating; repair is explicit; uninstall is ownership-based; rollback is journaled.

Near the end, the user pasted broader application-layer canon from other chats. That canon says applications are content-agnostic orchestration shells, CLI is canonical, GUI/TUI are views, UI is data via UI IR, tools are read-only by default, and RepoX/TestX/BUILD-ID-0 govern metadata, validation, changelogs, and releases. This is project context visible in the chat, not something invented by the assistant.

The final part of the chat focused on preservation. A maximum-fidelity context transfer packet was produced, then a downloadable report package, then an in-chat reader. This current report translates the substance of the chat into a human-readable narrative.

What remains unresolved is the actual state of the repository. The two Codex prompts were said to be applied, but this chat did not show the final tree, CMake output, test results, setup CLI output, schema files, or libs/contracts contents. Before implementing anything, the next assistant should verify the repo tree, schemas, contracts, CMake build, CTest, setup --help, launcher --help, and enforcement scripts.

The key memory is simple: do not redesign setup; verify and harden it. Preserve setup authority, canonical paths, schema-only handoff, engine purity, CMake enforcement, explicit repair/update semantics, and the generated setup hardening prompt.

Reader Status
Chat title: Dominium Setup Architecture and Handoff

Report type: human-readable explanatory report

Main value of this chat: It records the evolution from setup-system architecture brainstorming to canonical repository alignment, setup authority rules, schema handoff, build enforcement, and future setup-hardening work.

Most important decision: Setup is the sole authority for installation, upgrade, downgrade, verification, repair, uninstall, rollback, installed-state ownership, and packaging layout enforcement.

Most important unresolved issue: The actual repository state after the two applied Codex prompts remains unverified in this chat.

Most important next action: Verify the current repo tree/build/schema/contract state, then execute or audit the generated Setup Final Spec Alignment prompt.

Safe to use for later aggregation: yes, with caveats

Main caveats: Some material is project-context pasted from other chats; early directory structures are superseded; actual implementation/build state is unverified; assistant proposals must not be treated as user decisions unless accepted or canonized.

Branched from Plan S: The Setup


okay, im think maybe we can make this so portable modular extensible moddable customizable future proof backwards compatible robust reliable and etc such that we can make a github repo for a universal setup/installer/unistaller/repair/etc that we can use across all our projects (dominium, eureka, aide, etc) and also across all machines platforms systems vintages and etc, basically the ultimate OEM+ cross platform native system

Thought for 3m 29s
GPT-5.5 Pro — 2026-06-28 00:00:00

Yes — this is a strong idea, but it needs one important correction:

Do not turn Dominium’s setup/ product itself into the universal system.
Instead, create a separate universal setup framework that Dominium, Eureka, AIDE, and future projects can all use.

Think of it as:

universal-setup/        ← reusable installer framework
dominium/setup/         ← Dominium-specific binding
eureka/setup/           ← Eureka-specific binding
aide/setup/             ← AIDE-specific binding
Dominium setup remains the authority for Dominium installs, but it is powered by a shared setup kernel.

Recommended Direction
Create a universal OEM+ setup framework
The goal should be:

A project-agnostic, deterministic, modular setup framework for installing, verifying, repairing, updating, downgrading, uninstalling, packaging, and auditing software across many projects, platforms, package managers, stores, vintages, and deployment environments.

It should not be “an installer app.”
It should be a setup operating layer.

The reusable repo should provide:

setup kernel

manifest/schema system

transaction engine

installed-state database

payload fetch/cache layer

verification layer

rollback/journal system

platform service adapters

package recipe tooling

CLI frontend

optional GUI/TUI frontend bindings

test/fault-injection harness

reproducible build helpers

Each project then supplies:

product identity

manifests

payloads

branding/text/assets

platform policy

package recipes

update channels

compatibility rules

optional GUI skin/layout

The Key Architectural Split
The universal repo should not know what Dominium, Eureka, or AIDE are.

It should know about products, components, payloads, install plans, state snapshots, transactions, and platform services.

So the split should be:

universal setup framework
├─ generic install logic
├─ generic transaction engine
├─ generic schema validation
├─ generic platform service interfaces
└─ generic CLI / API

project setup package
├─ product metadata
├─ component manifests
├─ payload layout
├─ compatibility rules
├─ user-facing strings
├─ branding
└─ package outputs
That gives you portability without turning the core into a project-specific mess.

Proposed Repository Concept
A good top-level shape would be:

universal-setup
├─ core
│  ├─ fetch
│  ├─ verify
│  ├─ install
│  ├─ rollback
│  ├─ state
│  └─ plan
├─ include
│  ├─ usk
│  └─ usu
├─ schema
│  ├─ install_plan
│  ├─ installed_state
│  ├─ verify_report
│  ├─ audit_log
│  └─ package_manifest
├─ platform
│  ├─ win
│  │  ├─ win9x
│  │  └─ winnt
│  ├─ mac
│  │  ├─ classic
│  │  └─ osx
│  ├─ linux
│  ├─ bsd
│  ├─ unix
│  ├─ steam
│  ├─ epic
│  └─ portable
├─ ui
│  ├─ cli
│  ├─ tui
│  └─ gui
├─ packages
│  ├─ windows
│  ├─ mac
│  ├─ linux
│  ├─ stores
│  └─ portable
├─ tools
│  ├─ manifest_check
│  ├─ package_build
│  ├─ state_inspect
│  ├─ repro_check
│  └─ fault_inject
├─ tests
│  ├─ unit
│  ├─ integration
│  ├─ fixtures
│  └─ golden
├─ docs
├─ examples
│  ├─ minimal_product
│  ├─ offline_bundle
│  ├─ native_package
│  └─ portable_app
└─ CMakeLists.txt
Names are flexible, but the structure should preserve these roles.

Important Naming Point
Because Dominium already uses dsk and dsu, the universal repo should probably use a neutral prefix.

Possible names:

Prefix	Meaning	Notes
usk	Universal Setup Kernel	Good for core logic
usu	Universal Setup Utility / execution layer	Good for runtime/platform
usp	Universal Setup Package	Good for package manifests
uxs	Universal Cross Setup	More distinctive
oemx	OEM+ setup layer	Branded but less neutral
A clean pair would be:

include/usk/   ← universal setup kernel API
include/usu/   ← universal setup execution/platform API
Then Dominium can wrap it:

setup/include/dsk/   ← Dominium setup kernel-facing API
setup/include/dsu/   ← Dominium setup execution/platform API
Dominium-specific setup can either directly use usk/usu, or expose dsk/dsu as thin project bindings.

How This Fits Dominium Without Breaking Canon
Dominium canon currently says:

setup/ is the sole authority for Dominium installation.
setup/ depends only on libs/ and schema/.
launcher cannot reimplement setup logic.
engine cannot know setup exists.
A universal framework does not violate that if you treat it as a dependency under libs/, a submodule, or a vendored external.

For Dominium:

libs/universal_setup/       ← reusable setup framework
setup/                      ← Dominium-specific setup product
schema/setup/               ← Dominium setup schemas/bindings
Or, if kept as a separate GitHub repo:

third_party/universal_setup/
setup/
The important rule:

Dominium setup/ remains the product authority.
The universal framework is only the reusable mechanism.

So the launcher still invokes Dominium setup, not the universal framework directly.

What Should Be Universal
The universal repo should own:

1. Manifest model
Generic concepts:

product id

product version

channel

build id

component list

dependencies

conflicts

payload refs

install roots

platform predicates

user-data preservation rules

declarative post-install actions

uninstall rules

2. Transaction engine
Generic operation model:

preflight
fetch
stage
verify
install
commit
state write
rollback
audit export
3. Installed-state format
Generic state should record:

product instance id

installed components

files owned by installer

hashes

sizes

install roots

registrations

rollback anchors

verification status

package manager ownership notes

4. Platform service interfaces
Generic platform operations:

create shortcut

register file type

write app entry

check privileges

request elevation

set permissions

integrate with package manager

remove registration

discover standard paths

5. Fetch/cache layer
Generic sources:

local directory

offline bundle

mounted media

content-addressed cache

HTTP/HTTPS source

package manager source

store depot/source

Network must remain optional.

6. Verification
Generic verification:

hash tree

manifest validation

installed-state validation

payload integrity

rollback journal validity

reproducible package layout check

7. Audit and forensics
Generic reports:

what was installed

what was touched

what changed

why verification failed

what rollback did

what remains after uninstall

What Should Stay Project-Specific
Dominium, Eureka, AIDE, etc. should own:

product name

product id

branding

icons

legal text

license text

component definitions

payloads

update channels

compatibility rules

default install selections

project-specific package recipes

user-facing strings

launcher handoff policy

project-specific schemas or schema extensions

The universal framework should not know:

what Dominium gameplay is

what Eureka does

what AIDE does

what launcher profiles mean

what game packs mean semantically

what engine versions are compatible beyond declared metadata

Best Architecture Pattern
Use a kernel + policy + frontend model.

Universal Setup Kernel
        ↓
Project Policy Binding
        ↓
Project Setup Application
        ↓
Platform Frontend / Package Format
In practice:

usk_core
  ↓
dominium_setup_policy
  ↓
dominium_setup_cli
  ↓
winnt/msi/deb/rpm/pkg/steam/etc.
This gives you reuse without losing authority boundaries.

Compatibility Tiers
Trying to support “all machines, platforms, systems, vintages” is possible only if you define tiers.

Do not pretend every feature works everywhere.

Use capability tiers:

Tier 0 — Portable core
C89-compatible core subset

local install

local manifest

local payloads

installed-state write

verify

uninstall

basic rollback

Target:

old Windows

old Unix/Linux

classic systems

embedded environments

Tier 1 — Native desktop
Windows NT

macOS X

Linux/BSD

shortcuts

app entries

file associations

package manager cooperation

Tier 2 — Modern distribution
online fetch

channels

update check

signed manifests

binary delta support if added later

reproducible packages

Tier 3 — Storefront integration
Steam

Epic

itch-like/web distribution

console-style packaging where permitted

Tier 4 — Legacy/retro special cases
Windows 9x

classic Mac OS

old Linux

optical media

offline-only bundles

constrained filesystems

This avoids overpromising.

The Crucial Rule: Capability Discovery
The universal setup system should not assume features exist.

Each platform adapter should expose capabilities:

can_create_shortcuts
can_register_file_types
can_elevate
can_write_system_scope
can_use_symlinks
can_verify_signatures
can_fetch_network
can_atomic_rename
can_package_manager_own_files
can_rollback_registrations
Then the setup core builds a plan based on declared capabilities.

That is how you support both modern Windows and old Windows 9x without branching business logic everywhere.

Moddable and Customizable Without Becoming Unsafe
A universal setup system can be moddable/customizable, but not by allowing arbitrary installer scripts.

Use declarative extension points:

Good:

component definitions
install root roles
file groups
optional features
platform predicates
declarative actions
localization packs
UI layout IR
package recipes
policy modules
Dangerous:

arbitrary shell scripts
arbitrary postinstall code
installer plugins with full system access
runtime-downloaded executable hooks
undocumented side effects
If extensibility is needed, use constrained verbs:

create_shortcut
register_file_type
install_service
write_config_template
create_directory
preserve_user_data
remove_owned_file
verify_hash
Not:

run_this_script_as_admin
For hostile environments and long-term support, declarative beats scriptable.

Relationship to GitHub Repo Strategy
You could make this a standalone GitHub repository.

A good strategy:

github.com/your-org/universal-setup
github.com/your-org/dominium
github.com/your-org/eureka
github.com/your-org/aide
Each project can consume universal setup as:

Git submodule,

vendored snapshot,

release tarball,

package dependency,

internal mirror.

For maximum long-term reliability, I would support both:

submodule/source integration for active development,

vendored release snapshot for stable products.

That way Dominium can pin a known-good setup framework version.

Versioning Model
The universal setup framework needs its own versions.

Separate these:

Universal setup framework version
Manifest schema version
Installed-state schema version
Platform adapter ABI version
Project setup policy version
Product version
Build/release metadata version
Do not mix them.

Example:

universal-setup 0.3.0
install_plan_schema 2
installed_state_schema 1
platform_iface_abi 4
dominium_setup_policy 7
dominium 1.2.0+beta.10471
This allows old installers to read old states, new installers to migrate them, and future projects to evolve independently.

Minimal Viable Universal Setup Repo
Do not try to build the ultimate system first.

Build the smallest reusable spine:

MVP 1 — Portable local install
Must support:

parse manifest

verify payload hashes

copy/stage files

write installed-state

verify installed-state

uninstall owned files

write audit log

run through CLI

No registry.
No network.
No GUI.
No package manager.
No Steam.

This proves the core.

MVP 2 — Repair and rollback
Add:

transaction journal

rollback on failure

repair missing/corrupt owned files

idempotent rerun

fault-injection tests

This proves reliability.

MVP 3 — Platform services
Add:

Windows NT adapter

Linux portable adapter

macOS adapter

platform capability discovery

shortcut/file-association declarations

This proves portability.

MVP 4 — Packaging
Add:

portable tar/zip bundle

MSI/WiX or equivalent packaging path

.pkg/.dmg recipes

.deb/.rpm recipes

reproducible package validation

This proves distribution.

MVP 5 — Network/update/channel
Add:

content-addressed cache

remote manifest source

update check

explicit update/downgrade

channel metadata

This proves live lifecycle.

MVP 6 — Storefronts and legacy
Add:

Steam/Epic lifecycle bridges

Win9x/OpenWatcom subset

classic Mac subset

old Linux constraints

offline optical/removable media bundles

This proves long-range support.

How Dominium Should Use It
Dominium should not wait for the whole universal framework to exist.

Instead:

Keep Dominium setup canonical.

Extract reusable pieces gradually.

Move only proven generic pieces into the universal repo.

Keep Dominium-specific policy inside Dominium.

Pin the universal setup framework version.

A safe migration path:

Phase A: Finish Dominium setup baseline.
Phase B: Identify generic setup kernel pieces.
Phase C: Extract universal setup repo.
Phase D: Rebind Dominium setup to universal setup.
Phase E: Add Eureka/AIDE as second and third consumers.
Phase F: Stabilize public APIs after multiple consumers exist.
Do not extract too early before Dominium’s setup semantics are clear.

What Not To Do
Do not create:

one giant installer app
Do not create:

a universal updater daemon
Do not create:

a package manager that fights OS package managers
Do not create:

a plugin system that runs arbitrary install scripts
Do not create:

a GUI-first installer framework
Do not create:

a “magic” installer that guesses what to do
The correct product is a deterministic setup kernel plus thin frontends and project policies.

Recommended Name and Identity
A good working title:

Universal Setup Kernel
Short name:

USK
Companion execution/platform layer:

Universal Setup Utility
USU
So:

usk_core
usu_cli
usu_platform_winnt
usu_platform_linux
usu_platform_macos
For branding, “OEM+” can be a project tagline, but I would not make the internal API name oem unless you want that identity permanently.

Possible repo names:

universal-setup
portable-setup
setup-kernel
usk
crosssetup
My recommendation:

universal-setup
with internal prefixes:

usk_*
usu_*
How This Affects the Current Dominium Plan
This idea should modify the plan, but not derail it.

Current Dominium setup plan should become:

Dominium setup is the first product implementation
of a reusable universal setup framework.
But do not rewrite everything immediately.

The correct next plan adjustment is:

New workstream: Universal Setup Extraction
Purpose:

identify project-agnostic setup code,

separate kernel from Dominium policy,

define reusable APIs/schemas,

make Dominium the first consumer,

later add Eureka and AIDE.

Immediate rule:

Finish and freeze Dominium setup baseline first.
Then extract.

Otherwise you risk designing a universal abstraction before you have one complete real implementation.

Proposed Future Structure Across Repos
universal-setup/
├─ core/
├─ include/
├─ schema/
├─ platform/
├─ ui/
├─ packages/
├─ tools/
├─ tests/
├─ docs/
└─ examples/

dominium/
├─ setup/
│  ├─ policy/
│  ├─ manifests/
│  ├─ packages/
│  └─ ui/
├─ libs/
│  └─ universal_setup/  ← pinned vendored/submodule
└─ schema/
   └─ dominium_setup/

eureka/
├─ setup/
└─ libs/
   └─ universal_setup/

aide/
├─ setup/
└─ libs/
   └─ universal_setup/
Dominium-specific setup remains Dominium-owned.
The universal repo provides the reusable kernel and tools.

Core Design Principle
The universal setup framework should be:

product-agnostic
platform-aware
policy-driven
schema-backed
transactional
auditable
offline-first
network-capable
capability-discovered
backwards-compatible
It should not be:

product-specific
GUI-first
script-first
daemon-based
storefront-specific
OS-package-manager-hostile
My Recommendation
Yes, pursue this.

But do it in this order:

Finish Dominium setup baseline.

Document what is generic vs Dominium-specific.

Extract a universal setup kernel repo.

Use Dominium as first real consumer.

Use Eureka and AIDE as second/third consumers.

Only then stabilize the public API.

That gives you the universal OEM+ system without abstracting too early.

The idea is strong because your setup requirements are already broader than one project. But the safe way to make it real is to let one concrete setup implementation harden first, then extract the universal core from proven code.


