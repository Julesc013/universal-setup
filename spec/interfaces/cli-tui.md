---
type: "Engineering Specification"
title: "Human CLI, machine mode and accessible TUI"
description: "Provide complete predictable terminal operation without requiring raw JSON for ordinary tasks."
tags: ["universal-setup","interfaces"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CLI","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PRESENT","USK-S-WIRE"]}
---

# Human CLI, machine mode and accessible TUI

## Invocation contract
Explicit machine mode overrides automatic GUI/TUI selection. Explicit frontend requests choose that frontend or return a typed unavailable result. A domain command implies CLI unless an explicit supported projection is requested. Redirection never opens a GUI or full-screen interface. Bare interactive invocation may offer a TUI; limited terminals use a linear landing/help surface. Internal worker/broker modes are never inferred from missing display alone.

## Machine mode
One JSON result on stdout; diagnostics on stderr; stable nonlocalized IDs; no prompts, color, pagination or window creation. NDJSON events require an explicit format. Exit codes map transport/general failure categories while the typed result preserves operation outcome, effects and reboot semantics. Noninteractive missing choices refuse, not guess.

## Human and TUI
Human CLI renders concise tables, effects/diffs, blockers, exact operation IDs and safe next steps. Full-screen and linear TUI share a reducer/controller and semantic actions. Linear mode is complete for screen readers, remote sessions, redirected transcripts and recovery. `NO_COLOR` removes color without automatically forbidding full-screen cursor addressing.

Terminal rendering must handle resize, minimum size, Unicode graphemes/cell widths, keyboard focus, input cancellation, suspension/termination and restoration of terminal state. No ordinary workflow requires Advanced or undocumented JSON. A generated Advanced command view supplies expert reachability but is not the ordinary user experience.

## Verifiable requirements

### USK-R-CLI-001 — Machine mode never prompts

**Requirement.** Explicit machine/noninteractive invocation MUST never open UI or prompt, even when attached to a terminal.

**Rationale.** Automation must be deterministic.

**Acceptance.** `USK-AT-CLI-001` in the acceptance catalogue.

### USK-R-CLI-002 — Linear parity

**Requirement.** All admitted ordinary terminal workflows MUST remain operable in linear mode without color or cursor movement.

**Rationale.** Accessibility and weak terminals are primary uses.

**Acceptance.** `USK-AT-CLI-002` in the acceptance catalogue.

### USK-R-CLI-003 — Terminal restoration

**Requirement.** TUI exits and cancellation MUST restore the owned terminal state and preserve operation truth.

**Rationale.** A UI crash should not strand the terminal or lie about effects.

**Acceptance.** `USK-AT-CLI-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-FACMAN], [^CONVERSATION].

[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
