---
type: "Engineering Specification"
title: "Native OEM+ shells, accessibility and appearance"
description: "Use platform controls and shared semantics while allowing bounded product branding."
tags: ["universal-setup","interfaces"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-GUI","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PRESENT"]}
---

# Native OEM+ shells, accessibility and appearance

## Native reference strategy
Use a first Windows adapter suited to the admitted target, an AppKit macOS adapter and one GTK Linux adapter. WinForms is useful for the current ecosystem but the installer bootstrap/recovery path must not depend on the framework it is meant to install. Win32 can serve a constrained zero-extra-runtime profile. Qt, WinUI, SwiftUI and web are separately admitted adapters, not mandatory first-release stacks.

## OEM+ limits
System Native is always available and Safe Mode overrides custom appearance. Keep system fonts/colors/focus/controls/window conventions. Brand icons, welcome/header, component artwork, completion and support pages. No executable theme code or broad CSS/QSS/XAML injection. High contrast, large text and reduced motion may override product styling.

## Platform behavior
Windows: native dialogs, access keys, UI Automation, default/cancel buttons, responsive layout, mixed-DPI transitions and no unnecessary elevation of the normal application. GTK: native theme metrics, keyboard/focus, AT-SPI/Orca and separately qualified X11/Wayland. macOS: AppKit menus, Command shortcuts, sheets, resizing, VoiceOver and signed bundle immutability. Never demand pixel parity between platforms.

## Interface laboratory
Run shared empty/loading/refused/stale/interrupted/recovery/large-corpus scenarios. Capture exact package/host/toolkit identity, screenshots, accessibility trees, focus traces and timings. Test 100–200% scaling where applicable, high contrast, text expansion, IME, RTL, keyboard-only, screen reader and small window sizes. Automated checks detect regressions; a concentrated human experience receipt remains distinct.

## Verifiable requirements

### USK-R-GUI-001 — Accessible complete flows

**Requirement.** Every required native setup/maintenance flow MUST support keyboard and named assistive-technology operation on each supported target profile.

**Rationale.** Drawing native controls is not an accessibility proof.

**Acceptance.** `USK-AT-GUI-001` in the acceptance catalogue.

### USK-R-GUI-002 — Safe theme fallback

**Requirement.** Malformed or incompatible branding MUST fall back to System Native without changing allowed effects.

**Rationale.** Presentation is untrusted data.

**Acceptance.** `USK-AT-GUI-002` in the acceptance catalogue.

### USK-R-GUI-003 — Bootstrap independence

**Requirement.** Each setup profile MUST document and qualify its GUI/runtime dependency and preserve a recovery route when that runtime is missing.

**Rationale.** An installer cannot assume its prerequisite exists.

**Acceptance.** `USK-AT-GUI-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-FACMAN], [^USR-SYSPANE], [^CONVERSATION].

[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
