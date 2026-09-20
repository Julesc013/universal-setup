---
type: "Engineering Specification"
title: "Process protocol, framing and reconnect"
description: "Give CLI, native UI and external consumers bounded transport without transport-owned semantics."
tags: ["universal-setup","interfaces"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-WIRE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-API","USK-S-POLICY"]}
---

# Process protocol, framing and reconnect

## Initial transport
Support a one-shot stdin/stdout host first: one bounded request, one response, diagnostics on stderr. A long-running worker/IPC transport is optional once operations need independent lifetime. Direct and process modes share command/result semantics.

The proposed framed profile uses a four-byte unsigned big-endian byte length followed by strict UTF-8 JSON, with an explicit configurable maximum. Reject oversized length before allocating. No mixed log text on the protocol stream. Version negotiation precedes stateful operations; unknown mandatory features refuse.

## Identity and retries
Request IDs correlate responses. Idempotency keys identify semantic retry. Operation and attempt IDs survive transport reconnection. A disconnect after dispatch means inspect the operation; retrying a destructive request under a new ID is not automatic recovery.

## Local IPC
Use explicit endpoints with target-appropriate peer authentication and permissions. Do not expose TCP merely because a daemon exists. Bound client count, frame size, output, queue depth, processing time and rate. A UI is untrusted with respect to elevated effects. Remote transport is a separately admitted security profile.

## Events
NDJSON can be an explicit CLI event format; a machine-result JSON command never unexpectedly emits multiple documents. Event sequences are monotonic per operation. On gap or overflow return a resynchronization marker and full inspection route. Critical state remains in durable operation storage, not a client event buffer.

## Verifiable requirements

### USK-R-WIRE-001 — Frame bounds

**Requirement.** A process host MUST reject oversized, truncated, malformed and duplicate-key frames before dispatch.

**Rationale.** Hostile clients should not exhaust or confuse workers.

**Acceptance.** `USK-AT-WIRE-001` in the acceptance catalogue.

### USK-R-WIRE-002 — Reconnect identity

**Requirement.** Reconnect MUST inspect the original operation rather than infer no effects from a lost response.

**Rationale.** Operations outlive clients.

**Acceptance.** `USK-AT-WIRE-002` in the acceptance catalogue.

### USK-R-WIRE-003 — No secret protocol leakage

**Requirement.** Machine responses and diagnostics MUST redact secret material while preserving safe correlation IDs.

**Rationale.** Support logs and agent tools are shared.

**Acceptance.** `USK-AT-WIRE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
