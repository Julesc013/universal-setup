# AIDE Task OS Ledgers

This directory contains append-only-style ledger schemas for Task OS v0.

The schemas define record shapes for task, blocker, capability, branch provenance, and checkpoint history. X-OS-00 does not create authoritative instance ledgers that claim current repo history. Example records live under `.aide/examples/task-os/` and are marked as examples.

X-OS-01 command outputs under `.aide/reports/task-os-*` are generated report evidence, not canonical append-only ledgers.

X-OS-02 capability outputs under `.aide/reports/capability-*` are generated report-only observations over the current source tree. They classify reality posture conservatively and do not authorize apply behavior, target mutation, branch mutation, provider/model calls, network calls, release publication, or product capability claims beyond the evidence listed in the report.
