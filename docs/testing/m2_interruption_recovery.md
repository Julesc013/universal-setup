# M2 Interruption and Recovery Evidence

M2-WU5 exercised the committed interruption matrix at provider revision
`beccc0a` under the explicitly authorized synthetic acceptance root:

```text
D:\FacMan-Live-Acceptance\M2\m2wu5-20260714-01
```

The run exclusively created that previously nonexistent child. It used the
non-proprietary text-only synthetic product and retained 61 evidence files,
including 14 durable transaction journals. The summary is:

```text
schema: usk.interruption_acceptance_summary.v1
case_count: 11
unchanged: 1
rolled_back: 4
completed: 3
recovery_required: 3
operator_verdict: pending
automation_created_verdict: false
summary_sha256: c64ddfaa38bde351002d2840999b3ba74173cde8c76d3e6aa21891b5d169f6c1
```

The pre-commit cases stopped after journal creation, during staging creation,
during a staged write, after staged verification, and immediately before the
no-replace commit. The first left the target unchanged; the four cases with an
exact durable staging identity and closure completed reviewed rollback.

The install cases stopped after the target commit, before installed-state
commit, and before audit completion. Each exposed `recovery_required`, then
completed through idempotent finalization using the exact original install
plan. The repair, move, and uninstall cases stopped during owned replacement,
after destination commit, and after uninstall-marker commit respectively. Each
retained a visible `recovery_required` journal and its inspectable roots because
automatic continuation is not yet safe for those operation contexts.

This is automated evidence, not the M2 human verdict. No existing Factorio or
Steam installation was selected or changed. No product executable, network,
credential, registry, shortcut, elevation, package-manager, signing, or
publication behavior was introduced or exercised.
