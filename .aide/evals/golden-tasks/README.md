# Golden Tasks v0

Q15 golden tasks are deterministic repo-local quality gates for AIDE's
token-saving workflow. They do not call models, providers, network services,
exact tokenizers, external benchmarks, or LLM judges.

The first task set checks AIDE's own compact artifacts:

- compact task packet required sections and token estimate
- context packet references instead of full repo dumps
- verifier detection of malformed evidence
- review packet evidence-only shape
- token ledger metadata and budget status
- managed adapter section determinism

Token reduction is only valid when these local quality gates pass. These tasks
do not prove arbitrary coding quality; they prove the token-survival substrate
itself has not regressed.
