# Promotion Validation Gates

Normal post-task validation is T0 plus T1. Larger tasks add relevant T2. Checkpoint, promotion, and release gates require T0, T1, relevant T2, and T3.

T3 evidence must be current for the branch and commit under review. If T3 is missing, stale, timed out, or only available as a handoff, promotion is evidence-blocked until a compact summary is produced and validated.

Task OS automation depends on these validation semantics. Branch dispatch, repair apply, promotion, and transactional apply remain blocked until validation tiering, transaction safety, branch provenance, and rollback semantics are proven.

