# Rollback Model

Rollback is part of setup architecture, not an afterthought. Every mutating
operation must define the state it can restore, the evidence it records, and
the conditions where rollback is refused rather than guessed.
