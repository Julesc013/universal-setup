# Rollback Records

Rollback records preserve the information needed to review a future inverse operation. They record transaction id, preimage references, inverse-operation records, verification status, evidence references, and whether rollback execution is allowed.

In AIDE-APPLY-00 rollback execution is always forbidden. Rollback records are proof that a transaction model can describe recovery evidence before apply behavior exists.

Any future rollback execution requires a separate reviewed queue item, ownership evidence, preimage hash verification, conflict checks, dirty-work classification, and explicit review gates.
