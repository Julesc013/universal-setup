<!-- SPDX-FileCopyrightText: 2026 Jules C -->
<!-- SPDX-License-Identifier: MIT -->

The adjacent gzip file contains selected, unchanged diagnostic objects from the
original failed traced maintenance request in CI run 37929937674, attempt 1,
head `1ccb228ebcae755e37634c6d33db009156943443`, tree
`b152586b78f1f80eeecd3616cd8a83f4d6d52838`. Its original public receipt was
3,819,801 bytes, SHA-256
`81bd374718af09ff8b408fb21dff5f4fb1cfe74f45db743a61a7c12d8643be03`.

The selected input retains the actual original request/capture, failed readback,
original before readback and controlled damage. It omits unrelated outer receipt
fields and repeated failure/readback copies. Embedded protected record bytes,
native object facts, raw ACE order and access results are unchanged. The unit
test pins both compressed and decoded bytes. This fixture exercises a read-only
decoder and corruption refusals; it supplies no live native objects or mutation
authority.

The original request was still live at its 120-second deadline, with no native
response or known exit code. A later independent sample found the captured client
exited; that sample does not provide its response or qualify completion. The
effect prefix ends at `write_ownership` intent while the distinct native prefix
has a confirmation for that effect. The journal is `committing`. These retained
facts cannot qualify the request, restore native custody, establish an atomic
sample or prove whole-target safety.
