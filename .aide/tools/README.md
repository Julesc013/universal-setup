# AIDE Tool Absorption

`.aide/tools/` contains Q41 schemas and generated evidence for existing-tool
absorption.

Q41 discovers candidate repo-specific tools, classifies their likely
capabilities, records preservation-first fates, and creates future wrapper or
adapter plans. It does not execute unknown tools, rename tools, delete tools,
migrate tools, or apply wrappers.

Generated `latest-*` files are source-repo evidence only. Target repositories
must generate their own inventories and wrap plans after import.
