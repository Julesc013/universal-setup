# Product package and recipe contracts

The additive product-package contract separates authored product meaning from
generic setup lifecycle law. A product supplies exact product/version identity,
component closures, local-source identity, immutable payload paths, mutable and
preserved data paths, target topology, migrations, lifecycle support, and
evidence references.

Universal Setup verifies the local package, plans lifecycle effects, records
installed state, and applies only under separately authorized lifecycle APIs.
These contracts do not make a download URL authoritative and do not select a
release channel, acquire a package, describe launch intents or sessions, carry
branded user text, or authorize live mutation.

`usk.product_package.v1` composes `usk.component_manifest.v1` and
`usk.source_manifest.v1`. `usk.setup_recipe.v1` binds the selected components
and package digest to topology, migration, lifecycle, rollback/recovery, and
`usk.installed_state.v1` compatibility requirements.

The neutral provider-local fixture uses `org.example.fixture`, a `core`
component, `bin/fixture`, `share/message.txt`, and a single optional
`1.0.0` to `1.1.0` migration. Passing this fixture qualifies only these
contracts as `fixture-qualified`; it grants no product or mutation authority.
