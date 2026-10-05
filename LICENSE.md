# License

Copyright (c) 2026 TRI-SYNC. All rights reserved.

## Default position

No part of this repository — source code, documentation, protocol
definitions, diagrams, or the repository name and branding — may be
used, copied, modified, merged, published, distributed, sublicensed,
or sold, in whole or in part, without a license expressly granted in
writing by the copyright holder. **Public visibility of this
repository is not, by itself, a grant of any license.** An absence of
a `LICENSE` file is sometimes mistaken for an absence of restrictions;
this file exists to state, just as explicitly, that a *visible* public
repository under this notice grants no rights on its own either. Using
any part of this repository requires first obtaining one of the
licenses below.

## Licensed components

The following parts of this repository are covered by this license
and by any license granted under it. This repository holds two
genuinely different things, and this list says so explicitly rather
than leaving which is which to be inferred:

1. **The networked consensus node** (`tri_sync_node` and
   `tri_sync_core`) — **this is the product**: a real, self-hosted,
   network-capable consensus node, independent OS processes exchanging
   Ed25519-signed messages over real QUIC+TLS connections pinned to
   each peer's actual identity, with two-phase prevote/precommit
   quorum-certificate consensus, dynamic peer membership, chain-sync
   for a node that's fallen behind, LMDB persistence, Prometheus
   metrics, and the offline license-enforcement mechanism that this
   document's tiers below actually grant rights against (`tri_sync_node/
   src/license.rs`, and the signing side in `tri_sync_node/src/bin/
   sign_license.rs`). See the main `README.md`'s "The networked node
   (`tri_sync_node`)" section and `tri_sync_node::consensus`'s own
   module doc comment for the authoritative, current account of what
   this does and doesn't cover.
2. **The single-process simulation lab** (the root `tri_sync` package:
   `src/consensus.rs`, `src/trust_graph.rs`, `src/invariants.rs`,
   `src/phase.rs`, `src/node.rs`, `src/main.rs`, and the per-binary
   simulation loops in `src/bin/` — `tri_sync_graph`, `tri_sync_chain`,
   `tri_sync_chain_weighted`, `tri_sync_chain_crypto`, `tri_sync_http`)
   — the research/design testbed that validated the consensus and
   trust logic in isolation before it was extracted into
   `tri_sync_core` above. The main `README.md`'s own "Status" section
   describes this plainly: "a research/prototype sandbox, not a
   production consensus system." It is not the thing a Commercial or
   Internal Use License (below) exists to let someone deploy.
3. **The deterministic invariants and encoding rules** shared by both
   components above — the SHA-256 canonical-string digest rules used
   for block and reconcile hashing (`hash_vec`, `hash_list`,
   `canon_string`, `block_hash` — proved out in the simulation lab,
   now the versions actually running being `tri_sync_core::chain`'s),
   the `BTreeMap`-ordered trust-edge iteration that makes simulation
   runs reproducible under a fixed seed, and every other invariant the
   codebase defines and tests against.
4. **The repository name, branding, and documentation** —
   "tri-sync-consensus-lab," the architectural description, and every
   diagram and explanatory text in this repository (`README.md` and
   this file).

## License tiers

Four license types may be granted separately, in writing, by the
copyright holder. **None is granted by default** — each must be
requested and issued individually, and the copyright holder decides
whether to issue one.

Granting tier B or C below also means issuing a signed `license.toml`
for each licensed deployment, via `tri_sync_node_license_tool` (see
the main `README.md`'s "Issuing licenses" section) — this is the
technical mechanism that actually enforces the grant at runtime: the
written license is the legal permission, and the signed file is what
`tri_sync_node` itself checks before it will run. **As of this
writing, that check only enforces node count** (`max_nodes`) — a
license's `features` list is accepted, signed, and verified, but
nothing in `tri_sync_node` yet restricts behavior by feature name (see
`License::has_feature`'s doc comment in `tri_sync_node/src/license.rs`
for the precise, current status). Don't represent a `features` entry
to a licensee as something the software itself enforces until that
changes.

### A. Source License (Non-Commercial)
Permits reading and running the code — most naturally the single-
process simulation lab, given it's explicitly a research testbed
rather than production software — for academic or personal study. No
commercial use. No redistribution of modified versions.

### B. Commercial License
Permits deploying the networked consensus node (`tri_sync_node`) in
products, services, or infrastructure, up to the node count and until
the expiry set in the accompanying signed `license.toml`. Includes
redistribution rights and compliance requirements, set out in the
written license issued for that use.

### C. Internal Use License
Permits an organization to run the networked consensus node
internally, up to the node count and until the expiry set in the
accompanying signed `license.toml`. No external deployment or resale.

### D. Open Reference License
Permits reading the documentation and protocol descriptions. Does not
permit using either component's code in production or in derivative
works.

## Requesting a license

To request any of the licenses above, contact the copyright holder at
tri@trisync.dev.

## Not legal advice

This document states the copyright holder's intent for how this
repository's components may be used. It is a starting point, not a
substitute for review by a lawyer — particularly before issuing or
relying on a Commercial License, since terms referenced above (for
example "compliance requirements") are placeholders for specifics
that still need to be defined precisely, in the actual license issued
for a given use, to be enforceable.
