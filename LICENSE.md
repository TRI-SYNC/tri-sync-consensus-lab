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
and by any license granted under it:

1. **The consensus engine implementation** — the fusion logic,
   trust-weight learning, clarity gate, directed edge dynamics,
   potential flow, and the full simulation loop (`src/consensus.rs`,
   `src/trust_graph.rs`, `src/invariants.rs`, `src/phase.rs`,
   `src/node.rs`, and the per-binary simulation loops in `src/main.rs`
   and `src/bin/`).
2. **The deterministic invariants and encoding rules** — the SHA-256
   canonical-string digest rules used for block and reconcile hashing
   (`hash_vec`, `hash_list`, `canon_string`, `block_hash`), the
   `BTreeMap`-ordered trust-edge iteration that makes runs reproducible
   under a fixed seed, and every other invariant the codebase defines
   and tests against.
3. **The node implementation** — fork/reconcile logic, epoch-based key
   rotation, and the Ed25519 signing and verification pipeline
   (`src/bin/tri_sync_chain_weighted.rs`,
   `src/bin/tri_sync_chain_crypto.rs`).
4. **The HTTP API** — the `/health`, `/latest`, and `/events` routes
   and their request/response formats, including the streaming
   `/events` implementation (`src/bin/tri_sync_http.rs`). This is a
   read-only telemetry feed, not an interactive consensus API — it
   does not accept observations or otherwise participate in consensus.
5. **The simulation framework** — robust trimmed fusion, the noise
   model, the shock model, the directed trust graph, and adaptive
   weight learning (`src/bin/tri_sync_graph.rs` and the shared logic
   above).
6. **The repository name, branding, and documentation** —
   "tri-sync-consensus-lab," the architectural description, and every
   diagram and explanatory text in this repository (`README.md` and
   this file).

## License tiers

Four license types may be granted separately, in writing, by the
copyright holder. **None is granted by default** — each must be
requested and issued individually, and the copyright holder decides
whether to issue one.

### A. Source License (Non-Commercial)
Permits reading and running the code for academic or personal study.
No commercial use. No redistribution of modified versions.

### B. Commercial License
Permits integrating the consensus engine into products, services, or
infrastructure. Includes redistribution rights and compliance
requirements, set out in the written license issued for that use.

### C. Internal Use License
Permits an organization to use the system internally. No external
deployment or resale.

### D. Open Reference License
Permits reading the documentation and protocol descriptions. Does not
permit using the code in production or in derivative works.

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
