# tri-sync-consensus-lab

Simulation testbed for trust-weighted sensor fusion and block-based
agreement across noisy, adversarial-free nodes; telemetry-instrumented,
not yet cryptographically secured. Cargo package: `tri_sync`.

## What's here

- `src/invariants.rs` — the `clarity_gate` a node applies to its own
  observation noise before trusting it directly.
- `src/types.rs` — `TelemetryRow` (one step's reported state), plus
  `NodeState`/`Observation` for the modular variant below.
- `src/telemetry.rs` — plain stdout reporting for a run.
- `src/consensus.rs` — `robust_fuse`: the trimmed weighted-mean estimator
  used to fuse many nodes' observations into one reference value.
- `src/node.rs` — per-node state transitions (`set_observation`,
  `fuse_lock`) for the modular variant.
- `src/trust_graph.rs` — `update_reliability`, which moves a node's
  reliability toward how close its estimate is to ground truth. See the
  Status note below - this is not something a real node could run.
- `src/phase.rs` — `disagreement` and `should_explode`, the fast-sync
  phase-detection logic, extracted from the sim binaries into testable
  functions.
- `src/main.rs` (bin `tri_sync_scalar`) — a scalar-truth rewrite of the
  fusion loop (no chain) built on the modules above instead of one inline
  function; `n=25` nodes, single-value ground truth rather than a
  4-vector.
- `src/bin/tri_sync_graph.rs` (bin `tri_sync_graph`) — no chain: `n` nodes
  with a directed trust graph observe a drifting, occasionally-shocked
  ground truth with per-node noise, fuse neighbor readings with a
  trimmed weighted mean, and adapt edge weights based on whether fusing
  actually reduced their error. Also tracks a `phi` potential field via a
  gradient-flow update each step, currently unused by anything
  downstream.
- `src/bin/tri_sync_chain.rs` (bin `tri_sync_chain`) — adds a block chain
  on top of the fusion loop: candidate blocks are proposed from the mean
  fused state, and a flat headcount quorum (10 of 30 nodes) decides
  whether to extend the chain. No signatures, no per-node reliability
  weighting.
- `src/bin/tri_sync_chain_weighted.rs` (bin `tri_sync_chain_weighted`) —
  adds per-node reliability weights and a weighted quorum, plus a
  "reconcile forks at the same height" step.
- `src/bin/tri_sync_chain_crypto.rs` (bin `tri_sync_chain_crypto`) — the
  fullest variant: adds real Ed25519 signing/verification per node,
  epoch-based key rotation, and fork reconciliation.
- `src/bin/tri_sync_http.rs` (bin `tri_sync_http`) — a small HTTP server
  that tails a telemetry JSONL file and serves it over `/health`,
  `/latest`, and `/events`.

## Status

This is a research/prototype sandbox, not a production consensus system.
Concretely, as of this commit:

- **Nodes are not adversarial.** There is no faulty or malicious node
  model in any variant.
- **Quorum/signing/reliability decisions read ground truth.** Every chain
  variant decides whether a candidate block clears quorum by comparing
  its error against `truth` directly — something no real distributed
  node has access to. `tri_sync_chain_crypto` wraps this in real Ed25519
  signatures, but the sign/no-sign decision underneath is the same.
  `tri_sync_scalar`'s `trust_graph::update_reliability` has the identical
  problem in its own function signature: it takes `truth` as a
  parameter. A deployable version would compare a node's estimate
  against the fused reference or its neighbors, never the answer.
- **Runs are not reproducible.** All six binaries use unseeded
  `rand::thread_rng()`.
- **`/events` on `tri_sync_http` is not a real stream.** `tiny_http`
  doesn't support long-lived streaming responses, so it returns one
  batch in SSE format rather than pushing new events as they happen.
- **A known fork/reconcile bug in `tri_sync_chain_weighted`:** when a
  fork-probability step produces two proposals and both clear quorum, the
  second is built on top of the first (not as a true sibling), but the
  per-step bookkeeping still files both under one height. The
  reconciliation step can then treat a block's own parent as a rejected
  fork branch. Not yet fixed.
- No persistent ledger: the chain in every variant is an in-memory
  `HashMap` that vanishes when the process exits. What's written to disk
  (`telemetry.jsonl`) is a per-step summary, not the ledger itself.

## Running

```bash
cargo run --bin tri_sync_scalar
cargo run --bin tri_sync_graph
cargo run --bin tri_sync_chain -- --steps 400 --out /tmp/telemetry.jsonl
cargo run --bin tri_sync_chain_weighted -- --steps 600 --out /tmp/telemetry.jsonl
cargo run --bin tri_sync_chain_crypto -- --steps 600 --out /tmp/telemetry.jsonl
cargo run --bin tri_sync_http -- --file /tmp/telemetry.jsonl --port 8787
```
