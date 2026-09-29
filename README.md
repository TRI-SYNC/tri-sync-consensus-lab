# tri-sync-consensus-lab

Simulation testbed for trust-weighted sensor fusion and block-based
agreement across noisy, adversarial-free nodes; telemetry-instrumented,
not yet cryptographically secured.

## What's here

- `src/invariants.rs` — the `clarity_gate` a node applies to its own
  observation noise before trusting it directly.
- `src/types.rs` — `TelemetryRow`, the shape of one step's reported state.
- `src/telemetry.rs` — plain stdout reporting for a run.
- `src/bin/sim.rs` — no chain: `n` nodes with a directed trust graph
  observe a drifting, occasionally-shocked ground truth with per-node
  noise, fuse neighbor readings with a trimmed weighted mean, and adapt
  edge weights based on whether fusing actually reduced their error. Also
  tracks a `phi` potential field via a gradient-flow update each step,
  currently unused by anything downstream.
- `src/bin/sim_chain_basic.rs` — adds a block chain on top of the fusion
  loop: candidate blocks are proposed from the mean fused state, and a
  flat headcount quorum (10 of 30 nodes) decides whether to extend the
  chain. No signatures, no per-node reliability weighting.
- `src/bin/sim_chain_reconcile.rs` — adds per-node reliability weights and
  a weighted quorum, plus a "reconcile forks at the same height" step.
- `src/bin/sim_chain_signed.rs` — the fullest variant: adds real Ed25519
  signing/verification per node, epoch-based key rotation, and fork
  reconciliation.
- `src/bin/server.rs` — a small HTTP server that tails a telemetry JSONL
  file and serves it over `/health`, `/latest`, and `/events`.

## Status

This is a research/prototype sandbox, not a production consensus system.
Concretely, as of this commit:

- **Nodes are not adversarial.** There is no faulty or malicious node
  model in any variant.
- **Quorum/signing decisions read ground truth.** Every chain variant
  decides whether a candidate block clears quorum by comparing its error
  against `truth` directly — something no real distributed node has
  access to. `sim_chain_signed` wraps this in real Ed25519 signatures,
  but the sign/no-sign decision underneath is the same.
- **Runs are not reproducible.** All five binaries use unseeded
  `rand::thread_rng()`.
- **`/events` on the server is not a real stream.** `tiny_http` doesn't
  support long-lived streaming responses, so it returns one batch in SSE
  format rather than pushing new events as they happen.
- **A known fork/reconcile bug in `sim_chain_reconcile`:** when a
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
cargo run --bin sim
cargo run --bin sim_chain_basic -- --steps 400 --out /tmp/telemetry.jsonl
cargo run --bin sim_chain_reconcile -- --steps 600 --out /tmp/telemetry.jsonl
cargo run --bin sim_chain_signed -- --steps 600 --out /tmp/telemetry.jsonl
cargo run --bin server -- --file /tmp/telemetry.jsonl --port 8787
```
