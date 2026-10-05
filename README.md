# tri-sync-consensus-lab

[![CI](https://github.com/TRI-SYNC/tri-sync-consensus-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/TRI-SYNC/tri-sync-consensus-lab/actions/workflows/ci.yml)

Simulation testbed for trust-weighted sensor fusion and block-based
agreement across noisy, adversarial nodes; telemetry-instrumented. One
variant (`tri_sync_chain_crypto`) adds real Ed25519 signing and epoch
key rotation - the rest have no cryptography. Cargo package: `tri_sync`.

This same repository also contains the real product built on what the
simulation proved out: `tri_sync_core` and `tri_sync_node`, a
self-hosted, licensed, network-capable consensus node (real QUIC+TLS
transport, Ed25519-signed messages, LMDB persistence, Prometheus
metrics) - see
[The networked node (`tri_sync_node`)](#the-networked-node-tri_sync_node)
below. The sections above and immediately below this one (What's here
through Testing) describe only the single-process simulation; the
networked node has its own section with its own Running/Testing/
Known-limitations breakdown.

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
  reliability toward how close its estimate is to the fused reference
  (`RStar::value`), not ground truth - see Status below for why that
  distinction matters.
- `src/phase.rs` — `disagreement` and `should_explode`, the fast-sync
  phase-detection logic, extracted from the sim binaries into testable
  functions.
- `src/main.rs` (bin `tri_sync_scalar`) — a scalar-truth rewrite of the
  fusion loop (no chain) built on the modules above instead of one inline
  function; `n=25` nodes, single-value ground truth rather than a
  4-vector. 5 of the 25 nodes (`ADVERSARIAL_NODES`) are adversarial: they
  report a fixed, deliberate deviation (`DEVIATION_BIAS`) instead of a
  baseline noisy reading, and get the network's lowest noise bucket so
  the noise-based clarity gate never flags them - see Status below for
  what this actually demonstrates.
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
  weighting, no reconcile mechanism. Persists its chain to an
  append-only `--chain-log` file, replayed on startup.
- `src/bin/tri_sync_chain_weighted.rs` (bin `tri_sync_chain_weighted`) —
  adds per-node reliability weights and a weighted quorum, plus a
  "reconcile forks at the same height" step. Same `--chain-log`
  persistence as `tri_sync_chain`.
- `src/bin/tri_sync_chain_crypto.rs` (bin `tri_sync_chain_crypto`) — the
  fullest variant: adds real Ed25519 signing/verification per node,
  epoch-based key rotation, and fork reconciliation. Same `--chain-log`
  persistence as the other two chain binaries.
- `src/bin/tri_sync_http.rs` (bin `tri_sync_http`) — a small HTTP server
  that tails a telemetry JSONL file and serves it over `/health`,
  `/latest`, and a genuinely streaming `/events`.

## Status

This is a research/prototype sandbox, not a production consensus system.
Concretely, as of this commit:

- **Robustness and convergence testing don't require an adversarial node
  at all - that was true of the original design, before any adversarial
  model existed.** Heterogeneous per-node noise (`sigma` varies by
  `i % 6`), biased sensors (fixed per-node offsets), random shocks to
  `truth`, asymmetric directed trust edges, the Δe learning rule that
  downweights neighbors who worsen the fused estimate, the clarity gate
  that locks out noisy nodes, and trimmed-mean fusion that resists
  outliers already exercise stability and convergence under difficult,
  unbiased-in-intent stochastic conditions on their own. The adversarial
  node model below tests something categorically different: not
  difficulty, but deliberate, coordinated, persistent misinformation - a
  node reporting a fixed offset every step, specifically tuned to sit in
  the lowest noise bucket so the clarity gate's noise heuristic can't
  catch it by construction. It's an addition for that specific, narrower
  question (can the trust mechanism catch something actively trying not
  to look suspicious), not a prerequisite for testing normal stability
  or convergence.
- **Fixed, in all six binaries: a real adversarial node model.** A fixed
  minority of nodes (`ADVERSARIAL_NODES`, ~20% of the network in each
  binary) report a deliberate, consistent deviation (`truth +
  DEVIATION_BIAS`, no noise) instead of a baseline reading, and are given
  the network's lowest noise bucket so `invariants::clarity_gate` never
  flags them - the only thing that catches them is the trust/fusion
  mechanism itself, not a noise-based heuristic. The RNG is always drawn
  (even when the sample is unused) so the RNG stream doesn't depend on
  which nodes are adversarial, keeping runs reproducible either way.
  Verified per binary with a real run and an end-of-run adversarial
  summary:
  - `tri_sync_scalar` (`SEED=42`, 250 steps): fused reference stays
    close to truth despite the deviating nodes (`|truth - r_star| =
    0.095` against a `DEVIATION_BIAS` of `3.0`), and their reliability
    measurably and persistently settles below the baseline nodes'
    (`0.30` vs `0.71` mean, a 2.4x gap). One side effect: completion
    (`done`) requires *every* node, deviating ones included, within
    `eps_align` of `r_star`, and they never converge - so this binary
    now always runs to the full step budget while they're present
    rather than reporting sustained alignment, which is correct, not a
    regression.
  - `tri_sync_graph`: mean incoming trust weight separates
    (`baseline=1.5750` vs `adversarial=1.2711`), more modestly than the
    centralized-fusion case above since there's no single global
    reliability field to sharpen against - each node only ever sees its
    own neighbors' edges.
  - `tri_sync_chain`, `tri_sync_chain_weighted`: same incoming-trust-weight
    separation, measured against `head_block.state` rather than `truth`
    (see the ground-truth item below for why).
  - `tri_sync_chain_crypto`: separation is real but slow to resolve - at
    300 steps it's actually inverted (`adversarial=2.58` vs
    `baseline=2.55`), only becoming the expected direction by 600
    (`baseline=2.27` vs `adversarial=1.99`), since it's a
    deliberately-damped multiplicative update that just needs enough
    iterations. This is why the CLI default is `--steps 600`, not
    merely a starting point to raise if you want to see the separation
    - it was never shipped at 300, that number only ever came from an
    ad hoc verification probe during development. Overriding `--steps`
    down below the default
    risks reading a still-converging trend as a conclusion.
- **Fixed: no decision anywhere reads ground truth anymore.**
  `trust_graph::update_reliability` (used by `tri_sync_scalar`) now scores
  a node against the fused reference (`RStar::value`). All three chain
  variants' quorum/signing gates now score each node against its own
  locked estimate (`x_vec[i]`) instead of comparing a single global
  `truth`-based error for every node — `tri_sync_chain`'s old version
  didn't even vary by node despite looping over `i`, which is why that
  loop variable used to trigger an unused-variable warning. Their
  Δe edge-learning steps now compare against `head_block.state` (the
  chain's last agreed state, public to every node) instead of `truth`;
  comparing against each node's own `refs[i]` instead would have been
  circular, since a node's locked estimate is itself a blend toward
  `refs[i]` and would always look like an improvement by construction.
- **Fixed: runs are now reproducible.** All six binaries seed a
  `StdRng` from a fixed constant (`SEED`, not yet exposed as a CLI flag)
  instead of using unseeded `rand::thread_rng()`. That alone wasn't
  enough for the four binaries with a `w_out: HashMap<usize, f64>` per
  node: `HashMap`'s iteration order is randomized per-process
  independently of any RNG seed, and `w_out` was iterated inside a
  floating-point sum/sort that feeds back into itself every step -
  enough for a random iteration order alone to make two seeded runs
  diverge. Switched `w_out` to `BTreeMap`, which iterates in deterministic
  key order; verified by diffing two runs of each binary.
- **Fixed: `/events` on `tri_sync_http` is a real stream.** tiny_http's
  own `Response`/`raw_print` path can't be used for this: it buffers
  written data (an 8KB `chunked_transfer::Encoder` buffer, sitting on
  top of a 1KB `BufWriter` around the socket) and only flushes either
  buffer when the whole response ends, with no way for a caller to force
  an earlier flush - fine for a batch reply, fatal for a live trickle of
  small SSE events, which would just sit in memory and never reach the
  client. Fixed by taking the raw connection via
  `Request::into_writer()` (documented by tiny_http for exactly this:
  "things like CGI"), writing the HTTP response head and each chunk by
  hand, and calling `.flush()` after every chunk. The main server loop
  now spawns a thread per request instead of handling them inline, so
  the long-lived `/events` connection can't stall `/health`/`/latest`
  behind it. Verified end-to-end: appended lines to the telemetry file
  1-1.5s apart while a `curl -N` connection was open and confirmed each
  arrived at the client within the tailer's ~300ms poll interval rather
  than all at once at the end; confirmed `/health` still answers in ~1ms
  while `/events` is open on another connection; confirmed the server
  survives an abrupt (`kill -9`) client disconnect mid-stream and keeps
  serving other requests.
- **Fixed: the fork/reconcile bug, in both `tri_sync_chain_weighted` and
  `tri_sync_chain_crypto`.** `tri_sync_chain_crypto` had the identical bug
  even though only `tri_sync_chain_weighted` was originally reported -
  `tri_sync_chain` never had it, because it has no reconcile mechanism at
  all. In both fixed binaries, every proposal in a step now extends the
  *same* parent at the *same* height (computed once from the head at the
  top of the step), and the winner is chosen once after all of a step's
  proposals exist, instead of racing `head` forward after each one. That
  racing is what let a second proposal end up parented on the first
  instead of beside it, which is what let the reconciliation step treat
  a block's own parent as a rejected fork rival. Verified by asserting
  `height == parent.height + 1` for every block in a 600-step
  `tri_sync_chain_weighted` run (369 blocks, zero violations) and a
  300-step `tri_sync_chain_crypto` run (193 blocks, zero violations), and
  by confirming both fixed runs still reproduce byte-for-byte.
- **Fixed: proposals in the same fork step are no longer always
  identical.** `cand` (and everything derived from it: `conf`, `sigw`,
  the resulting hash) used to be a deterministic function of `x_vec`
  alone, which doesn't change between the two proposals in a step -
  there was no other source of variation, so they always collapsed into
  one deduplicated entry and the reconcile path was structurally
  unreachable even after the fix above. Fixed via a partial-network-view
  model: each proposal samples a random ~85% subset of contributing
  nodes (falling back to all nodes if the sample is empty) instead of
  always averaging every node, modeling asynchronous/partitioned
  visibility - a legitimate, reproducible (drawn from the seeded RNG)
  source of real variation between proposals. Verified with the same
  height/parent instrumentation as above, now also counting fork
  heights and reconciles: `tri_sync_chain_weighted` (600 steps) found 3
  true-fork heights and 3 reconciles; `tri_sync_chain_crypto` (300 steps)
  found 8 and 8 - both exact matches, and both still reproduce
  byte-for-byte.
- **Fixed: a persistent ledger, in all three chain binaries.** Each
  binary takes a `--chain-log <path>` argument (defaulting under
  `../telemetry/`) and appends every block it creates or accepts via
  reconciliation to that file as newline-delimited JSON, flushed
  immediately. On startup it replays the log through the same
  `prefer`/`choose_head` logic used live, in file order, to reconstruct
  the correct head - a malformed line is a hard error naming the file
  and line number, never silently skipped. Verified per binary: ran
  once, restarted pointed at the same log, and confirmed the resumed
  run's head height picked up exactly where the previous run left off
  (including a fork+reconcile event spanning the restart boundary in
  `tri_sync_chain_weighted`); confirmed a corrupted log line fails loudly
  with a clear message and a non-zero exit code instead of skipping it.
  **Persistence scope is a deliberate decision, not an open gap:** only
  the ledger (`blocks`/`head`) persists across a restart. The
  simulation's own live state - `x_vec`, `truth`, per-node reliability,
  the `w_out` trust graph - does not, and isn't meant to. That mirrors
  how a real node works: the chain is the durable source of truth it
  must agree on with everyone else, while its in-memory beliefs about
  its neighbors are working state it rebuilds by observing and
  re-earning trust, not something it needs to have persisted to rejoin
  correctly. Snapshotting the full simulation state was considered and
  rejected for that reason - it would make a restarted node's local
  memory durable, which is backwards for what this is modeling, and
  would need its own versioned format, write cadence, and consistency
  story with the ledger for questionable benefit. The visible
  consequence: a resumed run's new blocks extend the old chain's real
  history, but on top of a freshly-initialized simulation trajectory, so
  `x_vec`/`truth`/reliability show a jump at the restart boundary in the
  telemetry - expected, the same way a rebooted node shows a trust dip
  right after rejoining, not a bug to fix.

## Running

```bash
cargo run --bin tri_sync_scalar
cargo run --bin tri_sync_graph
cargo run --bin tri_sync_chain -- --steps 400 --out /tmp/telemetry.jsonl --chain-log /tmp/chain.jsonl
cargo run --bin tri_sync_chain_weighted -- --steps 600 --out /tmp/telemetry.jsonl --chain-log /tmp/chain-w.jsonl
cargo run --bin tri_sync_chain_crypto -- --steps 600 --out /tmp/telemetry.jsonl --chain-log /tmp/chain-c.jsonl
cargo run --bin tri_sync_http -- --file /tmp/telemetry.jsonl --port 8787
```

`--chain-log` defaults to `../telemetry/<binary-name>.blocks.jsonl` if omitted;
re-running with the same path resumes that binary's chain (see the
persistence scope caveat above for what does and doesn't carry over).
All five simulation binaries also take `--seed <u64>` to reproduce a
different run than the default (`--seed 42`); `tri_sync_http` has no RNG
and doesn't take one.

## Testing

```bash
cargo test --workspace
```

42 tests, zero `clippy --all-targets -- -D warnings` warnings, both
enforced in CI (`.github/workflows/ci.yml`, badge above). Each binary's
`main()` is a thin CLI wrapper around a `simulate()` (or `run_server()`)
function that takes its config as plain arguments and returns an
`Outcome` struct, so tests call it directly instead of scraping stdout
or spawning a subprocess - every claim in the Status section above is
backed by a test, not just a one-off run that was checked by hand and
then discarded:

- **Reproducibility** - the same seed produces byte-identical output,
  checked for all six binaries.
- **Adversarial trust/reliability separation** - adversarial nodes end up
  measurably less trusted than baseline ones, checked for all six
  binaries at a step count known to actually show it (see the
  `tri_sync_chain_crypto` note above for why that number matters).
- **Fork/reconcile structural invariants** - every block's height is
  exactly its parent's plus one, and two blocks sharing a height share a
  parent, checked across a full run's block set, not just spot-checked;
  plus a check that real forks and reconciles actually occur, in
  `tri_sync_chain_weighted` and `tri_sync_chain_crypto`.
- **Signature validity** - every block signature verifies against the
  verifying-key registry snapshotted from the epoch it was actually
  signed under (not just whichever registry the run ended on), in
  `tri_sync_chain_crypto`.
- **Persistence** - a resumed run's head height picks up where the
  previous run left off, and a corrupted chain-log line is a hard error
  rather than being silently skipped, in all three chain binaries.
- **Real streaming** - `tri_sync_http`'s `/events` delivers a line
  appended after the connection opened, on that same connection, well
  within the tailer's poll interval; `/health` stays responsive while
  `/events` is open; a connection past the concurrency cap gets `503`
  without disturbing connections already under it.

A few of these were sanity-checked in the other direction too: the
streaming and connection-cap tests were run against a temporarily
reintroduced version of the bug they're meant to catch (the old
batch-response behavior; the cap check disabled) to confirm they
actually fail, not just that they currently pass.

## The networked node (`tri_sync_node`)

Everything above this section describes `tri_sync`, the single-process
simulation workspace used to design and validate the consensus/trust
logic in isolation. This section describes the other two workspace
members built on top of that validated logic: `tri_sync_core` (the
pure consensus/trust/fusion/chain code, extracted with no I/O
dependencies) and `tri_sync_node` (a real, self-hosted, licensed,
network-capable consensus node - independent OS processes exchanging
real signed messages over a real network, not a loop simulating many
nodes in one process).

What it actually is:

- **Real transport.** Peers connect over QUIC with TLS 1.3
  (`quinn`/`rustls`). Each node's certificate is generated from its own
  Ed25519 identity key, and every outbound connection is pinned to the
  specific peer being dialed - a validly self-signed certificate for
  the wrong identity is rejected before a single message is sent, not
  just caught later at the message layer.
- **Real cryptography.** Every proposal, vote, precommit, observation,
  trust-update, key-rotation, and chain-sync message is Ed25519-signed
  and verified against a known peer key before any of its content is
  trusted - see `tri_sync_node::protocol`'s per-message canonical
  signing strings.
- **Real persistence.** Blocks, the trust graph, peer keys, epoch
  metadata, and this node's current consensus lock are stored in LMDB
  (`tri_sync_node::persistence`) and restored on restart.
- **Real operational surface.** A Prometheus `/metrics` endpoint,
  per-peer health tracking, clean SIGTERM/SIGINT shutdown, timestamped
  logs, an offline Ed25519-signed license file
  (`license.toml`/`LICENSE_PUBLIC_KEY_HEX`) gating node count and
  feature flags, and an in-band key-rotation flow
  (`--rotate-key`) for rotating a node's identity without taking the
  whole network down.
- **Real BFT consensus over the wire**: round-robin proposer selection,
  a two-phase prevote/precommit quorum-certificate protocol (a node
  locks onto a candidate only once it independently observes a real
  prevote quorum, and a block commits only once a precommit quorum is
  reached), a liveness fallback that bumps the view and hands off to
  the next proposer after a timeout, chain-sync for a node that's
  fallen behind on a committed height, fork detection/logging, and
  dynamic peer membership (an `Add`/`Remove` change rides the ordinary
  block-commit path, so it only ever takes effect once its own block
  earns a real quorum-certificate under the membership as it stood
  *before* the change) - see `tri_sync_node::consensus`'s module doc
  comment for the full, precise account of what is and isn't covered
  (it is the authoritative source; this README summarizes it).

### Running

```bash
# One-time per node: generate node.toml (see tri_sync_node/src/config.rs
# for every field) and a license.toml. tri_sync_node/license.example.toml
# is a real, working fixture signed with a development-only key - issue
# real licenses with tri_sync_node_license_tool instead (see below), and
# replace LICENSE_PUBLIC_KEY_HEX in src/license.rs with the resulting
# production public key before issuing any to a paying customer.
cargo run --bin tri_sync_node -- node.toml --show-identity   # prints this node's pubkey, then exits
cargo run --bin tri_sync_node -- node.toml                   # starts the QUIC server + consensus loop, runs until killed
cargo run --bin tri_sync_node -- node.toml --duration 60      # same, but exits cleanly after 60s (for scripted runs)
cargo run --bin tri_sync_node -- node.toml --rotate-key       # rotates this node's signing key and announces it to its configured peers; stop the node first (see the flag's own doc comment in main.rs for why)
cargo run --bin tri_sync_node -- node.toml --propose-add-peer <id> <addr> <pubkey_hex>   # signs and broadcasts a membership-change proposal to add a peer
cargo run --bin tri_sync_node -- node.toml --propose-remove-peer <id>                     # same, to remove one
```

The last two only ever *propose* a change - broadcasting one changes
nothing by itself. It takes effect only once whichever peer becomes
proposer next attaches it to a block that goes on to earn a real
precommit quorum-certificate under the network's actual current
membership, exactly like any other block - see `tri_sync_node::
consensus`'s module doc comment on dynamic membership for the full
mechanism.

### Issuing licenses

```bash
cargo run --bin tri_sync_node_license_tool -- generate-key
# public_key_hex  = ...
# private_key_hex = ...   (shown once; move it into your own secret
#                           storage immediately - this tool never
#                           persists it anywhere)

cargo run --bin tri_sync_node_license_tool -- sign \
  --private-key <hex> --org "Acme Corp" --max-nodes 5 \
  --expiry 2027-01-01 --features "chain_crypto,http_api" \
  --out acme-license.toml
```

`generate-key` never runs as a side effect of anything else in this
repository - the private key it prints is the actual secret that will
let anyone sign a license as you, so it's produced only when you ask
for it, shown exactly once, and never written to disk by this tool.
Run it yourself, on a machine you trust, and set
`LICENSE_PUBLIC_KEY_HEX` in `tri_sync_node/src/license.rs` to the
`public_key_hex` it prints before relying on it for a real customer.
`sign` rejects a malformed private key or an expiry date that doesn't
exist on the calendar, and verifies its own output against the
signing key's public half before ever printing or writing it - a
license this tool can't verify is never handed back.

### Testing

```bash
cargo test --workspace     # includes tri_sync_core and tri_sync_node
cargo clippy --workspace --all-targets -- -D warnings
```

`tri_sync_node`'s own test suite (139 tests at time of writing) covers
each message handler directly with real Ed25519 keys and real
`view_block_canon`/`block_canon` signing - not mocks - including a
dedicated adversarial-input test for every bug this project's own
focused code-review passes have found (forged signatures, replayed/
escalating views, malformed peer keys, a flooding expected proposer),
plus one real two-process end-to-end test that spins up two actual OS
processes talking QUIC over real sockets and asserts they converge on
the same committed chain.

### Known limitations and roadmap

Disclosed plainly, not glossed over - the authoritative, always-current
version of this list is `tri_sync_node::consensus`'s own module doc
comment. Five items in this family have been identified and closed, as
a demonstration that "disclosed" items get revisited and actually
fixed once genuinely scoped, rather than forgotten or left as a
permanent asterisk:

- **BFT locking / quorum certificates.** The liveness fallback
  (view-change) used to let a node advance past a stalled proposer
  while only *locking* its vote implicitly - by however far signature/
  expected-proposer checks let it advance, never via a real
  quorum-certificate proof that an earlier view genuinely failed. In
  an adversarial or badly-partitioned network that left a real window
  where votes could split across two views' candidates for the same
  height. Closed with a real two-phase prevote/precommit protocol: a
  node only locks once its own prevote tally for a (block, view) pair
  reaches quorum - a genuine polka, not a claim - and a block commits
  only once a *precommit* quorum (domain-separated signatures,
  never replayable from a prevote) is reached. Proven, not just
  implemented: a dedicated test drives two disjoint, individually
  legitimate candidates for the same height through a real 4-node
  quorum and confirms only one of them can ever reach a precommit QC.
- **TLS transport identity.** The QUIC transport used to encrypt every
  connection with a throwaway, unrelated certificate and accept any
  server certificate at all - confidentiality with zero peer
  authentication, resting entirely on message-level signing instead.
  Closed: each node's certificate is now generated from its real
  Ed25519 identity key, and every outbound connection is pinned to the
  specific peer being dialed, rejecting a real, validly self-signed
  certificate for the wrong identity before a single message is sent.
- **Chain-sync.** A node behind on an already-*committed* height (not
  merely a view, which the liveness fallback already handled) used to
  have no recovery path at all. Closed: `handle_proposal` triggers a
  debounced sync request the moment it sees evidence it's behind;
  every synced block is verified independently of whoever relayed it
  (content hash plus a real reconstructed precommit quorum), never
  trusted merely because the response envelope was validly signed.
- **Resource exhaustion.** `RoundState`'s candidate/vote maps are now
  capped (`MAX_CANDIDATES_PER_HEIGHT`) against a legitimate-but-malicious
  expected proposer signing unboundedly many distinct blocks for the
  same (height, view).
- **Dynamic peer membership.** `--rotate-key` only ever updates the
  *key* of an already-configured peer id; by itself it never touched
  `all_ids`/quorum/`network_size`, which used to stay exactly as
  `node.toml` originally described for the life of the process. Closed
  by piggybacking an `Add`/`Remove` change onto the ordinary
  block-commit path instead of building a separate agreement protocol
  for it: the change is part of the block's own signed identity, and
  `apply_membership_change` only ever runs *after* that block has
  independently earned a real precommit quorum-certificate under the
  membership as it stood before the change - so no node can unilaterally
  grow or shrink its own voting power, and the mechanism inherits
  quorum-certificate locking and chain-sync for free rather than
  needing its own copy of either. `--propose-add-peer`/
  `--propose-remove-peer` give an operator a way to get a change
  proposed promptly; a dedicated test proves the actual safety property
  (a change never takes effect without a real quorum) as well as the
  live effect (the quorum enforced for the *next* height genuinely
  rises or falls once a change commits, and chain-sync replays a
  historical change exactly like a live commit would).

Each of the five above has a dedicated test proving the actual
property closed, not just that the new code runs.

## License

All rights reserved by default - see [LICENSE.md](LICENSE.md). Public
visibility of this repository does not grant any right to use, copy,
modify, or redistribute it. Four separate license tiers (non-commercial
source, commercial, internal-use, and open-reference) can be granted in
writing by the copyright holder - see `LICENSE.md` for what each
permits and which parts of the repository they cover. This crate is
not published to crates.io (`publish = false`) and carries no
open-source license.
