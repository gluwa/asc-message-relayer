# asc-message-relayer

[![CI](https://github.com/gluwa/asc-message-relayer/actions/workflows/ci.yml/badge.svg)](https://github.com/gluwa/asc-message-relayer/actions/workflows/ci.yml)

Off-chain relayer for **USC write-ability** — Creditcoin's cross-chain messaging. It carries
messages published on Creditcoin to destination EVM chains (attestor-vote-based), and carries
delivery acknowledgments back to Creditcoin (native-proof-based). It holds **no protocol
authority**: everything it submits is either verified on-chain against attestor signatures or
against Creditcoin's native proving — a malicious relayer can censor (until another relayer picks
the message up), but cannot forge.

```
        Creditcoin L1                                        Destination chain (e.g. Sepolia)
  ┌─────────────────────────┐                             ┌──────────────────────────────────┐
  │ dApp ── publishMessage ─► Outbox                      │            Inbox ── receiveMessage ─► dApp
  │            (MessagePublished event)                   │              ▲                    │
  └────────────┬────────────┘                             └──────────────│────────────────────┘
               │  eth_getLogs                                            │ deliverMessage(votes)
               ▼                                                         │ (EOAValidator checks
  attestors (N) ── observe, ECDSA-sign messageHash ──┐                   │  2N/3+1 signatures)
               │                                     │                   │
               │        libp2p gossipsub             ▼                   │
               └──────► {chain_key}/message-votes/v1 ──► RELAYER: pool ──┘
                                                          (aggregate to threshold)

  ack path (reverse):  Inbox MessageDelivered ──► RELAYER: fetch native USC proof from proof-gen
                        ──► AcknowledgmentValidator.submitAcknowledgment on Creditcoin
                        ──► Outbox.acknowledgeMessage  (proof is self-validating)
```

## How a message flows (outbound)

1. **Publish** — a dApp on Creditcoin calls `Outbox.publishMessage(canAck, payload)`; the
   Outbox emits `MessagePublished(messageId, emitter, canAck, payload)`.
2. **Index** — the relayer's per-route *outbox watcher* polls Creditcoin EVM (`eth_getLogs`,
   cursor + confirmation depth, 5 000-block chunks) and inserts an `IndexedMessage` into the vote
   pool. Indexing establishes the **chain-first allowlist**: votes for a `messageHash` the relayer
   has not seen on-chain are dropped on arrival.
3. **Vote** — each attestor independently observes the same event (after its own confirmation
   depth), signs the raw 32-byte `messageHash` with its EVM secp256k1 key (no EIP-191 prefix), and
   gossips a `MessageVote` on `{chain_key}/message-votes/v1`.
4. **Aggregate** — the pool validates every vote (decode → `ecrecover` → signer ∈ attestor
   allowlist → dedup) and counts distinct signers. At threshold — `⌊2N/3⌋+1` — it encodes the
   votes and dispatches a `DeliveryJob`.
5. **Deliver** — the per-route *delivery worker* (optionally) simulates
   `Inbox.deliverMessage(messageId, emitter, payload, votes)`, then sends it. The Inbox's
   `EOAValidator` re-verifies every signature on-chain and the Inbox invokes the destination
   dApp's `receiveMessage`. If that callback reverts, the tx still succeeds but the Inbox emits
   `MessagePending` instead of `MessageDelivered` and stores the message for permissionless
   `retryPendingMessage` retries.
6. **Acknowledge & settle** (optional) — the *ack submitter* watches the destination for
   `MessageDelivered`/`MessagePending`, fetches a **native USC proof** of that transaction from
   the proof-gen API, and submits it to `AcknowledgmentValidator` on Creditcoin (verified against
   the block-prover precompile) for `canAck=true` messages — and, when the route has a
   `RelayerContract` configured, calls `RelayerContract.claimDelivery` to pay the relay fee to
   whoever delivered. The claim proof is always built from the *original* `deliverMessage` tx —
   `MessagePending` is itself a payable, provable outcome, so a message that ever goes pending
   still settles its fee without waiting on (or requiring) a retry to succeed. Both settlements
   are permissionless: the proof, not the sender, is what's trusted.

### The messageHash

Everything keys on one hash, computed identically by the Outbox-side contracts, the attestors,
this relayer, and the destination Inbox (`computeMessageHash`):

```
keccak256(abi.encode(messageId, emitterAddress, destinationChainKey, creditcoinChainId, payload))
```

`destinationChainKey` is the route's `u64` chain key left-encoded into `bytes32`. The
implementation lives in the shared [`write-ability`](write-ability/) crate and is pinned by
golden-vector tests in **both** this repo and the attestor's (see
[write-ability/README.md](write-ability/README.md) for the sync contract — read it before
touching anything on the wire path).

## Worker inventory

One tokio task per box, joined in a supervisor `JoinSet`; a single `CancellationToken` fans out
shutdown, and any worker exiting tears the process down (fail-fast, restart by the orchestrator).
Workers communicate over `mpsc` channels only — the pool owns all aggregation state, unshared.

| Worker | Source | Purpose |
|---|---|---|
| Outbox watcher (per route) | `src/events/` | Resolve the route's Outbox (static or on-chain factory lookup, re-checked periodically), poll `MessagePublished`, feed the pool's allowlist |
| Vote pool (one) | `src/pool/` | Validate + aggregate votes, dispatch deliveries, emit reobservation requests, serve `/votes` queries |
| p2p worker (one swarm) | `src/p2p/` | gossipsub mesh with the attestors: receive votes, publish reobservation requests |
| Delivery worker (per route) | `src/delivery/` | Simulate + send `deliverMessage`, classify outcomes, bounded retries |
| Ack submitter (per route, opt-in) | `src/ack/` | `MessageDelivered`/`MessagePending` → proof-gen → `submitAcknowledgment` + `claimDelivery` |
| Claim submitter (per route, opt-in) | `src/claim/` | bridge `Locked` → proof-gen → `CcBridge.claim` on Creditcoin ("relayer on both sides": users only send the lock tx) |
| Attestor-set watcher (per on-chain route) | `src/attestor_set.rs` | Poll `EOAValidator.attestors()/threshold()` every 30 s, hot-reload the pool |
| HTTP + metrics | `src/prom/` | `/health`, `/metrics`, `/votes/{message_hash}` |

## Liveness & failure semantics

The relayer is designed to make **every failure either self-heal or terminate loudly** — never
retry silently forever:

- **Reobservation** (`{chain_key}/reobservation-requests/v1`) — a message stuck below quorum for
  60 s triggers a gossiped `ReobservationRequest` (rate-limited per message). Attestors re-fetch
  the named transaction *from their own RPC*, re-verify against their own resolved Outbox, and
  re-sign — the request is unauthenticated and cannot make an attestor sign anything it can't
  independently confirm. This recovers votes lost to gossip partitions, attestor restarts, and
  observation-lag spread.
- **Delivery retries** — RPC-level retries with exponential backoff inside the worker
  (`delivery.max_retries`), then a bounded pool-level redispatch (5 attempts, 30 s → 5 min
  backoff). Deterministic reverts are terminal immediately; `"Already validated"` (lost the race
  to another relayer) is idempotent success.
- **Revert classification is node-agnostic** (`src/revert.rs`) — nodes word reverts differently
  (geth: `execution reverted`; Creditcoin's EVM RPC: `VM Exception … revert, data: "0x<selector>"`),
  so classification extracts the raw 4-byte custom-error selector and compares against the shared
  ABI's `SolError::SELECTOR` constants, with phrase and error-name fallbacks. String-matching
  decoded names alone *will* misclassify deterministic reverts as transient and loop forever.
- **Ack lifecycle** — `BlockNotReady` (proof not attested yet) defers on a steady 15 s cadence
  without penalty, bounded by a 24 h give-up; transient submit failures back off 30 s → 10 min and
  give up loudly after 20 attempts (the unfunded-signer failure mode); reverts bubbling from the
  Outbox (`MessageCannotBeAcknowledged`, `MessageAlreadyAcknowledged`, …) are terminal. A
  **canAck pre-check** reads the Outbox state first, so bridge-style `canAck=false` traffic costs
  a view call instead of a proof fetch + guaranteed-revert estimate — tagged per-message at
  discovery time against whichever Outbox is currently resolved (next bullet), so it is immune to
  a later Outbox rotation retroactively changing which contract an already-queued message is
  checked against.
- **Outbox resolution follows rotation** — every route resolves its Outbox from the chain key
  alone: a chain-info precompile lookup for the `OutboxDiscovery` registry address, then
  `defaultOutbox(chainKey)` on that registry (asc-contracts#38) — no operator-supplied address, no
  factory log scan. Re-checked periodically, so a registry-level rotation (`setDefaultOutbox`) is
  picked up without a restart. New discovery moves to the new address; already-indexed/pending
  work is unaffected. A chain key with no discovery address registered fails closed.
- **Checkpoints + startup lookback** — block cursors persist to `--checkpoint-path` so restarts
  never skip events. Because votes and pending acks are memory-only, cursors are rewound by
  `scan_lookback_blocks` (default 600) on startup: in-flight work is re-discovered, and
  already-finished work resolves idempotently (delivered → `Already validated` at simulate,
  acked → skipped by the pre-check). The Outbox watcher's checkpoint additionally records which
  Outbox address it was scanned against, so a restart can tell a valid long-running cursor apart
  from one left over from a since-rotated-away Outbox. Outbox resolution itself persists nothing —
  a registry read is complete and authoritative on every call, so there is no scan cursor to
  resume.
- **Bounded everything** — vote cache (TTL + LRU cap), pending-ack queue (cap 10 000, oldest
  evicted), per-tick ack batch (256) and concurrency (8), 5 000-block `eth_getLogs` chunks (an
  over-large resume range would error on every tick forever on range-capped RPCs), 120 s receipt
  timeouts (one stuck underpriced tx cannot wedge a route's serial worker).

## Trust & key model

| Key | Chain | Needs | Notes |
|---|---|---|---|
| `routes[].signer_key` | destination | gas | pays for `deliverMessage`; no authority — votes are what's verified |
| `routes[].ack.signer_key` | Creditcoin | gas | pays for `submitAcknowledgment`; permissionless, proof is self-validating |
| `p2p.identity` | — | stability only | ed25519 seed/mnemonic for a stable PeerId; ephemeral if unset |

Vote validation is defense-in-depth: chain-first allowlist (must be indexed from the Outbox) →
signature recovery → signer must be in the attestor set → per-signer dedup → threshold. A false
quorum requires compromising `⌊2N/3⌋+1` attestor keys; the relayer adds no trusted party.

## Configuration

Three layers, in precedence order: CLI flags / env vars → YAML file. See
[config.example.yaml](config.example.yaml) for the fully-commented reference of every YAML key.

```bash
# YAML-driven (production shape):
message-relayer \
  --config config.yaml \
  --creditcoin-eth-rpc-url https://rpc.usc-devnet.creditcoin.network \
  --checkpoint-path /data/relayer-checkpoints.json

# Single-route quickstart (dev, no file):
message-relayer --single-route \
  --chain-key 7 --cc3-chain-id 102035 \
  --creditcoin-eth-rpc-url http://localhost:9944 \
  --inbox-address 0x… \
  --destination-rpc-url http://localhost:8545 \
  --signer-key 0x… \
  --attestor-set 0xA…,0xB…,0xC…
```

Every flag has a `RELAYER_*` env twin (`--help` lists them); `.env` is loaded via dotenvy.
Ack flags (`--ack-proof-gen-url`, `--ack-validator-address`, `--ack-signer-key`) must be set
together or not at all. `--checkpoint-path ""` disables persistence (watchers start at head).
`--verbose` switches `info` → `debug` logging. A few poll cadences are env-only (no CLI flag,
sensible defaults): `RELAYER_ACK_POLL_SECS`, `RELAYER_CLAIM_POLL_SECS`,
`RELAYER_OUTBOX_RESOLVE_POLL_SECS` (how often a route re-checks the discovery registry for an
Outbox rotation, default 60 s).

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness (200 when the process is up) |
| `GET /metrics` | Prometheus/OpenMetrics |
| `GET /votes/{message_hash}` | vote bundle for a message: signers seen, threshold, delivered flag — lets an operator (or a sibling relayer) inspect aggregation state |

Key metrics: `relayer_messages_indexed`, `relayer_votes_received` (by outcome),
`relayer_votes_per_message`, `relayer_deliver_tx` (by status: submitted / succeeded /
already-validated / pending / reverted), `relayer_time_to_threshold_seconds`,
`relayer_time_to_deliver_seconds`, `relayer_pool_messages_pending`, `relayer_attestor_set_size` /
`relayer_attestor_set_reloads`, `relayer_p2p_peer_count`, `relayer_ack_submissions` /
`relayer_claim_submissions` (by outcome: confirmed / terminal / failed — `submitAcknowledgment` and
`claimDelivery` respectively; watch `failed` for a stuck settlement path, since delivery keeps
working independently of either), plus process gauges.

## Build, test, run

```bash
cargo build --release            # binary at target/release/message-relayer
cargo test --workspace           # unit + protocol golden vectors
cargo clippy --all-targets       # lint (CI-enforced)
cargo fmt --all                  # format
taplo format                     # TOML format (config in .taplo.toml)
```

Integration tests behind the `integration-tests` feature (`tests/e2e_anvil.rs`) expect a local
anvil; the golden-vector tests (`tests/golden_hash.rs`) run everywhere and are the drift guard
for the wire protocol.

### Docker

```bash
docker build -t gluwa/asc-message-relayer:$(git rev-parse --short HEAD) .
# from Apple Silicon for an amd64 cluster:
docker buildx build --platform linux/amd64 -t gluwa/asc-message-relayer:<sha> --push .
```

Two-stage build; runtime is `debian:bookworm-slim` with the binary at `/bin/message-relayer`
(plus a shell — required by the Helm chart's secret-substitution wrapper). Tag images with the
git SHA so what's running is never ambiguous.

CI publishes images automatically (`.github/workflows/release.yml`): every push to `main` →
`gluwa/asc-message-relayer:main` + `:main-<sha>`; every `v*` tag → `:vX.Y.Z` + `:latest`, plus a
GitHub Release with the linux-amd64 binary. Pull requests run fmt / clippy (`-D warnings`) /
taplo / cargo-machete / tests / a no-push Docker build (`ci.yml`). Publishing requires the
`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo secrets.

### Kubernetes

Deployed via the `creditcoin-message-relayer` Helm chart (in `cc-networks-iac`). The chart mounts
the YAML config from a ConfigMap, substitutes `${…}` placeholders from mounted Secret files
(signer keys, keyed RPC URLs, p2p identity), passes the Creditcoin RPC URLs via env, and persists
checkpoints on a PVC. Point `image.repository`/`image.tag` at this repo's image; the chart
overrides the entrypoint so no other change is needed.

## Repository layout

```
message-relayer/         the relayer crate
  bin/relayer.rs         CLI entrypoint (clap; --config or --single-route)
  src/lib.rs             Server: worker wiring, channels, supervisor JoinSet
  src/config.rs          YAML schema + validation (see config.example.yaml)
  src/events/            Outbox watcher + outbox resolver (discovery-registry resolution only;
                         see events/factory.rs)
  src/pool/              vote aggregation state machine (allowlist, threshold, retries,
                         reobservation triggers, /votes queries, hot set-reload)
  src/p2p/               libp2p swarm: gossipsub topics, envelope codecs, peer metrics
  src/delivery/          deliverMessage submission + outcome classification + votes calldata
  src/ack/               acknowledgment submitter (proof-gen client, pending queue, backoff)
  src/attestor_set.rs    on-chain attestor-set hot-reload watcher
  src/revert.rs          node-agnostic revert classification (selector extraction)
  src/checkpoint.rs      persisted block cursors
  src/prom/              metrics registry + HTTP router
  tests/                 golden vectors, abuse/race tests, anvil e2e (feature-gated)
write-ability/           vendored shared protocol crate — READ ITS README BEFORE EDITING
config.example.yaml      fully-commented configuration reference
Dockerfile               two-stage image build
```

## Known gaps

- **`cc3_active_set` attestor source is unimplemented** — use `evm_contract` (hot-reloaded) or
  `static`.
- **Generic intent target** — the claim submitter currently targets the bridge PoC's
  `CcBridge.claim`; when the reviewed `IUSCBridgeInbound.bridgeFromIntent` contracts deploy, the
  swap is an ABI + config change confined to `src/claim/` (identical proof arguments).
- **Outbox resolution depends on an unmerged creditcoin3 branch** — the
  `get_outbox_discovery_address` chain-info precompile getter `DiscoveryResolver` calls only exists
  on `writeability-off-usc-dev`, not yet on `main`/`usc-dev`. **A route on a network without the
  precompile, or whose chain key has no discovery address registered via
  `set_outbox_discovery_addr`, cannot resolve an Outbox at all** and fails closed by default.
  Confirm both are in place — precompile deployed, discovery address registered and pointing at
  the `OutboxDiscovery` proxy from asc-contracts#38 — before pointing this relayer at a network.
  `outbox_address` (route config / `--outbox-address`) is an operator-pinned escape hatch for
  exactly that gap or an incident — see `events/factory.rs`'s module docs — but it bypasses the
  registry entirely, so treat it as temporary and logged (WARN) loudly while set, not a substitute
  for registering the chain key properly.
