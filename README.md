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
- **Outbox resolution follows rotation** — a route with no `outbox_address` configured resolves
  its Outbox from the chain key alone (on-chain factory lookup + `OutboxCreated` log scan) and
  re-checks periodically, so a factory-level Outbox rotation is picked up without a restart. New
  discovery moves to the new address; already-indexed/pending work is unaffected.
- **Checkpoints + startup lookback** — block cursors persist to `--checkpoint-path` so restarts
  never skip events. Because votes and pending acks are memory-only, cursors are rewound by
  `scan_lookback_blocks` (default 600) on startup: in-flight work is re-discovered, and
  already-finished work resolves idempotently (delivered → `Already validated` at simulate,
  acked → skipped by the pre-check). The Outbox watcher's checkpoint additionally records which
  Outbox address it was scanned against, so a restart can tell a valid long-running cursor apart
  from one left over from a since-rotated-away Outbox. `FactoryResolver`'s own `OutboxCreated`
  discovery scan (against the factory contract, not the Outbox) persists the same way, under the
  same checkpoint file: a restart resumes that scan instead of rescanning the factory's full log
  history from genesis, and a checkpoint recorded against a factory since rotated away from is
  discarded rather than reused.
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
  --outbox-address 0x… --inbox-address 0x… \
  --destination-rpc-url http://localhost:8545 \
  --signer-key 0x… \
  --attestor-set 0xA…,0xB…,0xC…
```

Every flag has a `RELAYER_*` env twin (`--help` lists them); `.env` is loaded via dotenvy.
Ack flags (`--ack-proof-gen-url`, `--ack-validator-address`, `--ack-signer-key`) must be set
together or not at all. `--checkpoint-path ""` disables persistence (watchers start at head).
`--verbose` switches `info` → `debug` logging. A few poll cadences are env-only (no CLI flag,
sensible defaults): `RELAYER_ACK_POLL_SECS`, `RELAYER_CLAIM_POLL_SECS`,
`RELAYER_OUTBOX_RESOLVE_POLL_SECS` (how often a factory-resolved route re-checks for an Outbox
rotation, default 60 s). `RELAYER_FACTORY_ROTATION_RESUME_FROM_CHECKPOINT` (bool, default `true`)
controls how a factory-resolved route reacts to a rotation: by default it resumes the newly-current
factory's `OutboxCreated` scan from the block height the previous factory's scan had already
reached, instead of rescanning that factory's full history from genesis — cheap because nothing
before that height could have driven a delivery through the not-yet-current Outbox. Set to `false`
to force the always-genesis behavior, e.g. if a factory can have a permissionless `deployOutbox`
predating the rotation itself.

That resume is an assumption — that the rotated-to factory was itself deployed at rotation time —
and it is now self-correcting when wrong. A scan that reaches the confirmed tip having matched
nothing, and that started above the configured genesis block, **rewinds once and rescans from that
floor** before reporting "no Outbox" (logged as `🪃 no OutboxCreated found above the resumed
checkpoint`). Without it, re-pointing a chain key at a *pre-existing* factory strands it
permanently: the cursor is persisted at the tip against that factory, so it reads back as a valid
checkpoint and a restart entrenches the failure instead of clearing it. The rewind fires at most
once per factory, so a factory that genuinely has no Outbox costs one extra scan and then settles.

Expect that one-time rewind on the first resolve after upgrading to a build with this fallback,
too, for any chain key whose checkpoint predates it and still has no Outbox: a bare pre-upgrade
record carries no floor of its own, so it loads with one assumed at its cursor — the same reading
that heals a rotation stranded on an older build. There is no way to tell that healthy "no Outbox
yet" cursor apart from a stranded one after the fact, so both get the one rescan; a single `🪃` per
still-Outbox-less chain key on upgrade day is expected, not an incident.

`RELAYER_FACTORY_SCAN_GENESIS_BLOCK` (u64, default `0`) is the block every *from-scratch*
`OutboxCreated` scan starts at — a first boot with no checkpoint, a rotation with the flag above
disabled, and the rewind. Raising it to a height known to precede the chain key's factory
deployment is what makes those scans cheap on a long-lived chain. It is a floor for scans with **no**
position, never a rewind of one that has it: a persisted checkpoint, or a rotation resuming from
one, is kept even when it sits below this value. Set it *above* a factory's `OutboxCreated` and that
Outbox becomes undiscoverable, the rewind included — so use a height that precedes every factory the
chain key will be pointed at.

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
  src/events/            Outbox watcher + outbox resolver (static outbox_address, or on-chain
                         factory-based resolution when it's omitted; see events/factory.rs)
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
- **Outbox resolution depends on unmerged creditcoin3 branches** — `FactoryResolver` calls two
  chain-info precompile getters, `get_outbox_factory_address` and `get_outbox_discovery_address`,
  that only exist on `writeability-off-usc-dev` (the latter not yet merged even there), not on
  `main`/`usc-dev`. Until both merge and deploy, routes need an explicit `outbox_address` on any
  network where the precompile isn't available — see `resolve_from_precompile_registry` for the
  registry-first path the discovery getter unlocks once it's live.
