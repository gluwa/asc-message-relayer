# asc-message-relayer

[![CI](https://github.com/gluwa/asc-message-relayer/actions/workflows/ci.yml/badge.svg)](https://github.com/gluwa/asc-message-relayer/actions/workflows/ci.yml)

Off-chain relayer for **USC write-ability** — Creditcoin's cross-chain messaging. It carries
messages published on Creditcoin to destination EVM chains (attestor-vote-based), and carries
delivery acknowledgments back to Creditcoin (native-proof-based). It holds **no protocol
authority**: everything it submits is either verified on-chain against attestor signatures or
against Creditcoin's native proving — a malicious relayer can censor (until another relayer picks
the message up), but cannot forge.

```text
        Creditcoin L1                                        Destination chain (e.g. Sepolia)
  ┌─────────────────────────┐                             ┌──────────────────────────────────┐
  │ dApp ── publishMessage ─► Outbox                      │            Inbox ── receiveMessage ─► dApp
  │            (MessagePublished event)                   │              ▲                    │
  └────────────┬────────────┘                             └──────────────│────────────────────┘
               │  eth_getLogs                                            │ deliverMessage(votes)
               ▼                                                         │ (EOAValidator checks
  attestors (N) ── observe, ECDSA-sign messageId ──┐                   │  2N/3+1 signatures)
               │                                     │                   │
               │        libp2p gossipsub             ▼                   │
               └──────► {chain_key}/message-votes/v1 ──► RELAYER: pool ──┘
                                                          (aggregate to threshold)

  ack path (reverse):  Inbox MessageExecuted ──► RELAYER: fetch native USC proof from proof-gen
                        ──► AcknowledgmentValidator.submitAcknowledgment on Creditcoin
                        ──► Outbox.acknowledgeMessage  (proof is self-validating)
```

## How a message flows (outbound)

1. **Publish** — a dApp on Creditcoin calls `Outbox.publishMessage(canAck, payload)`; the
   Outbox emits `MessagePublished(messageId, emitterAddress, sequence, canAck, payload)`.
2. **Index** — the per-route source watcher scans finalized Creditcoin logs in bounded ranges,
   authorizes each emitting Outbox against historical governance state, and persists the full
   message before advancing its cursor. This establishes the chain-first allowlist: votes for a
   message ID not indexed from an authorized publication are not counted.
3. **Vote** — attestors independently authorize the source publication and sign the raw 32-byte
   `messageId` with their EVM secp256k1 keys, without an EIP-191 prefix. Votes travel over
   `{chain_key}/message-votes/v1`.
4. **Aggregate** — the pool validates each vote (decode, recover signer, check current attestor
   membership, deduplicate). At `⌊2N/3⌋+1` distinct signers, it dispatches a `DeliveryJob`.
5. **Deliver and recover execution** — the delivery worker sends
   `Inbox.deliverMessage(messageId, outbox, emitter, sequence, payload, votes)` after preflighting
   the exact transaction gas limit. Optional early simulation provides an additional check.
   The payload envelope is `abi.encode(destination, nativeCoinValue, gasLimit, payloadData)`:
   the relayer fronts `nativeCoinValue` subject to route caps, and the dispatcher forwards the
   attested execution gas. `MessageReceived` establishes acceptance; `MessageExecuted` confirms
   execution. `MessageQueued`/`MessageDeferred` and `DestinationFailed` retain durable work for
   permissionless `retryPendingMessage` or `retryFailedMessage`. Restart reconstructs this state
   from the Inbox, and confirmed execution is required before removing the durable record.
6. **Acknowledge and settle** (optional) — the ack worker proves destination `MessageExecuted`
   logs and submits each proof to the original Outbox's current acknowledgment validator.
   With a configured `RelayerContract`, it independently proves the original delivery's
   `MessageReceived`, `MessageQueued`, or `MessageDeferred` outcome to claim relay fees, even
   while execution needs recovery. A successful retry's execution log can settle the ack but
   does not replace the original fee-claim proof. Both submissions are permissionless; finalized
   source acknowledgment and fee state must confirm completion before work leaves the queue.

### Message ID and signed digest

The Outbox computes the ID, and the Inbox verifies the same original-publication binding:

```text
messageId = keccak256(abi.encode(outbox, emitter, sequence, keccak256(payload), sourceChainId))
```

Here `outbox` and `emitter` are addresses, `sequence` is `uint64`, and `sourceChainId` is the
Creditcoin EVM chain ID encoded as `uint256`. Attestors sign `messageId` directly; there is no
second message hash or signing prefix. The destination chain key scopes the route, Outbox,
validator, and gossip topic rather than adding another field to this digest. Shared wire and
ABI bindings live in [`write-ability`](write-ability/); both attestor and relayer must agree on
these formats.

## Worker inventory

One tokio task per box, joined in a supervisor `JoinSet`; a single `CancellationToken` fans out
shutdown, and any worker exiting tears the process down (fail-fast, restart by the orchestrator).
Workers communicate over `mpsc` channels only — the pool owns all aggregation state, unshared.

| Worker | Source | Purpose |
| --- | --- | --- |
| Outbox watcher (per route) | `src/events/` | Scan finalized `MessagePublished` across historically authorized Outboxes, journal work, feed the pool |
| Vote pool (one) | `src/pool/` | Validate + aggregate votes, dispatch deliveries, emit reobservation requests, serve `/votes` queries |
| p2p worker (one swarm) | `src/p2p/` | gossipsub mesh with the attestors: receive votes, publish reobservation requests |
| Delivery worker (per route) | `src/delivery/` | Preflight delivery/retries, reconcile confirmed execution, retain retryable work |
| Ack submitter (per route, opt-in) | `src/ack/` | Execution/acceptance logs → proof-gen → original-Outbox acknowledgment + independent fee claim |
| Claim submitter (per route, opt-in) | `src/claim/` | bridge `Locked` → proof-gen → `CcBridge.claim` on Creditcoin ("relayer on both sides": users only send the lock tx) |
| Attestor-set watcher (per on-chain route) | `src/attestor_set.rs` | Poll `EOAValidator.attestors()/threshold()` every 30 s, hot-reload the pool |
| HTTP + metrics | `src/prom/` | `/health`, `/metrics`, `/votes/{message_hash}` |

## Liveness & failure semantics

Retryable work remains recoverable across outages and restarts. Capped backoff bounds RPC load,
and repeated failures escalate in logs and metrics:

- **Reobservation** (`{chain_key}/reobservation-requests/v1`) — a message stuck below quorum for
  60 s triggers a gossiped `ReobservationRequest` (rate-limited per message). Attestors re-fetch
  the named transaction *from their own RPC*, re-verify historical Outbox authorization, and
  re-sign — the request is unauthenticated and cannot make an attestor sign anything it can't
  independently confirm. This recovers votes lost to gossip partitions, attestor restarts, and
  observation-lag spread.
- **Delivery retries** — RPC retries inside a worker attempt are bounded by
  `delivery.max_retries`; unresolved work then returns to the supervised pool with capped
  backoff. Five dispatch failures escalate warnings instead of abandoning the message.
  Mutable-state reverts (pause, expired quorum, policy or validator changes) remain retryable.
  `MessageAlreadyValidated` triggers confirmed Inbox-state reconciliation: it can mean executed,
  queued, or failed, so acceptance alone is not success.
- **Execution outcomes** — `MessageQueued`/`MessageDeferred` select `retryPendingMessage`, and
  `DestinationFailed` selects `retryFailedMessage`. Pending obligations stay in the durable work
  store until confirmed execution, without a fixed lifetime budget. `retryFailedMessage` is
  bounded, because a destination that reverts deterministically never succeeds and every attempt
  pays for its execution: exponential backoff (`delivery.failed_retry_initial_backoff_secs`,
  default 60 s, doubling to `failed_retry_max_backoff_secs`, default 4 h), at most
  `failed_retry_max_attempts` (default 5) attempts, all overridable per route. Past the budget the
  work is dropped with a `destination_failed` outcome, a WARN and
  `relayer_destination_failed_retries_exhausted_total`; the message stays retryable on-chain for
  anyone. The attempt count is persisted next to the durable work
  (`<checkpoint>.messages/<chain_key>/failed/`), so restarts and rescans do not reset it.
  `RetryDeferred(retryAfter)` can push the next attempt later. Permanent envelope/cap failures remain
  explicit refusal outcomes. Gas escalation stays within the route cap, and every broadcast
  preflights the final transaction gas limit. `relayer_deliver_tx{status="Unclassified"}` identifies
  mined reverts whose selector is not recognized; those remain retryable.
- **Under-funded deliveries** — when the estimate exceeds the funded `gasLimit` the job waits
  for a `topUpGasLimit` (bounded by the delivery deadline / settlement). With
  `auto_request_top_up: true` the route additionally emits
  `RelayerContract.requestTopUp(messageId, additionalGasNeeded)` on Creditcoin once per message
  from the ack (else claim) signer, so the payer/quoter learns the shortfall on-chain. Off by
  default: the call is permissionless and sending it is relayer policy.
- **Revert classification is node-agnostic** (`src/revert.rs`) — nodes word reverts differently
  (geth: `execution reverted`; Creditcoin's EVM RPC: `VM Exception … revert, data: "0x<selector>"`),
  so classification extracts the raw 4-byte custom-error selector and compares against the shared
  ABI's `SolError::SELECTOR` constants, with phrase and error-name fallbacks. These selectors
  distinguish retry outcomes, gas escalation, and cases needing on-chain state reconciliation.
- **Ack lifecycle** — proofs that are not ready yet (proof-gen 422 or 404) are re-polled at
  `ack.not_ready_poll_secs` (default 20 s) for `ack.not_ready_poll_window_secs` (default 30 min),
  then back off to a capped 10 min cadence. After 24 h, overdue proofs trigger warnings and
  remain pending. Transient submit failures similarly retain work and escalate after 20 attempts.
  A proof request that proof-gen permanently refuses (HTTP 4xx with `retriable: false`, e.g.
  `ArchiverRangeRejected`) is counted as `outcome="Rejected"` on `relayer_ack_proof_fetches_total`,
  logged with proof-gen's own message, and retried at the capped 10 min cadence without climbing
  the transient ramp; the settlement is retained, never dropped, so it settles once proof-gen or
  its archiver is fixed. A full queue applies scan backpressure; the checkpoint stays behind unfinished settlements so
  restart can recover them. A receipt or revert alone never releases an executed acknowledgment
  or funded relay fee: source state must confirm settlement at `finalized`.
- **Settlement across Outbox rotations** — recover every Outbox ever supported by the destination
  Inbox, including removals, from bounded authorization-log scans back to genesis. Persist this
  history beside the checkpoint independently of `ack.start_block`. Each message ID is bound to
  its original source publication before checking `canAck` or selecting that Outbox's current
  validator. One destination transaction can settle multiple validators independently; an unknown
  route or failed RPC retains the obligation. The configured acknowledgment validator is only a
  discovery hint. Fee ledgers remain explicitly configured per route.
- **All historically authorized Outboxes** — source scans query every `MessagePublished` emitter,
  then read the governance-selected Discovery and `isActiveOutbox(chainKey, emitter)` at that
  message's finalized source block. Default changes, scheduled removal, cancellation,
  re-registration and Discovery replacement do not reset the cursor or discard valid history.
  The effective removal block is excluded, matching the attestor's block-end policy. Historical
  `eth_call` support is required: missing state, RPC failures and malformed authorized events
  stop progress for retry. Unregistered spoof emitters are ignored before decoding their data.
  A result-limit error shrinks the log range; one dense block falls back to checked receipts.
  Production source scans pause if finalized state is unavailable, regresses or stalls.
- **Source checkpoint migration** — a new `outboxes:<chain-key>` checkpoint covers the complete
  source scope. Legacy `outbox:<chain-key>` cursors only covered one default and cannot establish
  this coverage, so upgrade replays from `start_block` or block 1 when no floor is configured.
  An explicit `outbox_address` override bypasses Discovery and gets its own address-scoped key;
  changing or clearing that override cannot reuse its partial cursor as complete history.
- **Durable source work + checkpoints** — each source message is fsynced into
  `<checkpoint-path>.messages` before the scan cursor advances. The bounded vote cache restores
  unfinished work independently of cursor age or lookback. Keep the checkpoint file and sibling
  directory together on persistent storage and in backups. Missing or corrupt work fails closed;
  disk errors stop source progress. A cursor without a durable-work marker is replayed from
  `start_block` or block 1, even if it already uses the all-Outbox scope key.
  Startup still rewinds marked cursors by `scan_lookback_blocks` (default 600) for idempotent
  rescanning and memory-only settlement recovery. Votes are recovered through reobservation.
  Initial route recovery counts stored records once with constant memory; subsequent refill scans
  inspect at most 4,096 directory entries, so a huge backlog can still lengthen startup/recovery.
- **Bounded memory and supervised execution** — source backlog stays on disk until final delivery.
  Stalled, non-inflight working-set entries rotate back to disk so later publications can progress;
  accepted queued/failed work reconciles on-chain and retries without requiring fresh signatures.
  Retry tasks run through the supervised delivery worker instead of detached memory-only loops.
  With persistence disabled, source admission uses backpressure and retains unfinished entries.
  Source log scans cover at most 2,000 blocks per request, shrinking further on provider limits.

## Trust & key model

| Key | Chain | Needs | Notes |
| --- | --- | --- | --- |
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
together or not at all. `--checkpoint-path ""` disables persistence: source discovery replays from
`start_block` or block 1 and uses memory backpressure; ack discovery starts from `ack.start_block`
or the current destination head. Production restart recovery requires persistent storage.
Per-route envelope policy (asc-contracts #36), YAML key = flag = env:
`max_native_coin_value_wei` / `--max-native-coin-value-wei` / `RELAYER_MAX_NATIVE_COIN_VALUE_WEI`
(decimal or 0x-hex string, default `0`: front no native value), `max_gas_limit` /
`--max-gas-limit` / `RELAYER_MAX_GAS_LIMIT` (default `5000000`, must be > 0), and
`auto_request_top_up` / `--auto-request-top-up` / `RELAYER_AUTO_REQUEST_TOP_UP` (default `false`;
needs `relayer_contract_address` and an ack or claim signer). The caps are logged at startup.
`--verbose` switches `info` → `debug` logging. A few poll cadences are env-only (no CLI flag,
sensible defaults): `RELAYER_ACK_POLL_SECS` and `RELAYER_CLAIM_POLL_SECS`.

## HTTP API

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | liveness (200 when the process is up) |
| `GET /metrics` | Prometheus/OpenMetrics |
| `GET /votes/{message_hash}` | vote bundle for a message: signers seen, threshold, delivered flag — lets an operator (or a sibling relayer) inspect aggregation state |

Key metrics: `relayer_messages_indexed`, `relayer_votes_received` (by outcome),
`relayer_votes_per_message`, `relayer_deliver_tx` (by status: submitted / succeeded /
already-validated / pending / reverted / unclassified / …, see Execution outcomes
above), `relayer_time_to_threshold_seconds`, `relayer_time_to_deliver_seconds`,
`relayer_pool_messages_pending`, `relayer_attestor_set_size` / `relayer_attestor_set_reloads`,
`relayer_p2p_peer_count`, `relayer_ack_submissions` / `relayer_claim_submissions` (by outcome:
confirmed / terminal / failed — `submitAcknowledgment` and `claimDelivery` respectively; watch
`failed` for a stuck settlement path, since delivery keeps working independently of either),
`relayer_checkpoint_write_failures`, `relayer_delivery_retries_exceeded`,
`relayer_outcome_store_size` / `relayer_outcome_store_evictions`, plus process gauges.

## Build, test, run

```bash
cargo build --release            # binary at target/release/message-relayer
cargo test --workspace           # unit + protocol golden vectors
cargo clippy --all-targets       # lint (CI-enforced)
cargo fmt --all                  # format
taplo format                     # TOML format (config in .taplo.toml)
```

The `Full-stack recovery` workflow runs the candidate relayer commit with a real Creditcoin
node, three attestors, Anvil and compiled contracts. It checks delivery, proof-based
acknowledgment and fee settlement, then exercises durable recovery across a relayer restart.
The workflow runs on every pull request and push to `main`. It reuses a verified
`binary-for-testing-ci` artifact from a successful Creditcoin CI run and builds the candidate
relayer. The reusable workflow definition, native source/run/artifact and contracts are pinned
in [fullstack-recovery.yml](.github/workflows/fullstack-recovery.yml). The workflow definition
SHA selects the test implementation; `creditcoin-ref` identifies the native producer's source
checkout, which can be a pull request merge commit.

Update all three native pins together: `creditcoin-ref`, `creditcoin-run-id` and
`creditcoin-artifact-id`. A manual dispatch can override these pins and the contracts commit
while retaining the selected relayer commit. The callee checks the artifact's source, run,
build configuration and binary hashes before execution, and records the original compilation
revision when the producer reused a verified cache. An unavailable or expired artifact fails
the check; refresh it through Creditcoin CI and update the pins after the complete producer run
succeeds. There is no native rebuild fallback. Inspect the run's provenance, logs and scenario
results for the tested revisions and assertions.

Full-stack CI requires the existing `GLUWA_BOT_TOKEN` secret to read private `asc-contracts`.
If it is absent, including fork and Dependabot pull requests, the check fails explicitly;
the run does not skip the required stack. The workflow uses GitHub-hosted runners and needs
no Linode credentials. After building the binaries and installing the documented prerequisites
in the pinned Creditcoin checkout, run:

```bash
cd usc-messaging
npm run e2e -- --scenario happy-path,durable-restart --output-dir /tmp/relayer-fullstack
```

The historical `integration-tests` fixtures, including `tests/e2e_anvil.rs`, remain ignored
placeholders and do not provide this coverage. The protocol golden-vector tests run as part
of `cargo test --workspace` and guard wire compatibility.

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

```text
message-relayer/         the relayer crate
  bin/relayer.rs         CLI entrypoint (clap; --config or --single-route)
  src/lib.rs             Server: worker wiring, channels, supervisor JoinSet
  src/config.rs          YAML schema + validation (see config.example.yaml)
  src/events/            finalized source scans + historical Outbox authorization
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
  `get_outbox_discovery_address` chain-info precompile getter only exists
  on creditcoin3's `asc-dev` (the write-ability trunk, formerly `writeability-off-usc-dev`), not yet on `main`/`dev` (formerly `usc-dev`). **A route on a network without the
  precompile, or whose chain key has no discovery address registered via
  `set_outbox_discovery_addr`, cannot authorize source publications** and fails closed by default.
  Confirm both are in place — precompile deployed, discovery address registered and pointing at
  the `OutboxDiscovery` proxy from asc-contracts#38 — before pointing this relayer at a network.
  `outbox_address` (route config / `--outbox-address`) is an operator-pinned escape hatch for
  exactly that gap or an incident — see `events/mod.rs`'s source watcher — but it bypasses the
  registry entirely, so treat it as temporary and logged (WARN) loudly while set, not a substitute
  for registering the chain key properly.
