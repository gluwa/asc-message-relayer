//! Solidity ABI bindings for the USC write-ability contracts.
//!
//! Shared by the attestor (which decodes `MessagePublished` from the Creditcoin Outbox) and the
//! `message-relayer` (which additionally calls `Inbox.deliverMessage` / `validateVotes`). Keeping
//! one definition here means both crates decode the *same* event signature — since asc-contracts
//! #54, `validateVotes` takes `messageId` itself as the signed digest, so there is no separate
//! hash preimage left to keep in sync (see `hash.rs`'s module doc).
//!
//! Inline `alloy::sol!` declarations are used while the production contracts are finalized — when
//! they ship, switch each block to the JSON form (`#[sol(rpc)] interface X, "contracts/x.json"`)
//! following the pattern in `common/eth/src/evm/block_prover.rs`. Keep the function & event
//! signatures byte-identical with the production artefacts.

use alloy::sol;

sol! {
    /// Stored message record returned by `Outbox.getMessage` (mirrors `OutboxTypes.Message`).
    /// Field order/types must match the Solidity struct exactly for ABI decoding.
    #[derive(Debug)]
    struct OutboxMessage {
        address emitter;
        uint64 sequence;
        uint64 timestamp;
        bool canAck;
        bool acknowledged;
        bytes32 payloadHash;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IOutbox {
        /// A new cross-chain message has been published to this outbox.
        ///
        /// `messageId` is the unique handle attestors and the inbox use to track delivery.
        /// `emitterAddress` is the dApp that called `publishMessage`, emitted as `bytes32` for
        /// cross-chain consistency — the 20-byte EVM address occupies the **high** bytes
        /// (`bytes32(bytes20(emitter))`), so recover it with `Address::from_slice(&value[..20])`.
        /// `canAck` flags whether the message may be acknowledged on-chain (usc-contracts #23
        /// renamed it from `requiresAck`: the ack is optional, requested by a nonzero
        /// acknowledgmentPrice in the relayer quote) before it is
        /// considered complete. `payload` is the opaque bytes the inbox will hand to the
        /// destination dApp's `receiveMessage`.
        event MessagePublished(
            bytes32 indexed messageId,
            bytes32 indexed emitterAddress,
            uint64 sequence,
            bool canAck,
            bytes payload
        );

        /// Whether `messageId` was published with `canAck = true`. `false` for an unknown id
        /// (mapping default), so the ack submitter uses it as the existence-and-requires-ack gate
        /// before checking `isAcknowledged`.
        function messageCanAck(bytes32 messageId) external view returns (bool);

        /// Whether `messageId` has already been acknowledged on the source Outbox. `false` for an
        /// unknown id.
        function isAcknowledged(bytes32 messageId) external view returns (bool);

        /// Stored message state. Mirrors `Outbox.getMessage`: reverts `MessageNotFound` for an
        /// unknown id. `emitter` here is a plain `address` — only the `MessagePublished` event
        /// widens it to `bytes32`.
        function getMessage(bytes32 messageId) external view returns (OutboxMessage memory);

        /// Reverts bubbled up through `AcknowledgmentValidator.submitAcknowledgment` when it calls
        /// `acknowledgeMessage` here. All three are permanent for a given delivery tx — the ack
        /// submitter classifies them as terminal (see `message-relayer/src/ack`).
        /// `MessageCannotBeAcknowledged` is the post-#23 name of `MessageDoesNotRequireAck`
        /// (`canAck == false`); the abi_surface drift test caught the stale selector.
        error MessageCannotBeAcknowledged(bytes32 messageId);
        error MessageNotFound(bytes32 messageId);
        error MessageAlreadyAcknowledged(bytes32 messageId);
    }

    /// OutboxDiscovery (asc-contracts #38): the cross-generation registry that replaces both the
    /// per-deployer `outboxOf` mapping and factory-log scanning as the source of truth for which
    /// Outbox serves a chain key. `defaultOutbox` is the confirmed read ("not from deployer,
    /// because there will be multiple versions of outbox" — Kevin, 28 Aug). Only what we read is
    /// mirrored.
    ///
    /// The timelock events matter to us specifically: `activeOutboxes` drops an Outbox the moment
    /// its scheduled removal block passes, so set membership disappearing is NOT the signal to stop
    /// watching one. These events carry the effective block in advance, and the cancel events stop
    /// us acting on a schedule that was called off. `effectiveBlock` is a source-chain BLOCK
    /// NUMBER, compared against `block.number` (asc-contracts #46 moved the timelock off unix
    /// time so it cannot drift with block production); `timelock()` and `MIN_TIMELOCK` (1200) are
    /// in blocks too. Drain-before-drop: keep serving an Outbox until the source chain has passed
    /// `effectiveBlock`, then stop.
    #[sol(rpc)]
    #[derive(Debug)]
    contract IOutboxDiscovery {
        /// Registered as active for `chainKey`. Its block is a listener's start block: the registry
        /// exposes no creation height, and starting at the head would skip everything below it.
        event OutboxRegistered(
            uint32 indexed chainKey,
            address indexed outbox,
            address indexed registrar
        );
        event OutboxRemovalScheduled(
            uint32 indexed chainKey,
            address indexed outbox,
            uint64 effectiveBlock
        );
        /// Also fires with `effectiveBlock == block.number` when the first live Outbox for a
        /// chain key auto-becomes the default (no delay: there was no prior default to drain).
        event DefaultOutboxChangeScheduled(
            uint32 indexed chainKey,
            address indexed outbox,
            uint64 effectiveBlock
        );
        event PendingDefaultCancelled(uint32 indexed chainKey);
        event PendingRemovalCancelled(uint32 indexed chainKey, address indexed outbox);

        function defaultOutbox(uint32 chainKey) external view returns (address);
        /// Every Outbox still serving `chainKey`, due-removed entries already filtered out.
        function activeOutboxes(uint32 chainKey) external view returns (address[] memory);
        function isActiveOutbox(uint32 chainKey, address outbox) external view returns (bool);
        /// Sole home for the deployer address once the runtime's stored factory address retires.
        function defaultDeployer() external view returns (address);
        /// Cold-start reads for a relayer booting after a schedule event already fired.
        function pendingDefaultOutbox(uint32 chainKey) external view returns (address outbox, uint64 effectiveBlock);
        function pendingRemovalBlock(uint32 chainKey, address outbox) external view returns (uint64 effectiveBlock);
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IInbox {
        /// Submit an aggregated set of attestor votes that prove `messageId` was finalized
        /// on Creditcoin. Calldata is byte-identical to what attestors signed.
        /// Post asc-contracts #45 the Inbox takes the source `outbox` (second argument, must be
        /// on its allowlist) and is `payable`: `msg.value` must equal the envelope's
        /// `nativeCoinValue` or the DispatcherRouter reverts `InvalidNativeCoinValue`.
        /// asc-contracts #54 adds `sequence` (the Outbox's per-emitter sequence `messageId` was
        /// derived from) and replaces the old messageHash vote digest with a direct check that
        /// `messageId == OutboxTypes.computeMessageId(outbox, emitterAddress, sequence,
        /// keccak256(messagePayload), sourceChainId)` — reverting `MessageIdMismatch` otherwise.
        /// A `DISPATCH_MESSAGE_FAILED` destination outcome no longer consumes the messageId: a
        /// later `deliverMessage` call (re-validating votes) may retry it.
        function deliverMessage(
            bytes32 messageId,
            address outbox,
            address emitterAddress,
            uint64 sequence,
            bytes calldata messagePayload,
            bytes calldata votes
        ) external payable;

        /// Retry a message previously left in the `MessagePending` state (e.g. dApp ran out
        /// of gas during `receiveMessage`). Permissionless.
        function retryPendingMessage(bytes32 messageId) external;

        /// Whether `messageId` was validated but its `receiveMessage` callback failed, leaving it
        /// retryable via `retryPendingMessage`. Mirrors `SimpleInbox.isPending`.
        function isPending(bytes32 messageId) external view returns (bool);

        /// asc-contracts #54: emitted when Inbox accepted a delivery attempt that reached the
        /// dispatcher destination path (executed OR destination-failed) — always paired with
        /// either `MessageExecuted` or `DestinationFailed` on the same tx. `processor` is the vote
        /// validator that authorized delivery; `relayer` is the `msg.sender` that delivered. Only
        /// `messageId` (topics[1]) is read; the two addresses are ignored. Renamed from
        /// `MessageDelivered` (3-arg shape unchanged) — unlike its predecessor, this event no
        /// longer implies the destination call succeeded: a `DestinationFailed`-paired delivery
        /// still emits it (relay work happened) and the message stays open for another
        /// `deliverMessage` retry. `EVMDeliveryDecoder`/`claimDelivery` read it alone (relay-fee
        /// settlement pays for relay work, not destination success); the ack path
        /// (`AcknowledgmentValidator`) reads `MessageExecuted` instead, specifically to exclude
        /// destination failures from acknowledgment.
        event MessageReceived(
            bytes32 indexed messageId,
            address indexed processor,
            address indexed relayer
        );
        /// Emitted (on a **successful** `deliverMessage` tx) when the votes validated but the
        /// dApp's `receiveMessage` callback reverted — the message is stored for
        /// `retryPendingMessage`. Signature must match `Inbox.MessagePending` exactly or
        /// receipt-log classification silently misses it: the 2-arg shape from the retired
        /// SimpleInbox had exactly that effect (caught by the abi_surface drift test). Only
        /// `messageId` (topics[1]) is read; `relayer` (the delivery-fee payee, see
        /// `IDeliveryDecoder`) is ignored here.
        event MessagePending(
            bytes32 indexed messageId,
            address indexed destinationContract,
            address indexed relayer
        );
        /// asc-contracts #54: emitted when the destination call succeeded and the message is
        /// fully completed (`processedAt` set) — always follows `MessageReceived` on the same
        /// successful attempt. Replaces the old "plain `MessageDelivered` alone" success signal.
        /// `AcknowledgmentValidator` reads this (not `MessageReceived`) so a retryable destination
        /// failure can never be mistaken for a completed, acknowledgeable delivery.
        event MessageExecuted(
            bytes32 indexed messageId,
            address indexed emitterAddress,
            address indexed destination,
            address dispatcher,
            address relayer,
            bytes messagePayload
        );
        /// asc-contracts #54: replaces `MessageExecutionFailed`. Emitted (alongside
        /// `MessageReceived`, same tx) when the destination call reverted or the destination has
        /// no code — but UNLIKE `MessageExecutionFailed`, this is **not terminal**: the message
        /// stays open (`processedAt` is not set) and a later `deliverMessage` call may retry it
        /// with fresh vote validation. Delivery/retry classification must treat this as
        /// retryable, not terminal-consumed — treating it as terminal (the old
        /// `MessageExecutionFailed` semantics) would silently abandon a message the Inbox is
        /// still willing to retry.
        event DestinationFailed(
            bytes32 indexed messageId,
            address indexed emitterAddress,
            address indexed destination,
            address dispatcher,
            address relayer,
            bytes messagePayload
        );

        /// Revert used to classify duplicate deliveries for metrics + retry logic. NOTE: older
        /// inboxes rejected duplicates with `require(..., "Already validated")` (a string revert) —
        /// classifiers must match that string as well as this custom-error selector.
        /// (Vote-validation failures revert from the EOAValidator with its own error names, so no
        /// vote errors are mirrored here.) Post-#23 the error carries the messageId — the old
        /// zero-arg selector matched nothing (caught by the abi_surface drift test).
        error MessageAlreadyValidated(bytes32 messageId);
        /// asc-contracts #54: `deliverMessage`'s submitted `(outbox, emitterAddress, sequence,
        /// messagePayload, sourceChainId)` does not recompute to `messageId`. A calldata-assembly
        /// bug on our side (wrong `sequence`, stale payload, …) — never expected in normal
        /// operation, since we source all of these from the same `MessagePublished` log.
        error MessageIdMismatch(bytes32 messageId);
        /// asc-contracts #36: `retryPendingMessage` reverts this when the dispatcher answered
        /// deferred/queued again. Pending state is restored, so the retry is not lost — but
        /// re-sending before `retryAfter` is a guaranteed revert. `retryAfter` is a unix timestamp
        /// from the dispatcher's optional `IMessageRetrySchedule` hint, or 0 when it exposes none
        /// (fall back to the fixed backoff). Decoded from the revert data by the pending-retry task.
        error RetryDeferred(bytes32 messageId, uint64 retryAfter);
        /// asc-contracts #36: `deliverMessage` reverts this (instead of emitting `ValidationFailed`
        /// and returning false) when the votes fail validation AND `msg.value != 0`, so the
        /// fronted native value is refunded rather than stranded in the Inbox. Terminal for these
        /// votes: the same bundle re-validates identically.
        error ValidationFailedWithNativeValue(bytes32 messageId, uint256 value);
        /// asc-contracts #36: the configured dispatcher has no code while native value is attached
        /// (a value-bearing failure cannot be parked as pending). Also raised by the owner-only
        /// setters. Terminal for the job — only an Inbox reconfiguration clears it.
        error InvalidMessageDispatcher(address dispatcher);
    }

    /// Dispatcher-side surface (asc-contracts #36: `DispatcherRouter` + the `DefaultDispatcher` /
    /// `RateLimitDispatcher` implementations it delegates to, via `DestinationCall`). Only the one
    /// revert the relayer must react to is mirrored; the Inbox bubbles it verbatim from
    /// `deliverMessage`.
    #[sol(rpc)]
    #[derive(Debug)]
    contract IMessageDispatcher {
        /// The destination call FAILED and, after EIP-150's 63/64 reduction, the caller had less
        /// than `gasLimit / 63` left — i.e. the relayer's tx gas was too low to prove the attested
        /// `gasLimit` was actually forwarded, so the failure may be the relayer's under-gassing
        /// rather than the destination's fault. The dispatcher reverts (rolling back replay/queue
        /// state) instead of recording a terminal `DISPATCH_MESSAGE_FAILED`, so the same message
        /// can be retried with more gas. Retryable: bump the tx gas and resend.
        error InsufficientGasForDestination();
    }

    /// Destination-side receiver base (`MessageReceiverBase.sol`). Mirrored for one reason: its
    /// duplicate guard reverts `MessageAlreadyProcessed` when a message that already ran the
    /// receiver callback is delivered again (relayer restart replaying a checkpoint, or losing a
    /// race past the Inbox's own guard). Delivery classifies that selector as idempotent success —
    /// without it a replayed delivery logs a terminal ERROR and counts as `Reverted` for a message
    /// that was in fact processed (seen on usc-devnet, 2026-09-01).
    #[sol(rpc)]
    #[derive(Debug)]
    contract IMessageReceiver {
        /// `messageId` already ran this receiver's callback; delivering it again is a no-op.
        error MessageAlreadyProcessed(bytes32 messageId);
        /// `outbox` is not on this Inbox's allowlist (asc-contracts #45). Terminal: no retry
        /// can fix a message published on an Outbox the destination does not trust.
        error UnsupportedOutbox(address outbox);
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IVoteValidator {
        /// Active attestor EVM addresses for this validator. Queried once at startup when the
        /// attestor set is sourced from the on-chain validator.
        function attestors() external view returns (address[] memory);

        /// Quorum threshold (e.g. 2N/3 + 1). Mirrored locally so callers do not burn gas on
        /// transactions that are guaranteed to revert.
        function threshold() external view returns (uint256);

        /// Monotonic nonce bound into the attestor-set-update digest (replay/rollback protection);
        /// increments on each successful update. The relayer reads it to reconstruct the digest.
        function attestorSetUpdateNonce() external view returns (uint256);

        /// Rotate the attestor set. `signatures` is the concatenation of 65-byte `(r,s,v)` ECDSA
        /// signatures by the *current* set over the update digest
        /// ([`attestor_set_update_digest`](crate::hash::attestor_set_update_digest)); the contract
        /// verifies threshold-many and swaps in `newAttestors`. Permissionless — the relayer submits
        /// it once it has aggregated a threshold of gossiped signatures.
        function submitAttestorSetUpdate(address[] memory newAttestors, bytes memory signatures) external;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IAcknowledgmentValidator {
        /// Trust-minimized acknowledgment entrypoint on the *source* (Creditcoin) chain. The relayer
        /// proves — via the chain's native USC proving (block-prover precompile: merkle inclusion +
        /// continuity) — that a `MessageExecuted` event was emitted in a finalized block on the
        /// destination chain (asc-contracts #54 renamed this from `MessageDelivered` and split out
        /// destination-failure retries, which no longer qualify as acknowledgeable). This contract
        /// verifies the proof, decodes the delivered messageId(s),
        /// and calls `Outbox.acknowledgeMessage` per log under try/catch (one already-acked or
        /// no-ack log cannot wedge the others). Permissionless AND fee-bearing: each message's
        /// user-set ackFee (held by this validator) pays `msg.sender` of the first successful
        /// submission — an open, front-runnable bounty by design (Jul 28 decision), so the relayer
        /// should submit promptly.
        ///
        /// `height` is the destination block height. The prover `txBytes` travel INSIDE
        /// `inclusionProof.data` (`abi.encode(bytes txBytes, MerkleProofEntry[] siblings)`) — the
        /// PR #23 envelope, same shape `claimDelivery` takes; there is no separate
        /// `encodedTransaction` parameter any more.
        function submitAcknowledgment(
            uint64 height,
            InclusionProof inclusionProof,
            ContinuityProof continuityProof
        ) external;

        event Acknowledged(bytes32 indexed messageId);
        event AckFeeClaimed(bytes32 indexed messageId, address indexed claimant, uint256 amount);

        /// Reverts the ack submitter treats as terminal for a given proof. Outbox message-state
        /// errors (`MessageCannotBeAcknowledged` / `MessageNotFound` / `MessageAlreadyAcknowledged`)
        /// no longer bubble up — the validator catches them per log — so a submission only reverts
        /// when NOTHING was acknowledged (`NoMessageExecutedLogs`) or the proof itself is bad.
        /// `ProofInvalid` is raised by the `USCProofVerifier` the validator delegates to.
        /// asc-contracts #54 renamed both from `NoMessageDeliveredLogs`/`MalformedMessageDeliveredLog`.
        error ProofInvalid(bytes32 chainKey, uint64 blockHeight);
        error NoMessageExecutedLogs();
        error MalformedMessageExecutedLog();
        error EncodedTransactionTooLarge(uint256 size, uint256 maxSize);
        error UnsupportedTxType(uint8 txType);
        error OutboxNotSet();
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IRelayerContract {
        /// Per-message fee + routing record on the *source* (Creditcoin) chain. Since PR #23's
        /// `RelayerFeeLedger` refactor this ledger lives on the RelayerContract(Lite) itself — the
        /// RelayerFeeVault holds tokens only and serves no reads — so this binding targets the
        /// route's `relayer_contract_address`. The relayer reads `gasLimit` so it can deliver the
        /// destination tx with exactly the funded gas: `claimDelivery` only pays when the proven
        /// delivery tx's gasLimit matches a funded tier, so an estimated gas would strand the fee.
        struct MessageInfo {
            address payer;
            uint32  destinationChain;
            uint256 gasLimit;
            uint256 relayFee;
            uint256 tip;
            uint256 tipExpiry;
            uint256 deliveryDeadline;
            bool    relaySettled;
            /// Fee currency of the route (from the signed quote): native-coin wei when true,
            /// ATTEST wei when false. Informational for the relayer — payout currency is bound
            /// on-chain to the deposit currency.
            bool    feesInNative;
        }

        function getMessageInfo(bytes32 messageId) external view returns (MessageInfo memory);

        /// Trust-minimized relay-fee settlement on the *source* (Creditcoin) chain. The relayer
        /// proves — via the block-prover precompile (merkle inclusion + continuity) — that a
        /// `MessageReceived` event for `messageId` was emitted in a finalized block on the
        /// destination chain (asc-contracts #54 renamed this from `MessageDelivered`; it still
        /// fires — and still counts for relay-fee settlement — on a destination-failure retry, not
        /// just on outright success). The contract verifies the proof, decodes the proven relayer from the
        /// event, and pays it the relay fee (+ any unexpired tip).
        ///
        /// NOTE: unlike the pre-#23 vault version, this does NOT acknowledge the message — ack
        /// settlement lives solely on [`IAcknowledgmentValidator::submitAcknowledgment`], so the
        /// two submissions are independent and must BOTH run on a fee-funded route.
        ///
        /// Permissionless: the payee is always the proven relayer, never `msg.sender`, so a
        /// front-runner can only settle the claim on the relayer's behalf, not steal it. `chainKey`
        /// is `bytes32(uint256(destinationChain))`; `inclusionProof` is the self-describing
        /// `BlockProverTypes.InclusionProof` the `USCProofVerifier` consumes.
        function claimDelivery(
            bytes32 messageId,
            bytes32 chainKey,
            uint64 blockHeight,
            InclusionProof inclusionProof,
            ContinuityProof continuityProof
        ) external;

        /// Relayer-side signal that the funded `gasLimit` is short by `additionalGasNeeded`. Pure
        /// signal: no state change, just `TopUpRequested(messageId, msg.sender,
        /// additionalGasNeeded)` for the payer/quoter to act on with `topUpGasLimit`. Reverts
        /// `UnknownOperation` (unfunded), `RelayAlreadySettled`, or `DeliveryDeadlineReached`
        /// when a top-up could no longer help. Permissionless; whether a relayer calls it is
        /// service policy (`ChainRoute::auto_request_top_up`, default off).
        function requestTopUp(bytes32 messageId, uint256 additionalGasNeeded) external;

        /// `messageId` was not funded through the relayer contract (e.g. bridge traffic, or a
        /// message published without a relay fee). Permanent for a given messageId.
        error UnknownOperation(bytes32 messageId);
        /// The relay fee for `messageId` was already claimed. Permanent — a duplicate claim.
        error RelayAlreadySettled(bytes32 messageId);
        /// A native payout leg failed (recipient rejected the transfer). Deliberately NOT in the
        /// relayer's terminal set: it can clear if the recipient starts accepting, and the
        /// pull-payment fix pending on usc-contracts #23 (review B1/B2) removes it entirely.
        error NativeTransferFailed(address to, uint256 amount);
    }

    /// One sibling along the merkle inclusion path. `isLeft` says whether the sibling is the
    /// left-hand input when hashing up to the parent.
    #[derive(Debug)]
    struct MerkleProofEntry {
        bytes32 hash;
        bool isLeft;
    }

    /// Merkle inclusion proof of the transaction within its block's transaction trie.
    #[derive(Debug)]
    struct MerkleProof {
        bytes32 root;
        MerkleProofEntry[] siblings;
    }

    /// Continuity proof that the attestation chain finalized the destination block: the chain of
    /// block-root digests from a known lower endpoint up to the proven height.
    #[derive(Debug)]
    struct ContinuityProof {
        bytes32 lowerEndpointDigest;
        bytes32[] roots;
    }

    /// PR #23 self-describing transaction-inclusion proof (`BlockProverTypes.InclusionProof`),
    /// consumed by [`IRelayerContract::claimDelivery`] and
    /// [`IAcknowledgmentValidator::submitAcknowledgment`] via the `USCProofVerifier`. `kind` is the
    /// `ProofKind` discriminator (`0` = `BinaryMerkle`, the only supported kind); `root` is the
    /// transaction-trie root; `data` is `abi.encode(bytes txBytes, MerkleProofEntry[] siblings)` —
    /// the same `txBytes`/`siblings` the flat [`MerkleProof`] carries, re-wrapped for the verifier.
    /// Build it via the relayer's `proofgen` helper, not by hand, so the `data` encoding cannot drift.
    #[derive(Debug)]
    struct InclusionProof {
        uint8 kind;
        bytes32 root;
        bytes data;
    }
}
