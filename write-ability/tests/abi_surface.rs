//! Solidity ↔ Rust ABI-surface drift detector (relayer side).
//!
//! `src/abi.rs` is a hand-maintained `sol!` mirror of the asc-contracts surface the relayer calls.
//! The golden vectors police creditcoin3↔relayer agreement, but nothing enforced Solidity↔Rust
//! agreement — and that drift is quiet: a renamed *error* doesn't break anything visibly, it just
//! turns the revert classifier's selector match into dead code (found here: the Outbox renamed
//! `MessageDoesNotRequireAck` → `MessageCannotBeAcknowledged` and the terminal-revert naming kept
//! matching the old selector), and a changed *event* signature moves topic0 so a log filter goes
//! silent instead of failing.
//!
//! For every mirrored function, event and error, recompute the selector / topic0 from the Rust
//! `sol!` types and assert a byte-identical one exists in the compiled hardhat artifact. For the
//! two struct-returning calls the selector alone can't protect (`getMessage`, `getMessageInfo` —
//! outputs aren't part of the selector), also pin the artifact's output tuple against the Rust
//! struct layout, since a reordered field decodes silently into garbage.
//!
//! Runs wherever `ASC_CONTRACTS_DIR` points at a compiled asc-contracts checkout; without the env
//! var it is a no-op so plain `cargo test` stays green. creditcoin3's write-ability-e2e workflow
//! (which checks out both this repo and asc-contracts) is the CI home for this check.

use alloy::primitives::keccak256;
use alloy::sol_types::{SolCall, SolError, SolEvent};
use std::path::{Path, PathBuf};
use write_ability::abi::{
    IAcknowledgmentValidator, IInbox, IMessageDispatcher, IMessageReceiver, IOutbox,
    IOutboxDiscovery, IRelayerContract, IVoteValidator,
};

/// Canonical ABI type for one artifact input/output, expanding structs: `tuple` →
/// `(comp1,comp2,…)`, preserving array suffixes (`tuple[]` → `(…)[]`).
fn canonical_type(param: &serde_json::Value) -> String {
    let ty = param["type"].as_str().expect("abi param has a type");
    if let Some(suffix_start) = ty.find("tuple").map(|_| "tuple".len()) {
        if ty.starts_with("tuple") {
            let components = param["components"]
                .as_array()
                .expect("tuple param has components")
                .iter()
                .map(canonical_type)
                .collect::<Vec<_>>()
                .join(",");
            return format!("({components}){}", &ty[suffix_start..]);
        }
    }
    ty.to_string()
}

fn canonical_signature(entry: &serde_json::Value) -> String {
    let name = entry["name"].as_str().expect("abi entry has a name");
    let params = entry["inputs"]
        .as_array()
        .expect("abi entry has inputs")
        .iter()
        .map(canonical_type)
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({params})")
}

struct Artifact {
    path: PathBuf,
    abi: Vec<serde_json::Value>,
}

impl Artifact {
    fn load(contracts: &Path, rel: &str) -> Self {
        let path = contracts.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let artifact: serde_json::Value = serde_json::from_str(&raw).expect("artifact is JSON");
        let abi = artifact["abi"]
            .as_array()
            .expect("artifact has an abi array")
            .clone();
        Self { path, abi }
    }

    /// First of `candidates` that exists, for a surface the contracts repo is mid-rename on.
    /// Panics naming all of them if none is present, so a genuine disappearance still fails.
    fn load_first(contracts: &Path, candidates: &[&str]) -> Self {
        for rel in candidates {
            if contracts.join(rel).is_file() {
                return Self::load(contracts, rel);
            }
        }
        panic!(
            "none of {candidates:?} exist under {} — the contract was renamed again or the \
             artifacts are incomplete; add the new name to the candidate list",
            contracts.display()
        )
    }

    fn signatures(&self, kind: &str) -> Vec<String> {
        self.abi
            .iter()
            .filter(|entry| entry["type"] == kind)
            .map(canonical_signature)
            .collect()
    }

    /// Assert some declared item of `kind` hashes to `selector_or_topic0` (4 bytes for
    /// functions/errors, 32 for events).
    fn assert_mirrored(&self, kind: &str, rust_signature: &str, hash_prefix: &[u8]) {
        let declared = self.signatures(kind);
        let found = declared
            .iter()
            .any(|sig| keccak256(sig.as_bytes()).0.starts_with(hash_prefix));
        assert!(
            found,
            "{kind} mirror drifted from {}: Rust binds `{rust_signature}` (hash prefix 0x{}), the \
             artifact declares {declared:?}. Update src/abi.rs — and every selector/topic match \
             that uses it — to the contract's current shape.",
            self.path.display(),
            alloy::hex::encode(hash_prefix),
        );
    }

    /// Pin the output tuple of a struct-returning view: selectors don't cover outputs, and a
    /// reordered/retyped field decodes silently into garbage instead of failing.
    fn assert_output_tuple(&self, function: &str, expected: &str) {
        let entry = self
            .abi
            .iter()
            .find(|e| e["type"] == "function" && e["name"] == function)
            .unwrap_or_else(|| panic!("{function} not found in {}", self.path.display()));
        let outputs = entry["outputs"]
            .as_array()
            .expect("function has outputs")
            .iter()
            .map(canonical_type)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            outputs,
            expected,
            "{function} output drifted in {} — the Rust struct in src/abi.rs decodes this shape \
             positionally and must be updated field-for-field",
            self.path.display(),
        );
    }
}

#[test]
fn mirrored_abi_surface_matches_compiled_contracts() {
    // `ASC_CONTRACTS_DIR` since the repository was renamed usc-contracts -> asc-contracts;
    // `USC_CONTRACTS_DIR` stays accepted so existing local setups keep working.
    let dir = std::env::var("ASC_CONTRACTS_DIR")
        .or_else(|_| std::env::var("USC_CONTRACTS_DIR"))
        .ok();
    // Set by CI alongside the artifacts dir. An unset dir skipping is what a plain `cargo test`
    // on a dev machine wants, but it also meant this gate never ran in CI at all — nothing here
    // pointed it at any contracts. Any environment that means to enforce the gate sets this and
    // gets a failure instead of a silent pass.
    let strict = std::env::var("ABI_GATE_STRICT").is_ok();
    let Some(dir) = dir else {
        assert!(
            !strict,
            "ABI_GATE_STRICT is set but neither ASC_CONTRACTS_DIR nor USC_CONTRACTS_DIR is — the \
             drift gate would have silently passed without checking anything"
        );
        eprintln!(
            "ASC_CONTRACTS_DIR not set — skipping ABI-surface check (point it at a compiled \
             asc-contracts checkout to enable)"
        );
        return;
    };
    let contracts = Path::new(&dir).join("artifacts/contracts/write-ability");
    assert!(
        contracts.is_dir(),
        "contracts dir is set but {} does not exist — run `npx hardhat compile` there first",
        contracts.display()
    );

    // --- Outbox (source chain) ---
    let outbox = Artifact::load(&contracts, "Outbox.sol/Outbox.json");
    outbox.assert_mirrored(
        "event",
        IOutbox::MessagePublished::SIGNATURE,
        &IOutbox::MessagePublished::SIGNATURE_HASH.0,
    );
    outbox.assert_mirrored(
        "function",
        "messageCanAck(bytes32)",
        &IOutbox::messageCanAckCall::SELECTOR,
    );
    outbox.assert_mirrored(
        "function",
        "isAcknowledged(bytes32)",
        &IOutbox::isAcknowledgedCall::SELECTOR,
    );
    outbox.assert_mirrored(
        "function",
        "getMessage(bytes32)",
        &IOutbox::getMessageCall::SELECTOR,
    );
    outbox.assert_output_tuple("getMessage", "(address,uint64,uint64,bool,bool,bytes32)");
    outbox.assert_mirrored(
        "error",
        "MessageCannotBeAcknowledged(bytes32)",
        &IOutbox::MessageCannotBeAcknowledged::SELECTOR,
    );
    outbox.assert_mirrored(
        "error",
        "MessageNotFound(bytes32)",
        &IOutbox::MessageNotFound::SELECTOR,
    );
    outbox.assert_mirrored(
        "error",
        "MessageAlreadyAcknowledged(bytes32)",
        &IOutbox::MessageAlreadyAcknowledged::SELECTOR,
    );

    // --- Inbox (destination chain) ---
    let inbox = Artifact::load(&contracts, "Inbox.sol/Inbox.json");
    inbox.assert_mirrored(
        "function",
        "deliverMessage(bytes32,address,address,bytes,bytes)",
        &IInbox::deliverMessageCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "function",
        "retryPendingMessage(bytes32)",
        &IInbox::retryPendingMessageCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "function",
        "isPending(bytes32)",
        &IInbox::isPendingCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "event",
        IInbox::MessageDelivered::SIGNATURE,
        &IInbox::MessageDelivered::SIGNATURE_HASH.0,
    );
    inbox.assert_mirrored(
        "event",
        IInbox::MessagePending::SIGNATURE,
        &IInbox::MessagePending::SIGNATURE_HASH.0,
    );
    // #36: emitted alongside MessageDelivered for a consumed-but-failed destination call. A moved
    // topic0 would silently relabel every destination failure as a plain success.
    inbox.assert_mirrored(
        "event",
        IInbox::MessageExecutionFailed::SIGNATURE,
        &IInbox::MessageExecutionFailed::SIGNATURE_HASH.0,
    );
    inbox.assert_mirrored(
        "error",
        "MessageAlreadyValidated(bytes32)",
        &IInbox::MessageAlreadyValidated::SELECTOR,
    );
    // #36 reverts the delivery/pending-retry classifiers key on. The selectors are matched from raw
    // revert data (Creditcoin-style nodes decode no names), so a drifted one is dead code that
    // falls through to the generic "revert ⇒ terminal" arm: RetryDeferred would lose its
    // retryAfter scheduling, InsufficientGasForDestination would stop being retried with more gas.
    inbox.assert_mirrored(
        "error",
        "RetryDeferred(bytes32,uint64)",
        &IInbox::RetryDeferred::SELECTOR,
    );
    inbox.assert_mirrored(
        "error",
        "ValidationFailedWithNativeValue(bytes32,uint256)",
        &IInbox::ValidationFailedWithNativeValue::SELECTOR,
    );
    inbox.assert_mirrored(
        "error",
        "InvalidMessageDispatcher(address)",
        &IInbox::InvalidMessageDispatcher::SELECTOR,
    );

    // --- Dispatcher implementations (destination chain, #36) ---
    // `InsufficientGasForDestination` is raised inside the `DestinationCall` library, so it lands
    // in the ABI of every dispatcher implementation that links it (not the router, which only
    // delegatecalls them, nor the Inbox, which bubbles the raw revert). Pin it against both shipped
    // implementations: a route's Inbox may be wired to either.
    for artifact in [
        "DefaultDispatcher.sol/DefaultDispatcher.json",
        "RateLimitDispatcher.sol/RateLimitDispatcher.json",
    ] {
        let dispatcher = Artifact::load(&contracts, artifact);
        dispatcher.assert_mirrored(
            "error",
            "InsufficientGasForDestination()",
            &IMessageDispatcher::InsufficientGasForDestination::SELECTOR,
        );
    }

    // --- MessageReceiverBase (destination chain) ---
    // Only the duplicate guard is mirrored; delivery treats its selector as idempotent success.
    let receiver = Artifact::load(
        &contracts,
        "abstract/MessageReceiverBase.sol/MessageReceiverBase.json",
    );
    receiver.assert_mirrored(
        "error",
        "MessageAlreadyProcessed(bytes32)",
        &IMessageReceiver::MessageAlreadyProcessed::SELECTOR,
    );

    // --- EOAValidator (destination chain) ---
    let validator = Artifact::load(&contracts, "EOAValidator.sol/EOAValidator.json");
    validator.assert_mirrored(
        "function",
        "attestors()",
        &IVoteValidator::attestorsCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "threshold()",
        &IVoteValidator::thresholdCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "attestorSetUpdateNonce()",
        &IVoteValidator::attestorSetUpdateNonceCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "submitAttestorSetUpdate(address[],bytes)",
        &IVoteValidator::submitAttestorSetUpdateCall::SELECTOR,
    );

    // --- AcknowledgmentValidator (source chain; note the artifact DIR spells "Acknowledgement") ---
    let ackv = Artifact::load(
        &contracts,
        "AcknowledgementValidator.sol/AcknowledgmentValidator.json",
    );
    ackv.assert_mirrored(
        "function",
        "submitAcknowledgment(uint64,(uint8,bytes32,bytes),(bytes32,bytes32[]))",
        &IAcknowledgmentValidator::submitAcknowledgmentCall::SELECTOR,
    );
    ackv.assert_mirrored(
        "event",
        IAcknowledgmentValidator::Acknowledged::SIGNATURE,
        &IAcknowledgmentValidator::Acknowledged::SIGNATURE_HASH.0,
    );
    ackv.assert_mirrored(
        "event",
        IAcknowledgmentValidator::AckFeeClaimed::SIGNATURE,
        &IAcknowledgmentValidator::AckFeeClaimed::SIGNATURE_HASH.0,
    );
    ackv.assert_mirrored(
        "error",
        "NoMessageDeliveredLogs()",
        &IAcknowledgmentValidator::NoMessageDeliveredLogs::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "MalformedMessageDeliveredLog()",
        &IAcknowledgmentValidator::MalformedMessageDeliveredLog::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "EncodedTransactionTooLarge(uint256,uint256)",
        &IAcknowledgmentValidator::EncodedTransactionTooLarge::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "UnsupportedTxType(uint8)",
        &IAcknowledgmentValidator::UnsupportedTxType::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "OutboxNotSet()",
        &IAcknowledgmentValidator::OutboxNotSet::SELECTOR,
    );
    // ProofInvalid is declared by the proof verifier the validator delegates to; the revert
    // bubbles through, so its selector is pinned against THAT artifact. Accept either name: the
    // contracts repo is mid-rename from USC to ASC and the two open PRs disagree about it, so
    // taking whichever exists keeps this gate independent of the order they land in.
    let verifier = Artifact::load_first(
        &contracts,
        &[
            "common/ASCProofVerifier.sol/ASCProofVerifier.json",
            "common/USCProofVerifier.sol/USCProofVerifier.json",
        ],
    );
    verifier.assert_mirrored(
        "error",
        "ProofInvalid(bytes32,uint64)",
        &IAcknowledgmentValidator::ProofInvalid::SELECTOR,
    );

    // --- RelayerContract (source chain) ---
    //
    // Checked against BOTH deployable fee ledgers. They are genuinely different contracts —
    // `collectRelayerFee` has a different arity, Lite gates on `authorizedQuoters`, and Lite
    // lacks nine of the errors our revert classifier matches on — but the surface this crate
    // actually binds (`getMessageInfo`, `claimDelivery`, and the three settlement errors) is
    // shared and must stay identical, because a route can be pointed at either. Asserting
    // against only one leaves the other free to drift: the quoter service already targets Lite
    // (its ADR 0001), so the uncovered one is the one production is heading for.
    for artifact in [
        "RelayerContract.sol/RelayerContract.json",
        "RelayerContractLite.sol/RelayerContractLite.json",
    ] {
        let relayer = Artifact::load(&contracts, artifact);
        relayer.assert_mirrored(
            "function",
            "getMessageInfo(bytes32)",
            &IRelayerContract::getMessageInfoCall::SELECTOR,
        );
        relayer.assert_output_tuple(
            "getMessageInfo",
            "(address,uint32,uint256,uint256,uint256,uint256,uint256,bool,bool)",
        );
        relayer.assert_mirrored(
            "function",
            "claimDelivery(bytes32,bytes32,uint64,(uint8,bytes32,bytes),(bytes32,bytes32[]))",
            &IRelayerContract::claimDeliveryCall::SELECTOR,
        );
        // Opt-in relayer-side top-up signal (`ChainRoute::auto_request_top_up`). Only ever sent
        // when the operator turned it on, but a drifted selector would then revert every request.
        relayer.assert_mirrored(
            "function",
            "requestTopUp(bytes32,uint256)",
            &IRelayerContract::requestTopUpCall::SELECTOR,
        );
        relayer.assert_mirrored(
            "error",
            "UnknownOperation(bytes32)",
            &IRelayerContract::UnknownOperation::SELECTOR,
        );
        relayer.assert_mirrored(
            "error",
            "RelayAlreadySettled(bytes32)",
            &IRelayerContract::RelayAlreadySettled::SELECTOR,
        );
        relayer.assert_mirrored(
            "error",
            "NativeTransferFailed(address,uint256)",
            &IRelayerContract::NativeTransferFailed::SELECTOR,
        );
    }

    // --- OutboxDiscovery (source chain) ---
    //
    // Both events and reads. A moved topic0 silently blinds a subscription, and the timelock
    // events are our only advance notice before a default changes or an Outbox is removed. A
    // moved selector makes a read revert with empty returndata, which the registry-first resolver
    // cannot distinguish from "no Outbox for this chain key" — it would resolve to nothing and
    // idle. Deliberately NOT asserting `activeOutboxCount`: it existed in the reviewed revision
    // of #38 and was dropped before merge.
    let discovery = Artifact::load(
        &contracts,
        "deployer/OutboxDiscovery.sol/OutboxDiscovery.json",
    );
    discovery.assert_mirrored(
        "event",
        IOutboxDiscovery::OutboxRegistered::SIGNATURE,
        &IOutboxDiscovery::OutboxRegistered::SIGNATURE_HASH.0,
    );
    discovery.assert_mirrored(
        "event",
        IOutboxDiscovery::OutboxRemovalScheduled::SIGNATURE,
        &IOutboxDiscovery::OutboxRemovalScheduled::SIGNATURE_HASH.0,
    );
    discovery.assert_mirrored(
        "event",
        IOutboxDiscovery::DefaultOutboxChangeScheduled::SIGNATURE,
        &IOutboxDiscovery::DefaultOutboxChangeScheduled::SIGNATURE_HASH.0,
    );
    discovery.assert_mirrored(
        "event",
        IOutboxDiscovery::PendingDefaultCancelled::SIGNATURE,
        &IOutboxDiscovery::PendingDefaultCancelled::SIGNATURE_HASH.0,
    );
    discovery.assert_mirrored(
        "event",
        IOutboxDiscovery::PendingRemovalCancelled::SIGNATURE,
        &IOutboxDiscovery::PendingRemovalCancelled::SIGNATURE_HASH.0,
    );
    discovery.assert_mirrored(
        "function",
        "defaultOutbox(uint32)",
        &IOutboxDiscovery::defaultOutboxCall::SELECTOR,
    );
    discovery.assert_mirrored(
        "function",
        "activeOutboxes(uint32)",
        &IOutboxDiscovery::activeOutboxesCall::SELECTOR,
    );
    discovery.assert_mirrored(
        "function",
        "isActiveOutbox(uint32,address)",
        &IOutboxDiscovery::isActiveOutboxCall::SELECTOR,
    );
    discovery.assert_mirrored(
        "function",
        "defaultDeployer()",
        &IOutboxDiscovery::defaultDeployerCall::SELECTOR,
    );
    discovery.assert_mirrored(
        "function",
        "pendingDefaultOutbox(uint32)",
        &IOutboxDiscovery::pendingDefaultOutboxCall::SELECTOR,
    );
    discovery.assert_mirrored(
        "function",
        "pendingRemovalBlock(uint32,address)",
        &IOutboxDiscovery::pendingRemovalBlockCall::SELECTOR,
    );
}
