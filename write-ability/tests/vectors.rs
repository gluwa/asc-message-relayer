//! Cross-repo golden vectors. Every file under `vectors/` is a byte-identical copy:
//!
//! * the Solidity-generated ones come from asc-contracts `test/vectors/` (`npm run vectors`
//!   there), their canonical home;
//! * the SCALE gossip envelopes come from creditcoin3 `common/write-ability/vectors/`, which
//!   generates them from the canonical wire types.
//!
//! Do not edit a vector to make a test pass: a mismatch means this crate's wire or signing format
//! no longer matches the contracts or the attestors.

use std::path::Path;

use alloy::primitives::{Address, Bytes, B256, U256};
use serde::Deserialize;
use write_ability::envelope::{MessageVote, ReobservationRequest, SetUpdateVote};
use write_ability::hash::{attestor_set_update_digest, canonical_attestor_order};

const SOLIDITY_VECTORS: [&str; 4] = [
    "attestor_set_update.json",
    "evm_envelope.json",
    "message_id.json",
    "message_vote_eip712.json",
];
const SCALE_VECTORS: [&str; 3] = [
    "message_vote_scale.json",
    "reobservation_request_scale.json",
    "set_update_vote_scale.json",
];

fn load<T: serde::de::DeserializeOwned>(json: &str) -> Vec<T> {
    let vectors: Vec<T> = serde_json::from_str(json).expect("vectors file is valid JSON");
    assert!(!vectors.is_empty());
    vectors
}

fn decimal(value: &str) -> U256 {
    U256::from_str_radix(value, 10).expect("vector integers are decimal strings")
}

fn u64_decimal(value: &str) -> u64 {
    value.parse().expect("vector integers are decimal strings")
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("vector field has the wire length")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetUpdate {
    name: String,
    validator: Address,
    attestors: Vec<Address>,
    chain_id: String,
    nonce: String,
    digest: B256,
    canonical_attestors: Vec<Address>,
    canonical_digest: B256,
}

#[test]
fn attestor_set_update_digest_matches_solidity_vectors() {
    for v in load::<SetUpdate>(include_str!("../vectors/attestor_set_update.json")) {
        let (chain_id, nonce) = (decimal(&v.chain_id), decimal(&v.nonce));
        assert_eq!(
            attestor_set_update_digest(v.validator, &v.attestors, chain_id, nonce),
            v.digest,
            "{}: digest over the given order",
            v.name
        );
        let canonical = canonical_attestor_order(&v.attestors);
        assert_eq!(
            canonical, v.canonical_attestors,
            "{}: canonical order",
            v.name
        );
        assert_eq!(
            attestor_set_update_digest(v.validator, &canonical, chain_id, nonce),
            v.canonical_digest,
            "{}: digest over the canonical order",
            v.name
        );
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageVoteVector {
    name: String,
    chain_key: String,
    message_id: B256,
    signer: Address,
    signature: Bytes,
    encoded: Bytes,
}

#[test]
fn message_vote_matches_scale_vectors() {
    for v in load::<MessageVoteVector>(include_str!("../vectors/message_vote_scale.json")) {
        let vote = MessageVote {
            chain_key: u64_decimal(&v.chain_key),
            message_id: v.message_id.0,
            signer: v.signer.0 .0,
            signature: fixed(&v.signature),
        };
        assert_eq!(
            vote.encode_bytes(),
            v.encoded.to_vec(),
            "{}: encode",
            v.name
        );
        assert_eq!(
            MessageVote::decode_bytes(&v.encoded).as_ref(),
            Ok(&vote),
            "{}: decode",
            v.name
        );
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReobservationRequestVector {
    name: String,
    chain_key: String,
    message_id: B256,
    tx_hash: B256,
    block_height: String,
    encoded: Bytes,
}

#[test]
fn reobservation_request_matches_scale_vectors() {
    for v in load::<ReobservationRequestVector>(include_str!(
        "../vectors/reobservation_request_scale.json"
    )) {
        let request = ReobservationRequest {
            chain_key: u64_decimal(&v.chain_key),
            message_id: v.message_id.0,
            tx_hash: v.tx_hash.0,
            block_height: u64_decimal(&v.block_height),
        };
        assert_eq!(
            request.encode_bytes(),
            v.encoded.to_vec(),
            "{}: encode",
            v.name
        );
        assert_eq!(
            ReobservationRequest::decode_bytes(&v.encoded).as_ref(),
            Ok(&request),
            "{}: decode",
            v.name
        );
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetUpdateVoteVector {
    name: String,
    chain_key: String,
    new_attestors: Vec<Address>,
    nonce: B256,
    signer: Address,
    signature: Bytes,
    encoded: Bytes,
}

#[test]
fn set_update_vote_matches_scale_vectors() {
    for v in load::<SetUpdateVoteVector>(include_str!("../vectors/set_update_vote_scale.json")) {
        let vote = SetUpdateVote {
            chain_key: u64_decimal(&v.chain_key),
            new_attestors: v.new_attestors.iter().map(|a| a.0 .0).collect(),
            nonce: v.nonce.0,
            signer: v.signer.0 .0,
            signature: fixed(&v.signature),
        };
        assert_eq!(
            vote.encode_bytes(),
            v.encoded.to_vec(),
            "{}: encode",
            v.name
        );
        assert_eq!(
            SetUpdateVote::decode_bytes(&v.encoded).as_ref(),
            Ok(&vote),
            "{}: decode",
            v.name
        );
    }
}

/// Compares local copies with the canonical directory named by `var`. Unset skips on a dev
/// machine; under `ABI_GATE_STRICT` an unset `required` directory fails instead.
fn assert_copies_match(var: &str, required: bool, subdir: &str, files: &[&str]) {
    let Ok(dir) = std::env::var(var) else {
        assert!(
            !(required && std::env::var("ABI_GATE_STRICT").is_ok()),
            "ABI_GATE_STRICT is set but {var} is not; the vector drift gate would have passed \
             without checking anything"
        );
        eprintln!("{var} not set; skipping the shared-vector drift check against it");
        return;
    };
    let canonical = Path::new(&dir).join(subdir);
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    for file in files {
        let theirs = std::fs::read(canonical.join(file)).unwrap_or_else(|error| {
            panic!(
                "{}: {error}. The pinned revision must contain the shared vectors",
                canonical.join(file).display()
            )
        });
        let ours = std::fs::read(local.join(file)).expect("local vector copy exists");
        assert!(
            ours == theirs,
            "vectors/{file} differs from {}; copy the canonical file over and fix whichever \
             implementation it exposes",
            canonical.join(file).display()
        );
    }
}

#[test]
fn solidity_vectors_match_asc_contracts() {
    assert_copies_match("ASC_CONTRACTS_DIR", true, "test/vectors", &SOLIDITY_VECTORS);
}

#[test]
fn scale_vectors_match_creditcoin3() {
    assert_copies_match(
        "CREDITCOIN3_DIR",
        false,
        "common/write-ability/vectors",
        &SCALE_VECTORS,
    );
}
