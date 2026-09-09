//! Golden-vector tests for [`message_relayer::hash::message_hash`] (PoC test T1).
//!
//! The preimage is the one `Inbox.deliverMessage` recomputes on asc-contracts `feature/SMC-1646`
//! (PR #45, merged 2026-09-04):
//!
//! ```solidity
//! keccak256(abi.encode(messageId, emitterAddress, outbox, localChainKey, sourceChainId, messagePayload))
//! ```
//!
//! Three kinds of assertion:
//!
//!  * the hash matches a hand-rolled `keccak256(abi.encode(...))` over the same tuple,
//!  * each input field meaningfully changes the output (no silent collisions on swapped fields),
//!  * the hash matches constants produced independently with Foundry
//!    (`cast abi-encode 'f(bytes32,address,address,bytes32,uint256,bytes)' … | cast keccak`).
//!
//! The Foundry constants are duplicated in creditcoin3 `common/write-ability/src/hash.rs`. That
//! symmetry is what keeps the relayer's local recomputation aligned with what attestors sign and
//! what `validateVotes` checks; if either side drifts, delivery reverts on every message.

use alloy::primitives::{address, b256, Address, B256, U256};
use alloy::sol_types::SolValue;
use message_relayer::hash::message_hash;
use sha3::{Digest, Keccak256};

/// Hand-rolled `keccak256(abi.encode(...))` used as the oracle for [`message_hash`].
fn oracle(
    message_id: B256,
    emitter: Address,
    outbox: Address,
    destination_chain_key: B256,
    creditcoin_chain_id: u64,
    payload: &[u8],
) -> B256 {
    let encoded = (
        message_id,
        emitter,
        outbox,
        destination_chain_key,
        U256::from(creditcoin_chain_id),
        payload.to_vec(),
    )
        .abi_encode_params();
    let mut hasher = Keccak256::new();
    hasher.update(&encoded);
    B256::from_slice(&hasher.finalize())
}

const OUTBOX: Address = address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

#[test]
fn matches_hand_rolled_oracle() {
    let m = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let e = address!("dddddddddddddddddddddddddddddddddddddddd");
    let d = b256!("0000000000000000000000000000000000000000000000000000000000000007");
    let cc = 102_031u64;
    let payload = b"hello relayer".to_vec();

    let expected = oracle(m, e, OUTBOX, d, cc, &payload);
    let actual = message_hash(m, e, OUTBOX, d, cc, &payload);
    assert_eq!(expected, actual);
}

/// Constants generated outside Rust, with Foundry, against the six-field preimage. These are the
/// cross-language contract with the Solidity Inbox and with the attestor crate.
#[test]
fn matches_foundry_generated_vectors() {
    let m = b256!("1111111111111111111111111111111111111111111111111111111111111111");
    let e = address!("2222222222222222222222222222222222222222");
    let o = address!("3333333333333333333333333333333333333333");
    let d = b256!("0000000000000000000000000000000000000000000000000000000000000008");
    let cc = 42u64;

    assert_eq!(
        message_hash(m, e, o, d, cc, &[0xde, 0xad, 0xbe, 0xef]),
        b256!("4b387cab474082acc4b1765537d74b87b4425bf4ecd4e375472106d63e12ff68"),
        "six-field preimage with a 4-byte payload"
    );
    assert_eq!(
        message_hash(m, e, o, d, cc, b""),
        b256!("a5f139b554b2264af26a30ad40276a909055ca73db27a4e4d005baa1a3f8d013"),
        "six-field preimage with an empty payload"
    );
    // The pre-#45 five-field hash of the same inputs. Must NOT match: this is the vote-format fork
    // the coordinated attestor + relayer + Inbox redeploy exists for.
    assert_ne!(
        message_hash(m, e, o, d, cc, &[0xde, 0xad, 0xbe, 0xef]),
        b256!("c99b69d3aef00fc024cdb4751aae2a8ea1467501e2fdd2824dd415a120deb5bd"),
        "must not collide with the legacy five-field preimage"
    );
}

#[test]
fn changing_any_field_changes_hash() {
    let m = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let e = address!("dddddddddddddddddddddddddddddddddddddddd");
    let d = b256!("0000000000000000000000000000000000000000000000000000000000000007");
    let cc = 102_031u64;
    let p = b"baseline".to_vec();

    let base = message_hash(m, e, OUTBOX, d, cc, &p);
    assert_ne!(base, message_hash(B256::ZERO, e, OUTBOX, d, cc, &p));
    assert_ne!(
        base,
        message_hash(
            m,
            address!("0000000000000000000000000000000000000000"),
            OUTBOX,
            d,
            cc,
            &p
        )
    );
    assert_ne!(
        base,
        message_hash(
            m,
            e,
            address!("cccccccccccccccccccccccccccccccccccccccc"),
            d,
            cc,
            &p
        ),
        "a message replayed from a different Outbox must hash differently"
    );
    assert_ne!(base, message_hash(m, e, OUTBOX, B256::ZERO, cc, &p));
    assert_ne!(base, message_hash(m, e, OUTBOX, d, cc + 1, &p));
    assert_ne!(base, message_hash(m, e, OUTBOX, d, cc, b"different"));
}
