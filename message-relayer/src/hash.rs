//! Signing digests (EIP-712 message-vote digest and attestor-set-update digest), re-exported from
//! the shared [`write_ability`] crate.
//!
//! Prior to asc-contracts #54 this also re-exported a six-field `message_hash` vote-digest builder;
//! #54 moved votes to the raw `messageId`, and CSUB-2126 to an EIP-712 digest of it
//! ([`write_ability::hash::MessageVoteDomain`], golden vectors in
//! `write-ability/vectors/message_vote_eip712.json`).

pub use write_ability::hash::*;
