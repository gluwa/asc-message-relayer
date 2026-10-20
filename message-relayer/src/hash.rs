//! Attestor-set-update digest, re-exported from the shared [`write_ability`] crate.
//!
//! Prior to asc-contracts #54 this also re-exported a `message_hash` vote-digest builder; #54
//! moved `Inbox.validateVotes` to take `messageId` itself as the signed digest, so that builder
//! (and its golden-vector tests, formerly in `tests/golden_hash.rs`) is gone — see
//! [`write_ability::hash`]'s module doc.

pub use write_ability::hash::*;
