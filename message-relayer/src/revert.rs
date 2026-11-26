//! Node-agnostic classification of EVM revert errors.
//!
//! Execution clients word a revert differently: geth-style nodes say `execution reverted`,
//! Creditcoin's EVM RPC says `VM Exception while processing transaction: revert, data: "0x…"`,
//! and neither reliably decodes custom-error *names*. Matching decoded names alone therefore
//! misclassifies deterministic reverts as transient failures and retries them forever (the exact
//! bug behind the ack submitter's infinite no-ack-required loop — the error now named
//! `MessageCannotBeAcknowledged`).
//!
//! The helpers here extract the raw 4-byte custom-error **selector** from the revert data and
//! detect revert phrasing across node dialects, so callers can classify contract reverts without
//! depending on any one node's error format. Compare selectors against the `SolError::SELECTOR`
//! constants from [`write_ability::abi`] rather than hand-computed hex.

/// Extract the full ABI-encoded revert payload (selector + arguments) from a revert error string
/// of the form `… revert, data: "0x2f28bb55…"`. Anchored on the `data` field so an address or hash
/// appearing earlier in the message cannot be mistaken for the payload. `None` when there is no
/// `data` field or it is shorter than a selector; the caller decodes it with the matching
/// `SolError::abi_decode` (which validates the argument length).
#[must_use]
pub fn revert_data(s: &str) -> Option<Vec<u8>> {
    let data_at = s.find("data")?;
    let hex_at = s[data_at..].find("0x")? + data_at + 2;
    let hex: String = s[hex_at..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    if hex.len() < 8 || !hex.len().is_multiple_of(2) {
        return None;
    }
    hex::decode(hex.to_ascii_lowercase()).ok()
}

/// Extract the 4-byte custom-error selector from a revert error string of the form
/// `… revert, data: "0x2f28bb55…"`. Anchored on the `data` field so an address or hash appearing
/// earlier in the message cannot be mistaken for a selector.
#[must_use]
pub fn revert_selector(s: &str) -> Option<[u8; 4]> {
    let data_at = s.find("data")?;
    let hex_at = s[data_at..].find("0x")? + data_at + 2;
    let hex: String = s[hex_at..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    if hex.len() < 8 {
        return None;
    }
    let mut sel = [0u8; 4];
    hex::decode_to_slice(hex.to_ascii_lowercase(), &mut sel).ok()?;
    Some(sel)
}

/// Whether the error carries `sel` as its revert selector.
#[must_use]
pub fn has_selector(s: &str, sel: [u8; 4]) -> bool {
    revert_selector(s) == Some(sel)
}

/// Whether the error string reads as a **deterministic contract revert** (any node dialect), as
/// opposed to a transport / infrastructure failure (connection refused, timeout, nonce, funds).
/// A revert observed at send / gas-estimation time re-verts identically on retry, so callers
/// should treat it as permanent for the transaction at hand.
#[must_use]
pub fn is_revert(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("execution reverted")
        || lower.contains("vm exception while processing transaction")
        || lower.contains("transaction reverted")
}

/// Whether a revert error says nothing beyond "reverted": no revert data (not even a stub shorter
/// than a selector), no selector and no reason text. This is how a Solidity `abi.decode` failure,
/// a bare `revert()` and an out-of-gas read on every node dialect: Solidity reverts them with
/// *empty* data. A named or decoded reason (`execution reverted: ThresholdNotMet`, `Error(string)`,
/// a custom-error selector) is **not** bare, because that identifies a specific, possibly
/// state-dependent condition.
///
/// Strict by construction: the error must contain a revert phrase, and after each one only the end
/// of the message or exactly an *empty* `data` field (`, data: "0x"`, the form alloy prints for a
/// JSON-RPC error with empty data) may follow, ignoring whitespace and case. Any other suffix
/// (`, reason: …`, a selector in some wrapper field, trailing text) or any other error shape is
/// reported as not bare, so the caller keeps its retry behaviour instead of discarding work on a
/// guess.
#[must_use]
pub fn is_bare_revert(s: &str) -> bool {
    /// The phrases a node uses to say a call reverted; [`is_revert`] also accepts a bare
    /// `VM Exception while processing transaction`, which is not enough to call a revert bare
    /// (`… invalid opcode`, `… out of gas`).
    const REVERT_PHRASES: [&str; 3] = [
        "execution reverted",
        "while processing transaction: revert",
        "transaction reverted",
    ];
    /// What may follow a revert phrase in a bare revert, with whitespace removed.
    const EMPTY_DATA_FIELDS: [&str; 2] = [",data:\"0x\"", ",data:0x"];

    if !is_revert(s) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    // Any revert data at all before or after the phrase, including 1–3 bytes that `revert_data`
    // ignores for being shorter than a selector.
    if let Some(at) = lower.find("data") {
        if let Some(hex_at) = lower[at..].find("0x") {
            let tail = &lower[at + hex_at + 2..];
            if tail.starts_with(|c: char| c.is_ascii_hexdigit()) {
                return false;
            }
        }
    }
    let mut recognised = false;
    for phrase in REVERT_PHRASES {
        if let Some(at) = lower.find(phrase) {
            recognised = true;
            let rest: String = lower[at + phrase.len()..]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if !(rest.is_empty() || EMPTY_DATA_FIELDS.contains(&rest.as_str())) {
                return false;
            }
        }
    }
    recognised
}

#[cfg(test)]
mod tests {
    use super::*;

    const CC_STYLE: &str = "server returned an error response: error code -32603: VM Exception \
         while processing transaction: revert, data: \
         \"0x2f28bb55c8e0b2db4217508f44fb2d148bd9fab3c94e876a56a3fdbcf71f17570ecbe54c\"";

    #[test]
    fn revert_data_extraction() {
        // Selector + one 32-byte word, as the node prints it.
        let data = revert_data(CC_STYLE).expect("payload present");
        assert_eq!(data.len(), 36);
        assert_eq!(&data[..4], &[0x2f, 0x28, 0xbb, 0x55]);
        assert_eq!(
            revert_data("call reverted, data: \"0x12345678\""),
            Some(vec![0x12, 0x34, 0x56, 0x78])
        );
        assert_eq!(revert_data("connection refused"), None);
        assert_eq!(revert_data("revert, data: \"0xabc\""), None); // shorter than a selector
        assert_eq!(revert_data("revert, data: \"0x123456789\""), None); // odd nibble count
    }

    #[test]
    fn selector_extraction() {
        assert_eq!(revert_selector(CC_STYLE), Some([0x2f, 0x28, 0xbb, 0x55]));
        // Anchored on `data`: an address earlier in the message is not mistaken for a selector.
        let with_addr =
            "call to 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef reverted, data: \"0x12345678\"";
        assert_eq!(revert_selector(with_addr), Some([0x12, 0x34, 0x56, 0x78]));
        assert_eq!(revert_selector("connection refused"), None);
        assert_eq!(revert_selector("revert, data: \"0xabc\""), None); // too short
    }

    #[test]
    fn revert_phrasing_across_dialects() {
        assert!(is_revert(CC_STYLE));
        assert!(is_revert("execution reverted: Already validated"));
        assert!(is_revert("transaction reverted on-chain"));
        assert!(!is_revert("error sending request: connection refused"));
        assert!(!is_revert("error code -32000: insufficient funds for gas"));
    }

    #[test]
    fn selector_match() {
        assert!(has_selector(CC_STYLE, [0x2f, 0x28, 0xbb, 0x55]));
        assert!(!has_selector(CC_STYLE, [0x33, 0x70, 0x4b, 0x28]));
    }

    /// A Solidity `abi.decode` failure reverts with empty data; every dialect must read as bare.
    #[test]
    fn bare_reverts_are_recognised_across_dialects() {
        for bare in [
            "execution reverted",
            "server returned an error response: error code 3: execution reverted",
            "server returned an error response: error code 3: execution reverted, data: \"0x\"",
            "error code 3: execution reverted , data: \"0x\"",
            "server returned an error response: error code -32603: VM Exception while processing \
             transaction: revert",
            "VM Exception while processing transaction: revert, data: \"0x\"",
            // Spacing and case are irrelevant.
            "Error code 3: Execution Reverted,data:\"0x\"",
            "error code 3: execution reverted,   data:   \"0x\"  ",
        ] {
            assert!(is_bare_revert(bare), "should be bare: {bare}");
        }
    }

    /// Anything that names a reason, carries data (of any length) or is not a revert at all must
    /// not read as bare, so the caller keeps retrying instead of discarding work on a guess.
    #[test]
    fn reverts_with_a_reason_or_data_are_not_bare() {
        for not_bare in [
            // A decoded or named reason.
            "execution reverted: ThresholdNotMet",
            "execution reverted: Already validated",
            "execution reverted: EnforcedPause()",
            "VM Exception while processing transaction: reverted with reason string 'nope'",
            "transaction reverted on-chain",
            // Revert data: a full custom error, and a stub shorter than a selector.
            CC_STYLE,
            "error code 3: execution reverted, data: \"0x12345678\"",
            "error code 3: execution reverted, data: \"0x12\"",
            // A comma after the phrase is not enough: only an empty `data` field may follow it.
            // Reasons or selectors in other wrapper fields, and anything trailing, are not bare.
            "execution reverted, reason: ThresholdNotMet",
            "execution reverted, selector: 0x12345678",
            "execution reverted, message: paused",
            "error code 3: execution reverted, data: \"0x\", reason: ThresholdNotMet",
            "error code 3: execution reverted, data: \"0x\" (retry later)",
            "error code 3: execution reverted, data: \"0x\" execution reverted: Foo",
            "VM Exception while processing transaction: revert, reason: nope",
            // A VM exception that is not a revert is not a bare revert either.
            "VM Exception while processing transaction: invalid opcode",
            "VM Exception while processing transaction: out of gas",
            // Two phrases, one of which carries a reason.
            "transaction reverted: execution reverted",
            // Not a contract revert at all.
            "error sending request: connection refused",
            "error code -32000: insufficient funds for gas",
            "",
        ] {
            assert!(!is_bare_revert(not_bare), "must not be bare: {not_bare}");
        }
    }
}
