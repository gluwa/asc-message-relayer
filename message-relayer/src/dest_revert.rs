//! Make a destination-side revert readable.
//!
//! Since asc-contracts #36 `deliverMessage` succeeds even when the dApp call fails: the Inbox emits
//! `MessageExecutionFailed` next to `MessageDelivered`, consumes the message, and the receipt says
//! nothing about *why* the destination reverted — the revert bytes were swallowed inside the
//! dispatcher. The relayer used to record just "the destination call reverted", which on
//! 2026-09-18 cost a partner a day: their message was an ERC20 `transfer` whose real failure was
//! `ERC20InsufficientBalance(sender = the DispatcherRouter, balance 0)`, because at the destination
//! `msg.sender` is the router, never the emitter.
//!
//! [`probe_destination_revert`] replays the *destination* call exactly as the dispatcher made it —
//! `from` the router, `to` the envelope's destination, calldata = `payloadData ++ emitter` (the
//! 20-byte emitter suffix the DefaultDispatcher appends), `value = nativeCoinValue`, `gas =
//! gasLimit` — at the delivery block, and [`describe_revert_data`] turns whatever comes back into a
//! sentence: `Error(string)`, `Panic(code)`, the OpenZeppelin v5 custom errors, our own receiver
//! errors, or at worst the raw selector. A second replay without the gas cap tells an out-of-gas
//! (the other common partner mistake: a 50 000 gasLimit on a token transfer) apart from a genuine
//! revert.

use alloy::eips::BlockId;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::{Panic, PanicKind, Revert, SolError, SolValue};
use alloy::transports::{RpcError, TransportErrorKind};

use crate::abi::{IMessageDispatcher, IMessageReceiver};

sol! {
    /// Custom errors a destination dApp is likely to surface. OpenZeppelin v5 (`ERC20`, `ERC721`,
    /// `Ownable`, `AccessControl`, `Pausable`, `ReentrancyGuard`, `Address`, `SafeERC20`). Only the
    /// selector and the argument layout matter; the names are the OZ ones so the sentence reads
    /// like the Solidity.
    interface IKnownReverts {
        error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
        error ERC20InvalidSender(address sender);
        error ERC20InvalidReceiver(address receiver);
        error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
        error ERC20InvalidApprover(address approver);
        error ERC20InvalidSpender(address spender);
        error ERC721NonexistentToken(uint256 tokenId);
        error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);
        error ERC721InsufficientApproval(address operator, uint256 tokenId);
        error ERC721InvalidReceiver(address receiver);
        error OwnableUnauthorizedAccount(address account);
        error OwnableInvalidOwner(address owner);
        error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
        error EnforcedPause();
        error ExpectedPause();
        error ReentrancyGuardReentrantCall();
        error AddressEmptyCode(address target);
        error AddressInsufficientBalance(address account);
        error FailedInnerCall();
        error FailedCall();
        error SafeERC20FailedOperation(address token);
    }
}

/// One sentence for a destination revert's return data.
#[must_use]
pub fn describe_revert_data(data: &[u8]) -> String {
    if data.is_empty() {
        return "reverted with empty data (out of gas, a bare `revert()`/`require` without a \
                message, or a call to an address with no code)"
            .to_string();
    }
    if data.len() < 4 {
        return format!(
            "reverted with {} bytes of non-ABI data 0x{}",
            data.len(),
            hex::encode(data)
        );
    }
    let sel: [u8; 4] = data[..4].try_into().expect("checked length");

    if sel == Revert::SELECTOR {
        if let Ok(r) = Revert::abi_decode(data) {
            return format!("Error({:?})", r.reason);
        }
    }
    if sel == Panic::SELECTOR {
        if let Ok(p) = Panic::abi_decode(data) {
            let kind = p
                .kind()
                .map_or_else(|| "unknown".to_string(), |k| panic_kind_name(k).to_string());
            return format!("Panic(0x{:x}: {kind})", p.code);
        }
    }

    macro_rules! try_known {
        ($($ty:ty => |$e:ident| $fmt:expr),+ $(,)?) => {
            $(
                if sel == <$ty as SolError>::SELECTOR {
                    if let Ok($e) = <$ty as SolError>::abi_decode(data) {
                        return $fmt;
                    }
                }
            )+
        };
    }
    try_known! {
        IKnownReverts::ERC20InsufficientBalance => |e| format!(
            "ERC20InsufficientBalance(sender {}, balance {}, needed {}) — at the destination \
             msg.sender is the dispatcher router, not the emitter; the router holds no tokens",
            e.sender, e.balance, e.needed
        ),
        IKnownReverts::ERC20InsufficientAllowance => |e| format!(
            "ERC20InsufficientAllowance(spender {}, allowance {}, needed {})",
            e.spender, e.allowance, e.needed
        ),
        IKnownReverts::ERC20InvalidSender => |e| format!("ERC20InvalidSender({})", e.sender),
        IKnownReverts::ERC20InvalidReceiver => |e| format!("ERC20InvalidReceiver({})", e.receiver),
        IKnownReverts::ERC20InvalidApprover => |e| format!("ERC20InvalidApprover({})", e.approver),
        IKnownReverts::ERC20InvalidSpender => |e| format!("ERC20InvalidSpender({})", e.spender),
        IKnownReverts::ERC721NonexistentToken => |e| format!("ERC721NonexistentToken({})", e.tokenId),
        IKnownReverts::ERC721IncorrectOwner => |e| format!(
            "ERC721IncorrectOwner(sender {}, tokenId {}, owner {})", e.sender, e.tokenId, e.owner
        ),
        IKnownReverts::ERC721InsufficientApproval => |e| format!(
            "ERC721InsufficientApproval(operator {}, tokenId {})", e.operator, e.tokenId
        ),
        IKnownReverts::ERC721InvalidReceiver => |e| format!("ERC721InvalidReceiver({})", e.receiver),
        IKnownReverts::OwnableUnauthorizedAccount => |e| format!(
            "OwnableUnauthorizedAccount({}) — the caller at the destination is the dispatcher \
             router, not the emitter", e.account
        ),
        IKnownReverts::OwnableInvalidOwner => |e| format!("OwnableInvalidOwner({})", e.owner),
        IKnownReverts::AccessControlUnauthorizedAccount => |e| format!(
            "AccessControlUnauthorizedAccount(account {}, role {})", e.account, e.neededRole
        ),
        IKnownReverts::EnforcedPause => |_e| "EnforcedPause() — the destination contract is paused".to_string(),
        IKnownReverts::ExpectedPause => |_e| "ExpectedPause()".to_string(),
        IKnownReverts::ReentrancyGuardReentrantCall => |_e| "ReentrancyGuardReentrantCall()".to_string(),
        IKnownReverts::AddressEmptyCode => |e| format!("AddressEmptyCode({}) — no contract at that address", e.target),
        IKnownReverts::AddressInsufficientBalance => |e| format!("AddressInsufficientBalance({})", e.account),
        IKnownReverts::FailedInnerCall => |_e| "FailedInnerCall()".to_string(),
        IKnownReverts::FailedCall => |_e| "FailedCall()".to_string(),
        IKnownReverts::SafeERC20FailedOperation => |e| format!("SafeERC20FailedOperation(token {})", e.token),
        IMessageReceiver::MessageAlreadyProcessed => |e| format!(
            "MessageAlreadyProcessed({}) — the receiver has already consumed this messageId", e.messageId
        ),
        IMessageReceiver::UnsupportedOutbox => |e| format!(
            "UnsupportedOutbox({}) — the receiver does not trust the Outbox this message came from", e.outbox
        ),
        IMessageDispatcher::InsufficientGasForDestination => |_e| {
            "InsufficientGasForDestination() — the envelope gasLimit is below what the dispatcher \
             requires".to_string()
        },
    }

    format!(
        "custom error 0x{} ({} bytes of revert data)",
        hex::encode(sel),
        data.len()
    )
}

fn panic_kind_name(kind: PanicKind) -> &'static str {
    match kind {
        PanicKind::Generic => "generic compiler panic",
        PanicKind::Assert => "assert(false)",
        PanicKind::UnderOverflow => "arithmetic underflow/overflow",
        PanicKind::DivisionByZero => "division by zero",
        PanicKind::EnumConversionError => "invalid enum conversion",
        PanicKind::StorageEncodingError => "storage encoding error",
        PanicKind::EmptyArrayPop => "pop on empty array",
        PanicKind::ArrayOutOfBounds => "array index out of bounds",
        PanicKind::ResourceError => "allocation too large",
        PanicKind::InvalidInternalFunction => "invalid internal function",
        _ => "unknown panic code",
    }
}

/// Revert bytes carried by an `eth_call` error, from the structured JSON-RPC `data` first and the
/// node's error string second (Creditcoin-style `data: "0x…"` dialect).
fn revert_bytes(err: &RpcError<TransportErrorKind>) -> Vec<u8> {
    err.as_error_resp()
        .and_then(|payload| payload.as_revert_data())
        .map(|b| b.to_vec())
        .or_else(|| crate::revert::revert_data(&err.to_string()))
        .unwrap_or_default()
}

/// Replay the destination call the dispatcher made for `payload` and explain why it reverted.
///
/// `dispatcher` is the address the Inbox reported in `MessageExecutionFailed` — the
/// DispatcherRouter, which is `msg.sender` at the destination (the DefaultDispatcher runs under
/// `delegatecall`). `emitter` is appended to the calldata exactly as the dispatcher does.
/// `block` is the delivery receipt's block so the replay sees the same state.
///
/// `None` when the payload is not an envelope (nothing to replay) or the RPC did not answer.
pub async fn probe_destination_revert<P: Provider>(
    provider: &P,
    dispatcher: Address,
    emitter: Address,
    payload: &[u8],
    block: Option<u64>,
) -> Option<String> {
    let (destination, native_value, gas_limit, payload_data) =
        <(Address, U256, U256, Bytes)>::abi_decode_params(payload).ok()?;
    let mut input = payload_data.to_vec();
    input.extend_from_slice(emitter.as_slice());

    let base = TransactionRequest::default()
        .with_from(dispatcher)
        .with_to(destination)
        .with_input(Bytes::from(input))
        .with_value(native_value);
    let at = block.map_or(BlockId::latest(), BlockId::number);
    let gas: u64 = gas_limit.try_into().unwrap_or(u64::MAX);

    match provider
        .call(base.clone().with_gas_limit(gas))
        .block(at)
        .await
    {
        Ok(_) => Some(format!(
            "the destination call succeeds when replayed at block {} with the envelope gasLimit \
             {gas} — the failure was state-dependent (balance or allowance changed since, or the \
             dispatcher's overhead on top of gasLimit)",
            block.map_or_else(|| "latest".to_string(), |b| b.to_string())
        )),
        Err(err) => {
            let data = revert_bytes(&err);
            // Empty data is what an out-of-gas looks like. Retry without the cap: if the call
            // then passes, the gasLimit was the problem.
            if data.is_empty() && provider.call(base).block(at).await.is_ok() {
                return Some(format!(
                    "out of gas: the destination call needs more than the envelope gasLimit \
                     {gas}; quote at least 300 000 for calls through the router"
                ));
            }
            Some(describe_revert_data(&data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    /// The 2026-09-18 partner case, byte for byte as Sepolia returned it for the replay.
    #[test]
    fn erc20_insufficient_balance_names_the_router_as_sender() {
        let data = IKnownReverts::ERC20InsufficientBalance {
            sender: address!("5dF0F2D8fdb0b5Ca0815c8959154862F84ff80AB"),
            balance: U256::ZERO,
            needed: U256::from(1_968u64) * U256::from(10u64).pow(U256::from(18)),
        }
        .abi_encode();
        let s = describe_revert_data(&data);
        assert!(
            s.starts_with("ERC20InsufficientBalance(sender 0x5dF0"),
            "{s}"
        );
        assert!(s.contains("balance 0"), "{s}");
        assert!(s.contains("msg.sender is the dispatcher router"), "{s}");
    }

    #[test]
    fn error_string_and_panic_decode() {
        let e = Revert::from("not enough").abi_encode();
        assert_eq!(describe_revert_data(&e), "Error(\"not enough\")");
        let p = Panic::from(PanicKind::UnderOverflow).abi_encode();
        assert_eq!(
            describe_revert_data(&p),
            "Panic(0x11: arithmetic underflow/overflow)"
        );
    }

    #[test]
    fn empty_short_and_unknown_data_are_still_readable() {
        assert!(describe_revert_data(&[]).contains("empty data"));
        assert!(describe_revert_data(&[0xde, 0xad]).contains("2 bytes of non-ABI data 0xdead"));
        let unknown = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1];
        assert_eq!(
            describe_revert_data(&unknown),
            "custom error 0x12345678 (8 bytes of revert data)"
        );
    }

    #[test]
    fn own_receiver_errors_decode() {
        let data = IMessageReceiver::UnsupportedOutbox {
            outbox: address!("0000000000000000000000000000000000000bad"),
        }
        .abi_encode();
        assert!(describe_revert_data(&data).starts_with("UnsupportedOutbox(0x0000"));
    }

    /// Live replay of usc-devnet message 0x2999fffa… (Sepolia delivery tx 0x97467c69…, block
    /// 11727197): a partner's ERC20 `transfer` that reverted `ERC20InsufficientBalance` because the
    /// router, not the emitter, is `msg.sender`. Needs `SEPOLIA_RPC_URL`; run with `--ignored`.
    #[tokio::test]
    #[ignore = "needs SEPOLIA_RPC_URL and network"]
    async fn live_probe_reproduces_the_partner_case() {
        let Ok(url) = std::env::var("SEPOLIA_RPC_URL") else {
            eprintln!("SEPOLIA_RPC_URL unset; skipping");
            return;
        };
        let provider = alloy::providers::ProviderBuilder::new()
            .connect(&url)
            .await
            .expect("connect");
        // abi.encode(0xb2d9…87bac, 0, 50_000, transfer(0x…01, 1968e18)) as indexed on usc-devnet.
        let payload = hex::decode(concat!(
            "000000000000000000000000b2d93bdbca037cd71c070368ae59773e83b87bac",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000c350",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000044",
            "a9059cbb",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "00000000000000000000000000000000000000000000006aaf7c8516d0c00000",
            "00000000000000000000000000000000000000000000000000000000",
        ))
        .expect("hex");
        let detail = probe_destination_revert(
            &provider,
            address!("5dF0F2D8fdb0b5Ca0815c8959154862F84ff80AB"),
            address!("2FabAFfC7F6426C1beEdec22cc150A7dBE6667FB"),
            &payload,
            Some(11_727_197),
        )
        .await
        .expect("replay answered");
        eprintln!("replay says: {detail}");
        assert!(
            detail.starts_with("ERC20InsufficientBalance(sender 0x5dF0"),
            "{detail}"
        );
        assert!(detail.contains("needed 1968000000000000000000"), "{detail}");
    }
}
