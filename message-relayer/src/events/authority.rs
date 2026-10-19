//! Historical source authorization. The governance-selected registry and its Outbox membership
//! are both read at the message's finalized source block, never at the current head.

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::BlockNumberOrTag;
use alloy::sol_types::SolCall;
use anyhow::{Context, Result};

use super::RPC_TIMEOUT;
use crate::abi::IOutboxDiscovery;

alloy::sol! {
    /// Governance-selected Outbox discovery registry from the chain-info precompile.
    #[sol(rpc)]
    contract IChainInfo {
        function get_outbox_discovery_address(uint64 chainKey)
            external view returns (address discoveryAddr, bool exists);
    }
}

const CHAIN_INFO_PRECOMPILE: Address =
    alloy::primitives::address!("0000000000000000000000000000000000000fd3");

pub(super) fn registry_chain_key(chain_key: u64) -> Result<u32> {
    u32::try_from(chain_key).context("chain_key exceeds the uint32 Outbox registry key")
}

pub(super) async fn discovery_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    block: u64,
) -> Result<Option<Address>> {
    registry_chain_key(chain_key)?;
    let binding = IChainInfo::new(CHAIN_INFO_PRECOMPILE, provider);
    let call = binding
        .get_outbox_discovery_address(chain_key)
        .block(BlockNumberOrTag::Number(block).into());
    let bytes = tokio::time::timeout(RPC_TIMEOUT, call.call_raw())
        .await
        .context("historical Discovery lookup timed out")?
        .context("historical Discovery lookup failed")?;
    let result = decode_response::<IChainInfo::get_outbox_discovery_addressCall>(&bytes)
        .context("malformed historical Discovery response")?;
    Ok((result.exists && !result.discoveryAddr.is_zero()).then_some(result.discoveryAddr))
}

pub(super) async fn authorized_at<P: Provider>(
    provider: &P,
    chain_key: u64,
    discovery: Address,
    outbox: Address,
    block: u64,
) -> Result<bool> {
    let binding = IOutboxDiscovery::new(discovery, provider);
    let call = binding
        .isActiveOutbox(registry_chain_key(chain_key)?, outbox)
        .block(BlockNumberOrTag::Number(block).into());
    let bytes = tokio::time::timeout(RPC_TIMEOUT, call.call_raw())
        .await
        .context("historical membership lookup timed out")?
        .context("historical membership lookup failed")?;
    decode_response::<IOutboxDiscovery::isActiveOutboxCall>(&bytes)
        .context("malformed historical Outbox membership response")
}

fn decode_response<C: SolCall>(bytes: &[u8]) -> Result<C::Return> {
    let decoded = C::abi_decode_returns_validate(bytes)?;
    // The ABI decoder accepts non-zero bool words beyond 1. Require canonical encoding before
    // using any response as authorization, and reject trailing/padded data as well.
    anyhow::ensure!(
        C::abi_encode_returns(&decoded) == bytes,
        "non-canonical authorization response"
    );
    Ok(decoded)
}
