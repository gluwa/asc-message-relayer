//! Per-route EIP-712 message-vote domain (CSUB-2126).
//!
//! Attestors sign each message vote over [`MessageVoteDomain::digest`], which binds the
//! `messageId` to the destination chain id, the destination `EOAValidator` (EIP-712
//! `verifyingContract`) and the destination Inbox. The pool recovers signers against that digest,
//! so every route needs its domain before it can count a single vote:
//!
//! * `chain_id` is read from the destination RPC (`eth_chainId`);
//! * `validator` is the route's `attestor_set` validator ([`AttestorSet::validator`]);
//! * `inbox` is the route's configured `inbox_address`.
//!
//! Before trusting the domain, [`read`] asks the validator for its ERC-5267 `eip712Domain()` and
//! requires it to match. That catches a relayer pointed at a pre-EIP-712 validator (which verifies
//! raw-`messageId` signatures and has no `eip712Domain()`) or at a validator deployed with a
//! different name/version: in both cases every bundle the relayer assembled would revert on
//! delivery.
//!
//! None of this happens at startup. The per-route attestor-set watcher (`attestor_set::run`) calls
//! [`read`] on every poll together with `attestors()` / `threshold()`, and only hands the pool a
//! set once all of it succeeded. Until then the route accepts no vote; an incompatible validator
//! is logged as an error and reported on `/health` as a degraded route, and the relayer keeps
//! running (and journaling source messages) meanwhile.
//!
//! [`AttestorSet::validator`]: crate::config::AttestorSet::validator

use std::time::Duration;

use alloy::primitives::{FixedBytes, U256};
use alloy::providers::Provider;
use anyhow::{anyhow, bail, Context, Result};
use write_ability::hash::{
    MessageVoteDomain, MESSAGE_VOTE_DOMAIN_NAME, MESSAGE_VOTE_DOMAIN_VERSION,
};

use crate::config::ChainRoute;

alloy::sol! {
    /// ERC-5267 domain introspection, as OZ `EIP712` implements it.
    #[sol(rpc)]
    #[derive(Debug)]
    interface IERC5267 {
        function eip712Domain() external view returns (
            bytes1 fields,
            string name,
            string version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] extensions
        );
    }
}

/// ERC-5267 `fields` bitmap for a domain of exactly name, version, chainId and verifyingContract
/// (bits 0..=3; bit 4 would be a salt, which [`MessageVoteDomain`] does not use).
const EXPECTED_DOMAIN_FIELDS: u8 = 0x0f;

/// Per-call timeout for the domain reads.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Why the domain could not be read, split by whether the next poll can help.
#[derive(Debug)]
pub enum DomainError {
    /// RPC unreachable / timed out. The next poll retries.
    Transient(anyhow::Error),
    /// The validator is not an EIP-712 `EOAValidator` matching this route (a revert, no data, or
    /// a domain mismatch). Retrying only helps once the validator or config changes.
    Incompatible(anyhow::Error),
}

/// Read the destination chain id and verify the validator's ERC-5267 domain for `route`'s message
/// votes. Called by the attestor-set watcher on every poll.
pub async fn read<P: Provider>(
    provider: &P,
    route: &ChainRoute,
) -> Result<MessageVoteDomain, DomainError> {
    let validator = route.attestor_set.validator;

    let chain_id = tokio::time::timeout(CALL_TIMEOUT, provider.get_chain_id())
        .await
        .map_err(|_| DomainError::Transient(anyhow!("eth_chainId timed out")))?
        .context("eth_chainId")
        .map_err(DomainError::Transient)?;

    let domain = MessageVoteDomain {
        chain_id,
        validator,
        inbox: route.inbox_address,
    };

    let reported = tokio::time::timeout(
        CALL_TIMEOUT,
        IERC5267::new(validator, provider).eip712Domain().call(),
    )
    .await
    .map_err(|_| DomainError::Transient(anyhow!("eip712Domain() timed out")))?
    .map_err(|err| {
        if is_permanent_call_error(&err) {
            DomainError::Incompatible(anyhow!(
                "eip712Domain() is not answered ({err}); a pre-EIP-712 validator that verifies \
                 raw-messageId votes, or not a validator at all"
            ))
        } else {
            DomainError::Transient(anyhow!(err).context("eip712Domain()"))
        }
    })?;

    check_reported_domain(&domain, &reported).map_err(DomainError::Incompatible)?;
    Ok(domain)
}

/// A call error that retrying will not fix: the node executed the call and it reverted, or it
/// returned nothing / undecodable data (no such function, or no contract at the address).
fn is_permanent_call_error(err: &alloy::contract::Error) -> bool {
    match err {
        alloy::contract::Error::ZeroData(..) | alloy::contract::Error::AbiError(_) => true,
        alloy::contract::Error::TransportError(e) => e.as_error_resp().is_some_and(|payload| {
            // Geth-style code 3 carries revert data; nodes without data use a message.
            payload.code == 3 || payload.message.to_ascii_lowercase().contains("revert")
        }),
        _ => false,
    }
}

/// Require the validator's ERC-5267 domain to equal the one the relayer recovers votes under.
fn check_reported_domain(
    expected: &MessageVoteDomain,
    reported: &IERC5267::eip712DomainReturn,
) -> Result<()> {
    let mut mismatches = Vec::new();
    if reported.fields != FixedBytes([EXPECTED_DOMAIN_FIELDS]) {
        mismatches.push(format!(
            "fields {} (expected 0x{EXPECTED_DOMAIN_FIELDS:02x}: name, version, chainId, \
             verifyingContract)",
            reported.fields
        ));
    }
    if reported.name != MESSAGE_VOTE_DOMAIN_NAME {
        mismatches.push(format!(
            "name {:?} (expected {MESSAGE_VOTE_DOMAIN_NAME:?})",
            reported.name
        ));
    }
    if reported.version != MESSAGE_VOTE_DOMAIN_VERSION {
        mismatches.push(format!(
            "version {:?} (expected {MESSAGE_VOTE_DOMAIN_VERSION:?})",
            reported.version
        ));
    }
    if reported.chainId != U256::from(expected.chain_id) {
        mismatches.push(format!(
            "chainId {} (expected {} from eth_chainId)",
            reported.chainId, expected.chain_id
        ));
    }
    if reported.verifyingContract != expected.validator {
        mismatches.push(format!(
            "verifyingContract {} (expected {})",
            reported.verifyingContract, expected.validator
        ));
    }
    if !reported.extensions.is_empty() {
        mismatches.push(format!(
            "{} extensions (expected none)",
            reported.extensions.len()
        ));
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        bail!("eip712Domain() mismatch: {}", mismatches.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, Address, B256};

    const DOMAIN: MessageVoteDomain = MessageVoteDomain {
        chain_id: 11_155_111,
        validator: address!("71a21ea8d28d3a0618d61d478ee20dcb64be8082"),
        inbox: address!("5fbdb2315678afecb367f032d93f642f64180aa3"),
    };

    /// What OZ `EIP712("ASC EOAValidator", "1")` deployed at `DOMAIN.validator` returns.
    fn oz_domain() -> IERC5267::eip712DomainReturn {
        IERC5267::eip712DomainReturn {
            fields: FixedBytes([0x0f]),
            name: MESSAGE_VOTE_DOMAIN_NAME.to_string(),
            version: MESSAGE_VOTE_DOMAIN_VERSION.to_string(),
            chainId: U256::from(DOMAIN.chain_id),
            verifyingContract: DOMAIN.validator,
            salt: B256::ZERO,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn matching_domain_is_accepted() {
        check_reported_domain(&DOMAIN, &oz_domain()).unwrap();
    }

    #[test]
    fn every_mismatching_field_is_reported() {
        let cases: Vec<(&str, IERC5267::eip712DomainReturn)> = vec![
            (
                "name",
                IERC5267::eip712DomainReturn {
                    name: "EOAValidator".into(),
                    ..oz_domain()
                },
            ),
            (
                "version",
                IERC5267::eip712DomainReturn {
                    version: "2".into(),
                    ..oz_domain()
                },
            ),
            (
                "chainId",
                IERC5267::eip712DomainReturn {
                    chainId: U256::from(1u64),
                    ..oz_domain()
                },
            ),
            (
                "verifyingContract",
                IERC5267::eip712DomainReturn {
                    verifyingContract: Address::repeat_byte(0x01),
                    ..oz_domain()
                },
            ),
            (
                "fields",
                IERC5267::eip712DomainReturn {
                    fields: FixedBytes([0x1f]),
                    ..oz_domain()
                },
            ),
            (
                "extensions",
                IERC5267::eip712DomainReturn {
                    extensions: vec![U256::from(1u64)],
                    ..oz_domain()
                },
            ),
        ];
        for (field, reported) in cases {
            let err = check_reported_domain(&DOMAIN, &reported).unwrap_err();
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn reverts_and_empty_returns_are_permanent_but_transport_failures_are_not() {
        use alloy::transports::{RpcError, TransportErrorKind};

        // Deserialized rather than named: `ErrorPayload` lives in alloy-json-rpc, which the
        // umbrella crate only re-exports behind a feature this workspace does not enable.
        let resp = |code: i64, message: &str| {
            alloy::contract::Error::TransportError(RpcError::ErrorResp(
                serde_json::from_value(serde_json::json!({ "code": code, "message": message }))
                    .unwrap(),
            ))
        };
        assert!(is_permanent_call_error(&resp(3, "execution reverted")));
        assert!(is_permanent_call_error(&resp(-32000, "execution reverted")));
        assert!(!is_permanent_call_error(&resp(-32005, "limit exceeded")));

        let down = alloy::contract::Error::TransportError(TransportErrorKind::backend_gone());
        assert!(!is_permanent_call_error(&down));

        let zero = alloy::contract::Error::ZeroData(
            "eip712Domain".into(),
            alloy::sol_types::Error::Overrun.into(),
        );
        assert!(is_permanent_call_error(&zero));
    }
}
