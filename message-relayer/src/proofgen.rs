//! Shared HTTP client for the proof-gen API server's `proof-by-tx` endpoint, used by every
//! proof submitter (ack, claim).
//!
//! `GET {base}/api/v1/proof-by-tx/{chain_key}/{tx_hash}` returns the prover `txBytes` (encoded
//! tx + receipt) plus the merkle-inclusion and continuity proofs for the block containing the
//! transaction.
//!
//! Two response classes mean "not yet" rather than "failed", and are mapped to
//! [`ProofFetch::NotReady`] so callers poll instead of backing off as if the service were broken:
//!
//! - HTTP 422 `BlockNotReady` — the block exists but is not yet attested on Creditcoin. The normal
//!   early state of every request (destination finality + attestation take minutes).
//! - HTTP 404 (`TxHashNotFound`, `BlockNotOnSourceChain`, `AttestationsMissing`) — proof-gen's own
//!   view of the destination chain has not caught up with the tx yet: its source RPC has not
//!   indexed the tx, the block is still inside proof-gen's reorg-protection window, or the chain
//!   has no attestations at all yet. On usc-devnet (2026-09-08) a delivery was answered 404 four
//!   times over six minutes and then served normally; treating each 404 as a transient *error*
//!   put the ack on the 30 s-doubling backoff and landed it 17 minutes after delivery, about four
//!   of them pure backoff after the proof had become available. A tx hash that genuinely never
//!   existed also answers 404 — the caller's bounded fast-poll window, slow backoff and age
//!   give-up cover that case, so it is not worth classifying differently here.
//!
//! Everything else (5xx, connection errors, an unparseable proof) is an `Err`.

use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Bytes, B256};
use anyhow::{Context, Result};
use serde::Deserialize;

use alloy::sol_types::SolValue;

use crate::abi::{ContinuityProof, InclusionProof, MerkleProof, MerkleProofEntry};

/// Minimal HTTP client for the proof-gen API server's `proof-by-tx` endpoint.
pub struct ProofGenClient {
    http: reqwest::Client,
    base: String,
}

pub enum ProofFetch {
    Ready(SingleContinuityResponse),
    /// Proof-gen cannot serve this proof *yet* (HTTP 422 / 404 — see the module docs). Not an
    /// error: callers poll on a steady cadence instead of backing off.
    NotReady(ProofNotReady),
}

/// Why proof-gen could not serve a proof yet — carried on [`ProofFetch::NotReady`] so the
/// caller's deferral log names the state instead of a bare "not ready".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofNotReady {
    /// HTTP status proof-gen answered with (422 or 404).
    pub status: u16,
    /// proof-gen's `code` from its JSON error body (`BlockNotReady`, `TxHashNotFound`, …), or the
    /// status' canonical reason phrase when the body carried no parseable code.
    pub code: String,
}

impl std::fmt::Display for ProofNotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} {}", self.status, self.code)
    }
}

/// The subset of proof-gen's `ErrorResponse` body we read back (`code` names its `ServiceError`
/// variant). Everything else in the body is ignored.
#[derive(Debug, Deserialize)]
struct ProofGenErrorBody {
    code: Option<String>,
}

/// Classify one proof-gen response into ready / not-ready / error. Pure, so the mapping is
/// unit-tested without a server: `status` and `body` are the raw HTTP response, `url` only feeds
/// error messages.
pub fn classify_proof_response(
    status: reqwest::StatusCode,
    body: &str,
    url: &str,
) -> Result<ProofFetch> {
    if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        || status == reqwest::StatusCode::NOT_FOUND
    {
        let code = serde_json::from_str::<ProofGenErrorBody>(body)
            .ok()
            .and_then(|b| b.code)
            .filter(|c| !c.trim().is_empty())
            .unwrap_or_else(|| {
                status
                    .canonical_reason()
                    .unwrap_or("not ready")
                    .replace(' ', "")
            });
        return Ok(ProofFetch::NotReady(ProofNotReady {
            status: status.as_u16(),
            code,
        }));
    }
    if !status.is_success() {
        anyhow::bail!("proof-gen returned {status} for {url}: {body}");
    }
    let parsed: SingleContinuityResponse = serde_json::from_str(body)
        .with_context(|| format!("decoding proof-gen response from {url}"))?;
    Ok(ProofFetch::Ready(parsed))
}

impl ProofGenClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build proof-gen HTTP client")?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn proof_by_tx(&self, chain_key: u64, tx_hash: B256) -> Result<ProofFetch> {
        let url = format!(
            "{}/api/v1/proof-by-tx/{}/{:#x}",
            self.base, chain_key, tx_hash
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url} failed"))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .with_context(|| format!("reading body of {url}"))?;
        classify_proof_response(status, &body, &url)
    }
}

// ---------------------------------------------------------------------------
// proof-gen response shape (mirrors proof-gen-api-server SingleContinuityResponse)
// ---------------------------------------------------------------------------

/// Subset of the proof-gen `SingleContinuityResponse` the submitters need. Field names are
/// camelCase to match the server's `#[serde(rename_all = "camelCase")]`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleContinuityResponse {
    pub header_number: u64,
    /// Hex-encoded prover `txBytes` (encoded tx + receipt). `None` when the server only returned a
    /// continuity proof (no merkle inclusion) — which would not satisfy any proof consumer.
    tx_bytes: Option<String>,
    continuity_proof: ContinuityProofJson,
    merkle_proof: MerkleProofJson,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinuityProofJson {
    lower_endpoint_digest: String,
    roots: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MerkleProofJson {
    root: String,
    siblings: Vec<MerkleProofEntryJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MerkleProofEntryJson {
    hash: String,
    is_left: bool,
}

impl SingleContinuityResponse {
    /// Hex-decode the prover `txBytes` into the calldata the on-chain verifier expects.
    pub fn encoded_transaction(&self) -> Result<Bytes> {
        let raw = self.tx_bytes.as_deref().context(
            "proof-gen response missing txBytes (continuity-only proof cannot be submitted)",
        )?;
        let bytes =
            hex::decode(raw.trim_start_matches("0x")).context("txBytes is not valid hex")?;
        Ok(Bytes::from(bytes))
    }

    /// Convert the JSON proof bundle into the `sol!`-generated argument structs.
    pub fn to_proofs(&self) -> Result<(MerkleProof, ContinuityProof)> {
        let merkle = MerkleProof {
            root: parse_b256(&self.merkle_proof.root).context("merkle_proof.root")?,
            siblings: self
                .merkle_proof
                .siblings
                .iter()
                .map(|s| {
                    Ok(MerkleProofEntry {
                        hash: parse_b256(&s.hash).context("merkle_proof.siblings[].hash")?,
                        isLeft: s.is_left,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };

        let continuity = ContinuityProof {
            lowerEndpointDigest: parse_b256(&self.continuity_proof.lower_endpoint_digest)
                .context("continuity_proof.lower_endpoint_digest")?,
            roots: self
                .continuity_proof
                .roots
                .iter()
                .map(|r| parse_b256(r).context("continuity_proof.roots[]"))
                .collect::<Result<Vec<_>>>()?,
        };

        Ok((merkle, continuity))
    }

    /// Build the PR #23 `(InclusionProof, ContinuityProof)` pair consumed by
    /// `RelayerContract.claimDelivery` and `AcknowledgmentValidator.submitAcknowledgment`. The inclusion proof is the self-describing
    /// `BlockProverTypes.InclusionProof`: `kind = BinaryMerkle` (0), `root` = the transaction-trie
    /// root, and `data = abi.encode(bytes txBytes, MerkleProofEntry[] siblings)` — exactly what
    /// `QueryProofVerificationLib.decodeBinaryMerklePayload` decodes on-chain. The continuity proof
    /// is identical to the flat-`MerkleProof` path's ([`to_proofs`](Self::to_proofs)).
    pub fn to_inclusion_and_continuity(&self) -> Result<(InclusionProof, ContinuityProof)> {
        let tx_bytes = self.encoded_transaction()?;
        let (merkle, continuity) = self.to_proofs()?;
        // `abi.encode(bytes, MerkleProofEntry[])` == `abi_encode_params` of the 2-tuple. The
        // MerkleProofEntry wire layout (bytes32 + bool) matches BlockProverTypes.MerkleProofEntry, so
        // the same siblings re-encode without a distinct type.
        let data = (tx_bytes, merkle.siblings).abi_encode_params();
        let inclusion = InclusionProof {
            kind: 0, // BlockProverTypes.ProofKind.BinaryMerkle
            root: merkle.root,
            data: data.into(),
        };
        Ok((inclusion, continuity))
    }
}

fn parse_b256(s: &str) -> Result<B256> {
    B256::from_str(s.trim()).with_context(|| format!("not a 32-byte hex value: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "headerNumber": 42,
        "txBytes": "0xdeadbeef",
        "continuityProof": {
            "lowerEndpointDigest": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "roots": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
        },
        "merkleProof": {
            "root": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "siblings": [
                { "hash": "0x4444444444444444444444444444444444444444444444444444444444444444", "isLeft": true }
            ]
        }
    }"#;

    #[test]
    fn parses_proof_gen_response_and_builds_sol_structs() {
        let parsed: SingleContinuityResponse = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(parsed.header_number, 42);
        assert_eq!(
            parsed.encoded_transaction().unwrap().as_ref(),
            [0xde, 0xad, 0xbe, 0xef]
        );
        let (merkle, continuity) = parsed.to_proofs().unwrap();
        assert_eq!(merkle.siblings.len(), 1);
        assert!(merkle.siblings[0].isLeft);
        assert_eq!(continuity.roots.len(), 1);
    }

    fn not_ready(status: u16, body: &str) -> ProofNotReady {
        let status = reqwest::StatusCode::from_u16(status).unwrap();
        match classify_proof_response(status, body, "http://pg/api/v1/proof-by-tx/8/0x1").unwrap() {
            ProofFetch::NotReady(r) => r,
            ProofFetch::Ready(_) => panic!("{status} must not classify as Ready"),
        }
    }

    /// The 2026-09-08 usc-devnet shape: proof-gen answered 404 while its view of the destination
    /// chain lagged the delivery, and every 404 was treated as a transient error (30 s-doubling
    /// backoff). 404 and 422 are both "not yet"; the body's `code` rides along for the log.
    #[test]
    fn classifies_404_and_422_as_not_ready_with_proof_gen_code() {
        let r = not_ready(
            422,
            r#"{"code":"BlockNotReady","message":"...","retriable":true,"block_number":5,"last_attested_block":4}"#,
        );
        assert_eq!(r.status, 422);
        assert_eq!(r.code, "BlockNotReady");
        assert_eq!(r.to_string(), "HTTP 422 BlockNotReady");

        for code in [
            "TxHashNotFound",
            "BlockNotOnSourceChain",
            "AttestationsMissing",
        ] {
            let r = not_ready(
                404,
                &format!(r#"{{"code":"{code}","message":"x","retriable":false}}"#),
            );
            assert_eq!(r.status, 404);
            assert_eq!(r.code, code);
        }
    }

    /// A 404/422 without a parseable JSON body (a proxy's HTML page, an empty body) is still
    /// not-ready — the status alone decides; the code falls back to the reason phrase.
    #[test]
    fn not_ready_without_a_json_body_falls_back_to_the_status_reason() {
        assert_eq!(not_ready(404, "").code, "NotFound");
        assert_eq!(not_ready(404, "<html>nope</html>").code, "NotFound");
        assert_eq!(not_ready(422, r#"{"code":""}"#).code, "UnprocessableEntity");
    }

    /// Real failures keep erroring so they take the transient backoff, not the fast poll: 5xx,
    /// 4xx other than 404/422, and a 200 whose body is not a proof.
    #[test]
    fn real_errors_stay_errors() {
        let url = "http://pg/api/v1/proof-by-tx/8/0x1";
        for status in [400u16, 401, 429, 500, 502, 503] {
            let status = reqwest::StatusCode::from_u16(status).unwrap();
            let err = classify_proof_response(status, r#"{"code":"Internal"}"#, url)
                .err()
                .unwrap_or_else(|| panic!("{status} must be an error"));
            assert!(err.to_string().contains(&status.as_u16().to_string()));
        }
        assert!(
            classify_proof_response(reqwest::StatusCode::OK, "not json", url).is_err(),
            "a 200 with an undecodable body is an error, not a proof"
        );
        assert!(matches!(
            classify_proof_response(reqwest::StatusCode::OK, SAMPLE, url).unwrap(),
            ProofFetch::Ready(p) if p.header_number == 42
        ));
    }

    #[test]
    fn missing_tx_bytes_is_an_error() {
        let json = SAMPLE.replace("\"txBytes\": \"0xdeadbeef\",", "");
        let parsed: SingleContinuityResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.encoded_transaction().is_err());
    }

    #[test]
    fn builds_inclusion_proof_and_data_round_trips() {
        use alloy::primitives::Bytes;

        let parsed: SingleContinuityResponse = serde_json::from_str(SAMPLE).unwrap();
        let (inclusion, continuity) = parsed.to_inclusion_and_continuity().unwrap();

        // kind = BinaryMerkle (0); root and continuity match the flat-MerkleProof path.
        assert_eq!(inclusion.kind, 0);
        let (merkle, _) = parsed.to_proofs().unwrap();
        assert_eq!(inclusion.root, merkle.root);
        assert_eq!(continuity.roots.len(), 1);

        // `data` must decode exactly as the on-chain QueryProofVerificationLib expects:
        // abi.decode(data, (bytes txBytes, MerkleProofEntry[] siblings)).
        let (tx_bytes, siblings) =
            <(Bytes, Vec<MerkleProofEntry>)>::abi_decode_params(&inclusion.data).unwrap();
        assert_eq!(tx_bytes.as_ref(), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(siblings.len(), 1);
        assert!(siblings[0].isLeft);
    }
}
