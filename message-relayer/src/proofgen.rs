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
//!   existed also answers 404 — the caller's bounded fast-poll window and capped slow backoff
//!   prevent hot-looping while preserving any outstanding settlement obligation.
//!
//! A third class is a *permanent* refusal: a 4xx (other than 404/422) whose body says
//! `"retriable": false`, proof-gen's own statement that repeating the identical request cannot
//! help. It maps to [`ProofFetch::Rejected`]. On asc-devnet (2026-10-23) every ck2 proof that needed
//! a whole checkpoint span answered `400 ArchiverRangeRejected`, because the archiver's `/roots`
//! cap (1000 blocks) was below the 6000-block span; the acks backed off as transient errors under a
//! log that pointed at the signer balance. Callers keep the obligation (the proof is servable again
//! once proof-gen or its archiver is fixed) but skip the exponential ramp and say what is wrong.
//!
//! A fourth class is a *server-declared transient* condition: a 5xx whose body says
//! `"retriable": true` with a `code`. proof-gen is up and answering, and is saying the same request
//! will succeed once something it depends on catches up. On asc-devnet (2026-11-03) a ck3 proof
//! answered `503 ArchiverDataUnavailable` ("archiver has not yet indexed every root for range
//! 54000001..54001800: expected 1800 roots, found 347") for as long as the archiver backfilled;
//! counting each of those as a transient *error* moved `relayer_ack_submissions{outcome="Failed"}`
//! and the claim equivalent, the outage signal, for what is ordinary lag. It maps to
//! [`ProofFetch::NotReady`] with proof-gen's code and message carried into the log.
//!
//! Everything else (a 5xx without that flag — including a proxy's HTML 502/503 page, a 5xx that says
//! `retriable: false`, connection errors, a 4xx without the flag, an unparseable proof) is an `Err`.
//!
//! Every request carries a `User-Agent` naming the relayer version and git commit (see
//! [`user_agent`]) so proof-gen's request logs can attribute traffic to a build instead of logging
//! `user_agent=unknown`.

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
    /// Proof-gen cannot serve this proof *yet* (HTTP 422 / 404, or a 5xx that declares itself
    /// `retriable: true` — see the module docs). Not an error: callers poll on a steady cadence
    /// instead of backing off.
    NotReady(ProofNotReady),
    /// Proof-gen refuses this request and says repeating it unchanged cannot help (HTTP 4xx with
    /// `"retriable": false` — see the module docs). The request is not retriable, but the
    /// settlement obligation stays: it can succeed once proof-gen or its archiver is fixed.
    Rejected(ProofRejected),
}

/// Why proof-gen could not serve a proof yet — carried on [`ProofFetch::NotReady`] so the
/// caller's deferral log names the state instead of a bare "not ready".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofNotReady {
    /// HTTP status proof-gen answered with (422, 404, or a retriable 5xx).
    pub status: u16,
    /// proof-gen's `code` from its JSON error body (`BlockNotReady`, `TxHashNotFound`,
    /// `ArchiverDataUnavailable`, …), or the status' canonical reason phrase when the body carried
    /// no parseable code.
    pub code: String,
    /// proof-gen's human-readable `message` (empty when the body carried none). It names what
    /// proof-gen is waiting on — the block and last attested block, or the archiver's missing
    /// range — which the code alone does not.
    pub message: String,
}

impl std::fmt::Display for ProofNotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} {}", self.status, self.code)?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

/// Why proof-gen permanently refused a request — carried on [`ProofFetch::Rejected`] so the
/// caller's log names the cause (`ArchiverRangeRejected`, the archiver's own wording) instead of
/// a bare status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofRejected {
    /// HTTP status proof-gen answered with (a 4xx other than 404/422).
    pub status: u16,
    /// proof-gen's `code` from its JSON error body (`ArchiverRangeRejected`, …).
    pub code: String,
    /// proof-gen's human-readable `message` (empty when the body carried none).
    pub message: String,
}

impl std::fmt::Display for ProofRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} {}", self.status, self.code)?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

/// The subset of proof-gen's `ErrorResponse` body we read back (`code` names its `ServiceError`
/// variant, `retriable` says whether repeating the identical request can succeed). Everything else
/// in the body is ignored.
#[derive(Debug, Deserialize)]
struct ProofGenErrorBody {
    code: Option<String>,
    message: Option<String>,
    retriable: Option<bool>,
}

/// `Some` when a 4xx response carries proof-gen's JSON error body with an explicit
/// `"retriable": false` and a code. A missing flag, `true`, an unparseable body and every non-4xx
/// status stay errors: only proof-gen's own word makes a refusal permanent.
fn rejection(status: reqwest::StatusCode, body: &str) -> Option<ProofRejected> {
    if !status.is_client_error() {
        return None;
    }
    let parsed = serde_json::from_str::<ProofGenErrorBody>(body).ok()?;
    if parsed.retriable != Some(false) {
        return None;
    }
    let code = parsed.code.filter(|c| !c.trim().is_empty())?;
    Some(ProofRejected {
        status: status.as_u16(),
        code,
        message: parsed.message.unwrap_or_default(),
    })
}

/// `Some` when a 5xx response carries proof-gen's JSON error body with an explicit
/// `"retriable": true` and a code: proof-gen answered, and says the identical request will succeed
/// once something it depends on (its archiver, its attestation view) catches up. A missing flag,
/// `false`, an unparseable body (a proxy's HTML error page, an empty body) and every non-5xx
/// status return `None` and stay errors: without proof-gen's own word a 5xx is infrastructure.
fn retriable_server_error(status: reqwest::StatusCode, body: &str) -> Option<ProofNotReady> {
    if !status.is_server_error() {
        return None;
    }
    let parsed = serde_json::from_str::<ProofGenErrorBody>(body).ok()?;
    if parsed.retriable != Some(true) {
        return None;
    }
    let code = parsed.code.filter(|c| !c.trim().is_empty())?;
    Some(ProofNotReady {
        status: status.as_u16(),
        code,
        message: parsed.message.unwrap_or_default(),
    })
}

/// Classify one proof-gen response into ready / not-ready / rejected / error. Pure, so the mapping is
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
        let parsed = serde_json::from_str::<ProofGenErrorBody>(body).ok();
        let code = parsed
            .as_ref()
            .and_then(|b| b.code.clone())
            .filter(|c| !c.trim().is_empty())
            .unwrap_or_else(|| {
                status
                    .canonical_reason()
                    .unwrap_or("not ready")
                    .replace(' ', "")
            });
        let message = parsed.and_then(|b| b.message).unwrap_or_default();
        return Ok(ProofFetch::NotReady(ProofNotReady {
            status: status.as_u16(),
            code,
            message,
        }));
    }
    if let Some(not_ready) = retriable_server_error(status, body) {
        return Ok(ProofFetch::NotReady(not_ready));
    }
    if let Some(rejected) = rejection(status, body) {
        return Ok(ProofFetch::Rejected(rejected));
    }
    if !status.is_success() {
        anyhow::bail!("proof-gen returned {status} for {url}: {body}");
    }
    let parsed: SingleContinuityResponse = serde_json::from_str(body)
        .with_context(|| format!("decoding proof-gen response from {url}"))?;
    Ok(ProofFetch::Ready(parsed))
}

/// The `User-Agent` sent on every proof-gen request: `asc-message-relayer/<version> (<commit>)`.
/// The commit is embedded by `build.rs` (`GIT_COMMIT` in the Docker build, `git rev-parse` in a
/// checkout) and is `unknown` when neither is available.
pub fn user_agent() -> String {
    format!(
        "asc-message-relayer/{} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("RELAYER_GIT_COMMIT")
    )
}

impl ProofGenClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(user_agent())
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
            ProofFetch::Rejected(_) => panic!("{status} must not classify as Rejected"),
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
        assert_eq!(r.message, "...");
        assert_eq!(r.to_string(), "HTTP 422 BlockNotReady: ...");

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
        // No body, no message: Display must not leave a dangling ": ".
        assert_eq!(not_ready(404, "").to_string(), "HTTP 404 NotFound");
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

    /// The 2026-10-23 asc-devnet shape: the archiver's `/roots` cap (1000) was below the 6000-block
    /// checkpoint span, so proof-gen answered 400 `ArchiverRangeRejected` with `retriable: false`
    /// for every ck2 proof that needed a whole span.
    #[test]
    fn classifies_retriable_false_4xx_as_rejected() {
        let url = "http://pg/api/v1/proof-by-tx/2/0x1";
        let body = r#"{"code":"ArchiverRangeRejected","message":"archiver cannot serve roots for range 48996001..49002000: range too large (max 1000 blocks)","retriable":false}"#;
        let rejected =
            match classify_proof_response(reqwest::StatusCode::BAD_REQUEST, body, url).unwrap() {
                ProofFetch::Rejected(r) => r,
                _ => panic!("a retriable:false 400 must classify as Rejected"),
            };
        assert_eq!(rejected.status, 400);
        assert_eq!(rejected.code, "ArchiverRangeRejected");
        assert!(rejected
            .message
            .contains("range too large (max 1000 blocks)"));
        assert_eq!(
            rejected.to_string(),
            "HTTP 400 ArchiverRangeRejected: archiver cannot serve roots for range \
             48996001..49002000: range too large (max 1000 blocks)"
        );

        // The message is optional; Display must not leave a dangling ": ".
        let bare = rejection(
            reqwest::StatusCode::FORBIDDEN,
            r#"{"code":"Forbidden","retriable":false}"#,
        )
        .unwrap();
        assert_eq!(bare.to_string(), "HTTP 403 Forbidden");
    }

    /// Only proof-gen's own explicit word makes a refusal permanent. Everything else keeps taking
    /// the transient backoff, exactly as before.
    #[test]
    fn rejected_requires_an_explicit_retriable_false_on_a_4xx() {
        let url = "http://pg/api/v1/proof-by-tx/2/0x1";
        let is_err = |status: u16, body: &str| {
            classify_proof_response(reqwest::StatusCode::from_u16(status).unwrap(), body, url)
                .is_err()
        };
        // Flag missing, or true: still a (transient) error.
        assert!(is_err(400, r#"{"code":"ArchiverRangeRejected"}"#));
        assert!(is_err(400, r#"{"code":"X","retriable":true}"#));
        // No usable code, or a body that is not proof-gen's JSON (a proxy's page, an empty body).
        assert!(is_err(400, r#"{"retriable":false}"#));
        assert!(is_err(400, r#"{"code":"","retriable":false}"#));
        assert!(is_err(400, "<html>bad request</html>"));
        assert!(is_err(400, ""));
        // 5xx stays an error unless proof-gen explicitly says `retriable: true` (see
        // `classifies_retriable_true_5xx_as_not_ready`): `false`, a missing flag, no code or a
        // non-JSON body (a proxy's error page) are infrastructure.
        assert!(is_err(500, r#"{"code":"Internal","retriable":false}"#));
        assert!(is_err(503, r#"{"code":"Unavailable","retriable":false}"#));
        assert!(is_err(503, r#"{"code":"Unavailable"}"#));
        assert!(is_err(503, r#"{"retriable":true}"#));
        assert!(is_err(503, r#"{"code":"","retriable":true}"#));
        assert!(is_err(502, "<html>bad gateway</html>"));
        assert!(is_err(503, ""));
        // `retriable: true` only upgrades a 5xx; a 4xx keeps its own rules.
        assert!(is_err(400, r#"{"code":"X","retriable":true}"#));
        // 404 and 422 keep their "not yet" meaning regardless of the flag.
        for status in [404u16, 422] {
            let r = classify_proof_response(
                reqwest::StatusCode::from_u16(status).unwrap(),
                r#"{"code":"TxHashNotFound","retriable":false}"#,
                url,
            )
            .unwrap();
            assert!(
                matches!(r, ProofFetch::NotReady(_)),
                "{status} stays NotReady"
            );
        }
    }

    /// The 2026-11-03 asc-devnet shape: while the archiver backfilled, proof-gen answered
    /// `503 ArchiverDataUnavailable` with `retriable: true`. That is "not yet", not an outage, so
    /// it must not take the error path that moves the `Failed` settlement counters.
    #[test]
    fn classifies_retriable_true_5xx_as_not_ready() {
        let url = "http://pg/api/v1/proof-by-tx/3/0x1";
        let body = r#"{"code":"ArchiverDataUnavailable","message":"archiver has not yet indexed every root for range 54000001..54001800: incomplete data: expected 1800 roots for range 54000001..=54001800, found 347","retriable":true}"#;
        for status in [500u16, 502, 503, 504] {
            let r = match classify_proof_response(
                reqwest::StatusCode::from_u16(status).unwrap(),
                body,
                url,
            )
            .unwrap()
            {
                ProofFetch::NotReady(r) => r,
                _ => panic!("a retriable:true {status} must classify as NotReady"),
            };
            assert_eq!(r.status, status);
            assert_eq!(r.code, "ArchiverDataUnavailable");
            assert!(r.message.contains("found 347"));
            assert!(r.to_string().starts_with(&format!(
                "HTTP {status} ArchiverDataUnavailable: archiver has"
            )));
        }
    }

    /// The message is optional on the retriable 5xx path too.
    #[test]
    fn retriable_5xx_without_a_message_has_no_dangling_separator() {
        let r = retriable_server_error(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"code":"ArchiverDataUnavailable","retriable":true}"#,
        )
        .unwrap();
        assert_eq!(r.to_string(), "HTTP 503 ArchiverDataUnavailable");
    }

    #[test]
    fn user_agent_names_version_and_commit() {
        let ua = user_agent();
        let prefix = format!("asc-message-relayer/{} (", env!("CARGO_PKG_VERSION"));
        assert!(ua.starts_with(&prefix), "{ua}");
        assert!(ua.ends_with(')'), "{ua}");
        let commit = &ua[prefix.len()..ua.len() - 1];
        assert!(
            commit == "unknown" || commit.chars().all(|c| c.is_ascii_hexdigit()),
            "commit must be hex or `unknown`, got {commit:?}"
        );
        assert!(
            reqwest::header::HeaderValue::from_str(&ua).is_ok(),
            "must be a valid header value: {ua}"
        );
    }

    /// The header must actually reach the wire, not just be computable.
    #[tokio::test]
    async fn client_sends_the_user_agent_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let seen_in_handler = seen.clone();
        let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
            let seen = seen_in_handler.clone();
            async move {
                *seen.lock().unwrap() = headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                (axum::http::StatusCode::NOT_FOUND, "")
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = ProofGenClient::new(&url).unwrap();
        let fetched = client.proof_by_tx(2, B256::ZERO).await.unwrap();
        assert!(matches!(fetched, ProofFetch::NotReady(_)));
        assert_eq!(seen.lock().unwrap().as_deref(), Some(user_agent().as_str()));
        server.abort();
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
