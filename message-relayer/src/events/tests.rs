use super::*;
use alloy::primitives::{Bytes, U64};
use alloy::providers::{DynProvider, ProviderBuilder};
use alloy::sol_types::SolValue;
use alloy::transports::mock::Asserter;
use axum::{extract::State, routing::post, Json, Router};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

fn source(outbox_override: Option<Address>) -> SourceRoute {
    SourceRoute {
        chain_key: 2,
        destination_chain_key: B256::repeat_byte(2),
        creditcoin_chain_id: 42,
        outbox_override,
    }
}

fn publication(outbox: Address, id: u8, height: u64) -> Log {
    let event = IOutbox::MessagePublished {
        messageId: B256::repeat_byte(id),
        emitterAddress: B256::repeat_byte(3),
        sequence: u64::from(id),
        canAck: true,
        payload: Bytes::from(vec![4, 5]),
    };
    Log {
        inner: alloy::primitives::Log {
            address: outbox,
            data: event.encode_log_data(),
        },
        block_number: Some(height),
        block_hash: Some(B256::repeat_byte(0xbb)),
        transaction_hash: Some(B256::repeat_byte(id)),
        ..Default::default()
    }
}

fn discovery(address: Address) -> Bytes {
    Bytes::from((address, !address.is_zero()).abi_encode())
}
fn membership(allowed: bool) -> Bytes {
    Bytes::from(allowed.abi_encode())
}

async fn scan<P: Provider>(
    provider: &P,
    source: SourceRoute,
    cursor: &mut u64,
) -> (Result<()>, Vec<IndexedMessage>) {
    let (tx, mut rx) = mpsc::channel(64);
    let result = poll_once(
        &source,
        &FinalityPolicy::Depth(0),
        &mut FinalityTracker::new(Instant::now()),
        provider,
        cursor,
        &tx,
        crate::prom::NoopMetrics::new().as_ref(),
        None,
        &CancellationToken::new(),
        &|| {},
    )
    .await;
    let mut messages = Vec::new();
    while let Ok(message) = rx.try_recv() {
        messages.push(message);
    }
    (result, messages)
}

#[derive(Default)]
struct RpcState {
    responses: VecDeque<Value>,
    requests: Vec<Value>,
}
struct RpcMock {
    provider: DynProvider,
    state: Arc<Mutex<RpcState>>,
    task: tokio::task::JoinHandle<()>,
}
impl RpcMock {
    async fn start(responses: Vec<Value>) -> Self {
        async fn handle(
            State(state): State<Arc<Mutex<RpcState>>>,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            let mut state = state.lock().unwrap();
            state.requests.push(request.clone());
            let mut response = state
                .responses
                .pop_front()
                .unwrap_or_else(|| json!({"error":{"code":-32603,"message":"unexpected request"}}));
            response["id"] = request["id"].clone();
            response["jsonrpc"] = json!("2.0");
            Json(response)
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = ProviderBuilder::new()
            .connect_http(
                format!("http://{}", listener.local_addr().unwrap())
                    .parse()
                    .unwrap(),
            )
            .erased();
        let state = Arc::new(Mutex::new(RpcState {
            responses: responses.into(),
            requests: Vec::new(),
        }));
        let router = Router::new()
            .route("/", post(handle))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            provider,
            state,
            task,
        }
    }
    fn requests(&self) -> Vec<Value> {
        self.state.lock().unwrap().requests.clone()
    }
}
impl Drop for RpcMock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[test]
fn checkpoint_scope_cannot_reuse_single_outbox_or_another_override() {
    let dir = tempfile::tempdir().unwrap();
    let cp = CheckpointStore::load(dir.path().join("cp.json")).unwrap();
    cp.set_with_outbox("outbox:2", 100_000, &Address::repeat_byte(1).to_string())
        .unwrap();
    let all = checkpoint_key(2, None);
    assert_eq!(
        resume_cursor(cp.get(&all), cp.has_durable_work(&all), None, 600),
        0
    );
    assert_eq!(
        resume_cursor(cp.get(&all), cp.has_durable_work(&all), Some(50), 600),
        49
    );
    let pinned = checkpoint_key(2, Some(Address::repeat_byte(1)));
    cp.set(&pinned, 5000).unwrap();
    assert_eq!(cp.get(&all), None);
    assert_eq!(
        cp.get(&checkpoint_key(2, Some(Address::repeat_byte(2)))),
        None
    );
    cp.set_journaled(&all, 8000, None).unwrap();
    assert_eq!(
        resume_cursor(cp.get(&all), cp.has_durable_work(&all), None, 600),
        7400
    );
}

#[tokio::test]
async fn scans_two_active_outboxes_without_reading_or_filtering_the_default() {
    let a = Address::repeat_byte(1);
    let b = Address::repeat_byte(2);
    let registry = Address::repeat_byte(3);
    let rpc = RpcMock::start(vec![
        json!({"result":"0x64"}),
        json!({"result":[publication(a, 1, 10), publication(b, 2, 10)]}),
        json!({"result":discovery(registry)}),
        json!({"result":membership(true)}),
        json!({"result":membership(true)}),
    ])
    .await;
    let mut cursor = 0;
    let (result, messages) = scan(&rpc.provider, source(None), &mut cursor).await;
    result.unwrap();
    assert_eq!(
        messages.iter().map(|m| m.outbox).collect::<Vec<_>>(),
        vec![a, b]
    );
    assert_eq!(cursor, 100);
    let requests = rpc.requests();
    assert!(requests[1]["params"][0].get("address").is_none());
    assert_eq!(
        requests.len(),
        5,
        "one historical Discovery lookup shared by both emitters"
    );
    for request in &requests[2..] {
        assert_eq!(request["params"][1], "0xa");
    }
    for request in &requests[3..] {
        assert_eq!(request["params"][0]["to"], json!(registry));
    }
}

#[tokio::test]
async fn restart_replays_membership_at_each_publication_across_removal_reregistration_and_discovery_replacement(
) {
    let outbox = Address::repeat_byte(1);
    let old = Address::repeat_byte(2);
    let new = Address::repeat_byte(3);
    // A scheduled removal at 25 was cancelled, then a later removal became effective at 40.
    // The Outbox was re-registered at 50; governance replaced Discovery at 60. Current membership
    // cannot answer whether historical messages at these earlier blocks should be delivered.
    let history = [
        (10, old, true),
        (20, old, true),
        (25, old, true),
        (40, old, false),
        (50, old, true),
        (60, new, true),
    ];
    let logs: Vec<_> = history
        .iter()
        .enumerate()
        .map(|(i, (height, _, _))| publication(outbox, i as u8 + 1, *height))
        .collect();
    let mut responses = vec![json!({"result":"0x64"}), json!({"result":logs})];
    for (_, registry, active) in history {
        responses.push(json!({"result":discovery(registry)}));
        responses.push(json!({"result":membership(active)}));
    }
    let rpc = RpcMock::start(responses).await;
    let mut cursor = resume_cursor(None, false, None, 600);
    let (result, messages) = scan(&rpc.provider, source(None), &mut cursor).await;
    result.unwrap();
    assert_eq!(
        messages.iter().map(|m| m.block_height).collect::<Vec<_>>(),
        vec![10, 20, 25, 50, 60]
    );
    let requests = rpc.requests();
    for (i, (height, registry, _)) in history.iter().enumerate() {
        let discovery_read = &requests[2 + i * 2];
        let member_read = &requests[3 + i * 2];
        assert_eq!(discovery_read["params"][1], format!("0x{height:x}"));
        assert_eq!(member_read["params"][1], format!("0x{height:x}"));
        assert_eq!(member_read["params"][0]["to"], json!(registry));
    }
}

#[tokio::test]
async fn authorization_errors_and_malformed_responses_never_advance_the_cursor() {
    let outbox = Address::repeat_byte(1);
    for failure in [
        "discovery_rpc",
        "discovery_abi",
        "discovery_bool",
        "membership_rpc",
        "membership_abi",
        "membership_bool",
    ] {
        let rpc = Asserter::new();
        rpc.push_success(&U64::from(100));
        rpc.push_success(&vec![publication(outbox, 1, 10)]);
        match failure {
            "discovery_rpc" => rpc.push_failure_msg("historic state unavailable"),
            "discovery_abi" => rpc.push_success(&Bytes::new()),
            "discovery_bool" => {
                let mut bytes = discovery(Address::repeat_byte(2)).to_vec();
                bytes[63] = 2;
                rpc.push_success(&Bytes::from(bytes));
            }
            _ => {
                rpc.push_success(&discovery(Address::repeat_byte(2)));
                match failure {
                    "membership_rpc" => rpc.push_failure_msg("historic state unavailable"),
                    "membership_bool" => {
                        let mut bytes = [0u8; 32];
                        bytes[31] = 2;
                        rpc.push_success(&Bytes::copy_from_slice(&bytes));
                    }
                    _ => rpc.push_success(&Bytes::new()),
                }
            }
        }
        let provider = ProviderBuilder::new().connect_mocked_client(rpc);
        let mut cursor = 0;
        let (result, messages) = scan(&provider, source(None), &mut cursor).await;
        assert!(result.is_err(), "{failure}");
        assert!(messages.is_empty(), "{failure}");
        assert_eq!(cursor, 0, "{failure}");
    }
}

#[tokio::test]
async fn only_authorized_malformed_logs_block_progress() {
    let outbox = Address::repeat_byte(1);
    for allowed in [true, false] {
        let rpc = Asserter::new();
        let mut log = publication(outbox, 1, 10);
        log.inner.data =
            alloy::primitives::LogData::new_unchecked(log.topics().to_vec(), Bytes::new());
        rpc.push_success(&U64::from(100));
        rpc.push_success(&vec![log]);
        rpc.push_success(&discovery(Address::repeat_byte(2)));
        rpc.push_success(&membership(allowed));
        let provider = ProviderBuilder::new().connect_mocked_client(rpc);
        let mut cursor = 0;
        let (result, messages) = scan(&provider, source(None), &mut cursor).await;
        assert_eq!(result.is_err(), allowed);
        assert!(messages.is_empty());
        assert_eq!(cursor, if allowed { 0 } else { 100 });
    }
}

#[tokio::test]
async fn absent_discovery_is_not_an_rpc_error_and_pinned_override_is_explicit() {
    let outbox = Address::repeat_byte(1);
    let rpc = Asserter::new();
    rpc.push_success(&U64::from(100));
    rpc.push_success(&vec![publication(outbox, 1, 10)]);
    rpc.push_success(&discovery(Address::ZERO));
    let provider = ProviderBuilder::new().connect_mocked_client(rpc);
    let (result, messages) = scan(&provider, source(None), &mut 0).await;
    result.unwrap();
    assert!(messages.is_empty());
    // No Discovery responses are supplied: the operator scope must short-circuit those reads.
    let rpc = Asserter::new();
    rpc.push_success(&U64::from(100));
    rpc.push_success(&vec![publication(outbox, 1, 10)]);
    let provider = ProviderBuilder::new().connect_mocked_client(rpc);
    let (result, messages) = scan(&provider, source(Some(outbox)), &mut 0).await;
    result.unwrap();
    assert_eq!(messages.len(), 1);
}

#[tokio::test]
async fn log_result_limits_shrink_the_range_and_commit_only_successful_prefix() {
    let outbox = Address::repeat_byte(1);
    let rpc = RpcMock::start(vec![
        json!({"result":"0x4"}),
        json!({"error":{"code":-32603,"message":"query returned more than 10000 results"}}),
        json!({"result":[publication(outbox, 1, 1)]}),
        json!({"result":"0x4"}),
        json!({"result":[publication(outbox, 2, 3)]}),
    ])
    .await;
    let mut cursor = 0;
    let (result, first) = scan(&rpc.provider, source(Some(outbox)), &mut cursor).await;
    result.unwrap();
    assert_eq!(cursor, 2);
    assert_eq!(first.len(), 1);
    let (result, second) = scan(&rpc.provider, source(Some(outbox)), &mut cursor).await;
    result.unwrap();
    assert_eq!(cursor, 4);
    assert_eq!(second[0].block_height, 3);
    let requests = rpc.requests();
    assert_eq!(requests[1]["params"][0]["toBlock"], "0x4");
    assert_eq!(requests[2]["params"][0]["toBlock"], "0x2");
    assert_eq!(requests[4]["params"][0]["fromBlock"], "0x3");
}

#[tokio::test]
async fn finalized_rpc_failures_null_and_regression_do_not_scan_or_weaken_boundary() {
    let mut block: alloy::rpc::types::Block = Default::default();
    block.header.inner.number = 10;
    let mut regressed = block.clone();
    regressed.header.inner.number = 9;
    let rpc = RpcMock::start(vec![
        json!({"error":{"code":-32603,"message":"finality unavailable"}}),
        json!({"result":null}),
        json!({"result":block}),
        json!({"result":[]}),
        json!({"result":regressed}),
    ])
    .await;
    let (tx, _rx) = mpsc::channel(8);
    let mut cursor = 0;
    let mut finality = FinalityTracker::new(Instant::now());
    for expected_ok in [false, false, true, false] {
        let result = poll_once(
            &source(None),
            &FinalityPolicy::Finalized,
            &mut finality,
            &rpc.provider,
            &mut cursor,
            &tx,
            crate::prom::NoopMetrics::new().as_ref(),
            None,
            &CancellationToken::new(),
            &|| {},
        )
        .await;
        assert_eq!(result.is_ok(), expected_ok);
    }
    assert_eq!(cursor, 10);
    let requests = rpc.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "eth_getLogs")
            .count(),
        1
    );
    assert!(requests.iter().all(|r| r["method"] != "eth_blockNumber"));
}

fn receipt(log: &Log) -> Value {
    json!({
        "transactionHash":log.transaction_hash, "transactionIndex":"0x0",
        "blockHash":log.block_hash, "blockNumber":U64::from(log.block_number.unwrap()),
        "from":Address::repeat_byte(9), "to":log.address(), "contractAddress":null,
        "gasUsed":"0x5208", "effectiveGasPrice":"0x1", "cumulativeGasUsed":"0x5208",
        "status":"0x1", "type":"0x0", "logsBloom":alloy::primitives::Bloom::ZERO, "logs":[log]
    })
}

#[tokio::test]
async fn a_single_block_over_the_log_cap_uses_authenticated_receipts() {
    let spam = publication(Address::repeat_byte(1), 1, 1);
    let legitimate = publication(Address::repeat_byte(2), 2, 1);
    let mut block: alloy::rpc::types::Block = Default::default();
    block.header.inner.number = 1;
    block.header.hash = legitimate.block_hash.unwrap();
    block.transactions = alloy::rpc::types::BlockTransactions::Hashes(vec![
        spam.transaction_hash.unwrap(),
        legitimate.transaction_hash.unwrap(),
    ]);
    let rpc = Asserter::new();
    rpc.push_success(&U64::from(1));
    rpc.push_failure_msg("too many logs");
    rpc.push_success(&block);
    rpc.push_success(&receipt(&spam));
    rpc.push_success(&receipt(&legitimate));
    rpc.push_success(&discovery(Address::repeat_byte(3)));
    rpc.push_success(&membership(false));
    rpc.push_success(&membership(true));
    let provider = ProviderBuilder::new().connect_mocked_client(rpc);
    let mut cursor = 0;
    let (result, messages) = scan(&provider, source(None), &mut cursor).await;
    result.unwrap();
    assert_eq!(cursor, 1);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].outbox, legitimate.address());
}

#[tokio::test]
async fn receipt_fallback_rejects_inconsistent_block_or_log_provenance() {
    let log = publication(Address::repeat_byte(1), 1, 1);
    for bad_receipt in [true, false] {
        let mut block: alloy::rpc::types::Block = Default::default();
        block.header.inner.number = 1;
        block.header.hash = log.block_hash.unwrap();
        block.transactions =
            alloy::rpc::types::BlockTransactions::Hashes(vec![log.transaction_hash.unwrap()]);
        let mut inconsistent = receipt(&log);
        if bad_receipt {
            inconsistent["blockHash"] = json!(B256::ZERO);
        } else {
            inconsistent["logs"][0]["removed"] = json!(true);
        }
        let rpc = Asserter::new();
        rpc.push_success(&U64::from(1));
        rpc.push_failure_msg("too many logs");
        rpc.push_success(&block);
        rpc.push_success(&inconsistent);
        let provider = ProviderBuilder::new().connect_mocked_client(rpc);
        let mut cursor = 0;
        let (result, messages) = scan(&provider, source(None), &mut cursor).await;
        assert!(result.is_err());
        assert_eq!(cursor, 0);
        assert!(messages.is_empty());
    }
}

#[tokio::test]
async fn unrepresentable_registry_chain_key_is_rejected_before_rpc() {
    let provider = ProviderBuilder::new().connect_mocked_client(Asserter::new());
    assert!(authority::discovery_at(&provider, u64::MAX, 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("uint32"));
}

#[test]
fn unmarked_all_outbox_cursor_replays_history_before_marking_work_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.json");
    let key = checkpoint_key(2, None);
    let cp = CheckpointStore::load(&path).unwrap();
    cp.set(&key, 100_000).unwrap();
    assert_eq!(
        resume_cursor(cp.get(&key), cp.has_durable_work(&key), None, 600),
        0
    );
    assert_eq!(
        resume_cursor(cp.get(&key), cp.has_durable_work(&key), Some(50), 600),
        49
    );
    cp.set_journaled(&key, 2_000, None).unwrap();
    let restored = CheckpointStore::load(path).unwrap();
    assert!(restored.has_durable_work(&key));
    assert_eq!(
        restored.get_outbox(&key),
        None,
        "an all-Outbox cursor has no fabricated default address"
    );
    assert_eq!(
        resume_cursor(
            restored.get(&key),
            restored.has_durable_work(&key),
            None,
            600
        ),
        1_400
    );
}

async fn scan_to_channel_with_store(
    work: &crate::work::WorkStore,
    count: u8,
) -> (Result<()>, u64, mpsc::Receiver<IndexedMessage>) {
    let outbox = Address::repeat_byte(1);
    let rpc = Asserter::new();
    rpc.push_success(&U64::from(5_000));
    rpc.push_success(
        &((1..=count)
            .map(|id| publication(outbox, id, u64::from(id)))
            .collect::<Vec<_>>()),
    );
    let provider = ProviderBuilder::new().connect_mocked_client(rpc);
    let (tx, rx) = mpsc::channel(8);
    let mut cursor = 0;
    let result = poll_once(
        &source(Some(outbox)),
        &FinalityPolicy::Depth(0),
        &mut FinalityTracker::new(Instant::now()),
        &provider,
        &mut cursor,
        &tx,
        crate::prom::NoopMetrics::new().as_ref(),
        Some(work),
        &CancellationToken::new(),
        &|| {},
    )
    .await;
    (result, cursor, rx)
}

#[tokio::test]
async fn scanner_crash_before_pool_tick_restores_old_work_with_bounded_admission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.json");
    let work = crate::work::WorkStore::for_checkpoint(&path);
    let (result, cursor, rx) = scan_to_channel_with_store(&work, 3).await;
    result.unwrap();
    assert_eq!(cursor, MAX_BLOCKS_PER_SCAN);
    let key = checkpoint_key(2, None);
    let cp = CheckpointStore::load(&path).unwrap();
    cp.set_journaled(&key, cursor, None).unwrap();
    // No pool has consumed the channel or published a periodic checkpoint holdback.
    drop(rx);
    drop(work);
    let work = crate::work::WorkStore::for_checkpoint(&path);
    work.prepare_route(2, cp.has_durable_work(&key))
        .await
        .unwrap();
    let first = work.pending(2, Default::default(), 1).await.unwrap();
    assert_eq!(
        first.len(),
        1,
        "the working-set limit must bound restore memory"
    );
    let rest = work
        .pending(2, first.iter().map(|m| m.message_id).collect(), 10)
        .await
        .unwrap();
    assert_eq!(
        rest.len(),
        2,
        "overflow remains durable despite the advanced checkpoint"
    );
    assert!(first
        .iter()
        .chain(&rest)
        .all(|m| m.block_height < cursor.saturating_sub(600)));
}

#[tokio::test]
async fn journal_write_failure_cannot_publish_work_or_advance_source_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.json");
    std::fs::write(dir.path().join("cp.json.messages"), "not a directory").unwrap();
    let work = crate::work::WorkStore::for_checkpoint(&path);
    let (result, cursor, mut rx) = scan_to_channel_with_store(&work, 1).await;
    assert!(result.is_err());
    assert_eq!(cursor, 0);
    assert!(rx.try_recv().is_err());
}
