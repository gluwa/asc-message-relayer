//! Durable, unfinished source messages. The scanner writes each record before advancing its
//! checkpoint; the pool loads only as many records as fit in its bounded vote cache. Records are
//! immutable and keyed by route and message ID (which binds the source Outbox), so rotations do
//! not change their identity. Keeping separate files avoids rewriting or loading the backlog.
//!
//! Each route directory also holds a `failed/` subdirectory with the `retryFailedMessage` budget
//! of messages whose destination call failed ([`FailedRetryState`]). It is kept apart from the
//! records so their format is unchanged (older directories simply have no `failed/`), and so the
//! state outlives the record: after the relayer gives up, the entry is the tombstone that stops a
//! startup rescan from granting the same message a fresh budget.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use alloy::primitives::B256;
use anyhow::{Context, Result};

use crate::events::IndexedMessage;

/// Subdirectory of a route's work directory holding [`FailedRetryState`] entries. Has no `.json`
/// extension, so record scans skip it like any other non-record entry.
const FAILED_RETRY_DIR: &str = "failed";

/// Durable `retryFailedMessage` bookkeeping for one message (see `delivery::failed_retry`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FailedRetryState {
    /// `retryFailedMessage` transactions already broadcast.
    pub attempts: u32,
    /// Unix seconds before which the next attempt must not be sent.
    pub next_attempt_at: u64,
    /// Unix seconds when the relayer stopped retrying. A tombstone: the message is never retried
    /// by this relayer again, even if a rescan re-records it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gave_up_at: Option<u64>,
}

#[derive(Debug)]
pub struct WorkStore {
    path: PathBuf,
    /// A bounded cursor per configured route; reopening from the first filename on every read
    /// would repeatedly reload the same stalled messages and starve the rest of the backlog.
    readers: Arc<Mutex<HashMap<u64, RouteCursor>>>,
}

#[derive(Debug)]
struct RouteCursor {
    reader: Option<std::fs::ReadDir>,
    live_records: usize,
    remaining: usize,
}

impl RouteCursor {
    fn new(route: &Path) -> std::io::Result<Self> {
        // Count once, under the same lock as every writer. Memory is constant and new writes
        // cannot extend this initialization scan. Later generations use the maintained count.
        let mut live_records = 0;
        for entry in std::fs::read_dir(route)? {
            if is_record(&entry?.path()) {
                live_records += 1;
            }
        }
        Ok(Self {
            reader: None,
            live_records,
            remaining: 0,
        })
    }
}

fn is_record(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("json")
}

impl WorkStore {
    /// The sibling directory belongs to this checkpoint file and must be backed up with it.
    pub fn for_checkpoint(checkpoint: &Path) -> Self {
        let mut path = checkpoint.as_os_str().to_os_string();
        path.push(".messages");
        Self {
            path: path.into(),
            readers: Arc::default(),
        }
    }

    /// A marked checkpoint must have its corresponding work directory. Missing storage is not
    /// an empty backlog: silently recreating it would discard every unfinished message.
    pub async fn prepare_route(&self, chain_key: u64, resuming: bool) -> Result<()> {
        let route = self.path.join(chain_key.to_string());
        tokio::task::spawn_blocking(move || {
            if resuming {
                anyhow::ensure!(
                    route.is_dir(),
                    "durable work directory is missing: {}",
                    route.display()
                );
                Ok(())
            } else {
                create_dir_durable(&route)
            }
        })
        .await
        .context("joining pending-message initialization")?
    }

    /// Commit the original source event before handing it to an in-memory worker.
    pub async fn record(&self, message: IndexedMessage) -> Result<()> {
        let route = self.path.join(message.chain_key.to_string());
        let readers = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let mut readers = readers
                .lock()
                .map_err(|_| anyhow::anyhow!("work cursor poisoned"))?;
            create_dir_durable(&route)?;
            let path = route.join(format!("{}.json", message.message_id));
            let existed = path.try_exists().context("checking pending message")?;
            let bytes = serde_json::to_vec(&message).context("serializing pending message")?;
            crate::checkpoint::write_atomic(&path, &bytes)?;
            if !existed {
                if let Some(cursor) = readers.get_mut(&message.chain_key) {
                    cursor.live_records += 1;
                }
            }
            // Unlike a cursor, losing a newly created record can lose delivery work. Its rename
            // and every newly created parent directory must be durable before the cursor moves.
            sync_directory(&route)
        })
        .await
        .context("joining pending-message write")?
    }

    /// Load at most `limit` records not already in the vote cache. A route has its own directory,
    /// so a busy route cannot consume another route's allocation. Votes are recovered through
    /// the existing reobservation mechanism, not trusted from disk.
    pub async fn pending(
        &self,
        chain_key: u64,
        mut loaded: HashSet<B256>,
        limit: usize,
    ) -> Result<Vec<IndexedMessage>> {
        let route = self.path.join(chain_key.to_string());
        let readers = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let mut messages = Vec::new();
            if limit == 0 {
                return Ok(messages);
            }
            let mut readers = readers
                .lock()
                .map_err(|_| anyhow::anyhow!("work cursor poisoned"))?;
            let cursor = match readers.entry(chain_key) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    match RouteCursor::new(&route) {
                        Ok(cursor) => entry.insert(cursor),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(messages)
                        }
                        Err(err) => return Err(err).context("initializing pending-message cursor"),
                    }
                }
            };
            let mut wrapped = false;
            // After the one-time population count, bound each refill's directory IO even if a
            // route has millions of records or temporary files.
            // Each generation has a finite population budget: arrivals cannot indefinitely
            // extend the iterator and prevent parked execution from being visited again.
            for _ in 0..4096 {
                if cursor.reader.is_none() {
                    if cursor.live_records == 0 {
                        break;
                    }
                    cursor.reader = Some(
                        std::fs::read_dir(&route).context("reading pending-message directory")?,
                    );
                    cursor.remaining = cursor.live_records;
                }
                if cursor.remaining == 0 {
                    cursor.reader = None;
                    if wrapped {
                        break;
                    }
                    wrapped = true;
                    continue;
                }
                let Some(entry) = cursor.reader.as_mut().expect("reader inserted").next() else {
                    cursor.remaining = 0;
                    continue;
                };
                let path = entry?.path();
                if !is_record(&path) {
                    continue; // Ignore an interrupted atomic write's temporary file.
                }
                cursor.remaining -= 1;
                let id: B256 = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("invalid pending-message filename")?
                    .parse()
                    .context("invalid pending-message ID")?;
                if loaded.contains(&id) {
                    continue;
                }
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err).context("reading pending message"),
                };
                let message: IndexedMessage = serde_json::from_slice(&bytes)
                    .with_context(|| format!("decoding pending message {}", path.display()))?;
                anyhow::ensure!(
                    message.chain_key == chain_key && message.message_id == id,
                    "pending message identity disagrees with its storage key: {}",
                    path.display()
                );
                loaded.insert(id);
                messages.push(message);
                if messages.len() == limit {
                    break;
                }
            }
            Ok(messages)
        })
        .await
        .context("joining pending-message read")?
    }

    /// Remove only final work. A failed removal is safe to replay; callers must not treat it as
    /// successful bookkeeping and silently forget to retry it.
    pub async fn complete(&self, chain_key: u64, message_id: B256) -> Result<()> {
        let route = self.path.join(chain_key.to_string());
        let readers = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let mut readers = readers
                .lock()
                .map_err(|_| anyhow::anyhow!("work cursor poisoned"))?;
            match std::fs::remove_file(route.join(format!("{message_id}.json"))) {
                Ok(()) => {
                    if let Some(cursor) = readers.get_mut(&chain_key) {
                        cursor.live_records = cursor.live_records.saturating_sub(1);
                    }
                    sync_directory(&route)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err).context("removing completed message"),
            }
        })
        .await
        .context("joining completed-message removal")?
    }

    fn failed_retry_path(&self, chain_key: u64, message_id: B256) -> PathBuf {
        self.path
            .join(chain_key.to_string())
            .join(FAILED_RETRY_DIR)
            .join(format!("{message_id}.json"))
    }

    /// The persisted `retryFailedMessage` state of a message, if any.
    pub async fn failed_retry(
        &self,
        chain_key: u64,
        message_id: B256,
    ) -> Result<Option<FailedRetryState>> {
        let path = self.failed_retry_path(chain_key, message_id);
        tokio::task::spawn_blocking(move || match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("decoding failed-retry state {}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context("reading failed-retry state"),
        })
        .await
        .context("joining failed-retry read")?
    }

    /// Durably replace a message's `retryFailedMessage` state. Called after a retry is broadcast
    /// and before its receipt is awaited, so a crash cannot forget gas already spent.
    pub async fn put_failed_retry(
        &self,
        chain_key: u64,
        message_id: B256,
        state: FailedRetryState,
    ) -> Result<()> {
        let path = self.failed_retry_path(chain_key, message_id);
        tokio::task::spawn_blocking(move || {
            let dir = path.parent().expect("failed-retry path has a parent");
            create_dir_durable(dir)?;
            let existed = path.try_exists().context("checking failed-retry state")?;
            let bytes = serde_json::to_vec(&state).context("serializing failed-retry state")?;
            crate::checkpoint::write_atomic(&path, &bytes)?;
            if existed {
                Ok(())
            } else {
                sync_directory(dir)
            }
        })
        .await
        .context("joining failed-retry write")?
    }

    /// Drop a message's `retryFailedMessage` state once its execution is confirmed.
    pub async fn forget_failed_retry(&self, chain_key: u64, message_id: B256) -> Result<()> {
        let path = self.failed_retry_path(chain_key, message_id);
        tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => sync_directory(path.parent().expect("failed-retry path has a parent")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context("removing failed-retry state"),
        })
        .await
        .context("joining failed-retry removal")?
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing pending-message directory {}", path.display()))
}

fn create_dir_durable(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if path.is_dir() {
        // Also cover retry after the prior mkdir succeeded but syncing its parent failed.
        return sync_directory(parent.unwrap_or_else(|| Path::new(".")));
    }
    if let Some(parent) = parent {
        create_dir_durable(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(err) => return Err(err).context("creating pending-message directory"),
    }
    sync_directory(parent.unwrap_or_else(|| Path::new(".")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    fn message(chain_key: u64, id: u8) -> IndexedMessage {
        IndexedMessage {
            chain_key,
            message_id: B256::repeat_byte(id),
            emitter: Address::repeat_byte(2),
            outbox: Address::repeat_byte(3),
            sequence: u64::from(id),
            destination_chain_key: B256::repeat_byte(4),
            creditcoin_chain_id: 42,
            payload: vec![5, 6],
            tx_hash: B256::repeat_byte(7),
            block_height: 1,
        }
    }

    #[tokio::test]
    async fn restart_recovers_unfinished_work_independently_of_cursor_and_lookback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.json");
        let work = WorkStore::for_checkpoint(&path);
        work.record(message(2, 1)).await.unwrap();
        let cp = crate::checkpoint::CheckpointStore::load(&path).unwrap();
        cp.set_with_work("outbox:2", 100_000, &Address::repeat_byte(3).to_string())
            .unwrap();
        drop(work);
        let work = WorkStore::for_checkpoint(&path);
        work.prepare_route(2, true).await.unwrap();
        let restored = work.pending(2, HashSet::new(), 10).await.unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].message_id, B256::repeat_byte(1));
        assert_eq!(restored[0].block_height, 1);
        work.complete(2, restored[0].message_id).await.unwrap();
        assert!(WorkStore::for_checkpoint(&path)
            .pending(2, HashSet::new(), 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn capacity_limits_loaded_records_without_removing_backlog_or_other_routes() {
        let dir = tempfile::tempdir().unwrap();
        let work = WorkStore::for_checkpoint(&dir.path().join("cp"));
        for id in 1..=5 {
            work.record(message(2, id)).await.unwrap();
        }
        work.record(message(3, 1)).await.unwrap();
        let first = work.pending(2, HashSet::new(), 2).await.unwrap();
        assert_eq!(first.len(), 2);
        let loaded = first.iter().map(|m| m.message_id).collect();
        let rest = work.pending(2, loaded, 10).await.unwrap();
        assert_eq!(rest.len(), 3);
        assert_eq!(work.pending(3, HashSet::new(), 1).await.unwrap().len(), 1);
        assert_eq!(work.pending(2, HashSet::new(), 10).await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn scan_generations_revisit_parked_work_during_continuous_arrivals_and_completions() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("cp");
        let work = WorkStore::for_checkpoint(&checkpoint);
        let indexed = |sequence: u64| {
            let mut indexed = message(2, 0);
            indexed.sequence = sequence;
            indexed.message_id = B256::from(alloy::primitives::U256::from(sequence));
            indexed
        };
        // Larger than a directory iterator's usual buffer, so arrivals can extend its listing.
        for id in 1..=512 {
            work.record(indexed(id)).await.unwrap();
        }
        // Reopening must initialize the population from disk, excluding interrupted writes.
        std::fs::write(work.path.join("2/interrupted.tmp"), b"partial").unwrap();
        let work = WorkStore::for_checkpoint(&checkpoint);
        let first = work.pending(2, HashSet::new(), 32).await.unwrap();
        let parked = first[0].clone();
        let mut loaded = first.iter().map(|m| m.message_id).collect();
        let mut visits: HashMap<B256, usize> = HashMap::new();
        let original_remaining = work.readers.lock().unwrap()[&2].remaining;
        for batch in 0..100 {
            // Arrivals outpace both reads and completions throughout the test. An EOF-only
            // cursor must not depend on catching up with this increasing population.
            for offset in 0..48 {
                work.record(indexed(513 + batch * 48 + offset))
                    .await
                    .unwrap();
            }
            // Parking a record is an overwrite, not a new entry or a reason to reset its scan.
            work.record(parked.clone()).await.unwrap();
            if batch == 0 {
                let readers = work.readers.lock().unwrap();
                assert_eq!(readers[&2].remaining, original_remaining);
                assert_eq!(readers[&2].live_records, 512 + 48);
            }
            let next = work.pending(2, loaded, 32).await.unwrap();
            loaded = next.iter().map(|m| m.message_id).collect();
            let completed = next
                .iter()
                .find(|m| m.sequence > 512 && m.sequence != 1000)
                .map(|m| m.message_id);
            for indexed in next {
                *visits.entry(indexed.message_id).or_default() += 1;
            }
            // Exercise removals without deleting the parked work or the late sentinel.
            if let Some(completed) = completed.filter(|_| batch % 2 == 0) {
                work.complete(2, completed).await.unwrap();
            }
        }
        assert!(
            visits[&parked.message_id] >= 2,
            "parked execution was not revisited"
        );
        assert!(
            visits.contains_key(&indexed(1000).message_id),
            "late backlog was starved"
        );
        let remaining = std::fs::read_dir(work.path.join("2"))
            .unwrap()
            .filter(|entry| is_record(&entry.as_ref().unwrap().path()))
            .count();
        assert_eq!(work.readers.lock().unwrap()[&2].live_records, remaining);
        assert!(work
            .path
            .join("2")
            .join(format!("{}.json", parked.message_id))
            .exists());
    }

    #[tokio::test]
    async fn corrupt_or_miskeyed_work_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let work = WorkStore::for_checkpoint(&dir.path().join("cp"));
        let original = message(2, 1);
        work.record(original.clone()).await.unwrap();
        let path = work
            .path
            .join("2")
            .join(format!("{}.json", original.message_id));
        std::fs::write(&path, b"{").unwrap();
        assert!(work.pending(2, HashSet::new(), 10).await.is_err());
        std::fs::write(&path, serde_json::to_vec(&message(3, 1)).unwrap()).unwrap();
        assert!(work.pending(2, HashSet::new(), 10).await.is_err());
        std::fs::write(&path, serde_json::to_vec(&message(2, 2)).unwrap()).unwrap();
        assert!(work.pending(2, HashSet::new(), 10).await.is_err());
    }

    #[tokio::test]
    async fn failed_retry_state_round_trips_without_disturbing_records() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("cp");
        let work = WorkStore::for_checkpoint(&checkpoint);
        let id = B256::repeat_byte(1);
        // A pre-existing work directory has no `failed/`: no state, not an error.
        work.record(message(2, 1)).await.unwrap();
        assert_eq!(work.failed_retry(2, id).await.unwrap(), None);

        let state = FailedRetryState {
            attempts: 3,
            next_attempt_at: 1_900_000_000,
            gave_up_at: None,
        };
        work.put_failed_retry(2, id, state).await.unwrap();
        // Survives a restart, and the sidecar is invisible to the record scan and its count.
        let work = WorkStore::for_checkpoint(&checkpoint);
        assert_eq!(work.failed_retry(2, id).await.unwrap(), Some(state));
        let restored = work.pending(2, HashSet::new(), 10).await.unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(work.readers.lock().unwrap()[&2].live_records, 1);

        // The tombstone outlives completion of the record itself.
        let tombstone = FailedRetryState {
            gave_up_at: Some(1_900_000_100),
            ..state
        };
        work.put_failed_retry(2, id, tombstone).await.unwrap();
        work.complete(2, id).await.unwrap();
        assert!(work
            .pending(2, HashSet::new(), 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(work.failed_retry(2, id).await.unwrap(), Some(tombstone));

        work.forget_failed_retry(2, id).await.unwrap();
        work.forget_failed_retry(2, id).await.unwrap(); // idempotent
        assert_eq!(work.failed_retry(2, id).await.unwrap(), None);
    }

    #[test]
    fn failed_retry_state_decodes_older_and_newer_shapes() {
        // Fields added later default; unknown fields from a newer relayer are ignored.
        let old: FailedRetryState = serde_json::from_str(r#"{"attempts":2}"#).unwrap();
        assert_eq!(
            old,
            FailedRetryState {
                attempts: 2,
                ..Default::default()
            }
        );
        let newer: FailedRetryState =
            serde_json::from_str(r#"{"attempts":1,"next_attempt_at":5,"future":true}"#).unwrap();
        assert_eq!(newer.next_attempt_at, 5);
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            r#"{"attempts":2,"next_attempt_at":0}"#
        );
    }

    #[tokio::test]
    async fn missing_durable_directory_requires_explicit_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let work = WorkStore::for_checkpoint(&dir.path().join("cp"));
        assert!(work.prepare_route(2, true).await.is_err());
        work.prepare_route(2, false).await.unwrap();
        work.prepare_route(2, true).await.unwrap();
    }
}
