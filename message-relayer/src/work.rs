//! Durable, unfinished source messages. The scanner writes each record before advancing its
//! checkpoint; the pool loads only as many records as fit in its bounded vote cache. Records are
//! immutable and keyed by route and message ID (which binds the source Outbox), so rotations do
//! not change their identity. Keeping separate files avoids rewriting or loading the backlog.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use alloy::primitives::B256;
use anyhow::{Context, Result};

use crate::events::IndexedMessage;

#[derive(Debug)]
pub struct WorkStore {
    path: PathBuf,
}

impl WorkStore {
    /// The sibling directory belongs to this checkpoint file and must be backed up with it.
    pub fn for_checkpoint(checkpoint: &Path) -> Self {
        let mut path = checkpoint.as_os_str().to_os_string();
        path.push(".messages");
        Self { path: path.into() }
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
        tokio::task::spawn_blocking(move || {
            create_dir_durable(&route)?;
            let path = route.join(format!("{}.json", message.message_id));
            let bytes = serde_json::to_vec(&message).context("serializing pending message")?;
            crate::checkpoint::write_atomic(&path, &bytes)?;
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
        loaded: HashSet<B256>,
        limit: usize,
    ) -> Result<Vec<IndexedMessage>> {
        let route = self.path.join(chain_key.to_string());
        tokio::task::spawn_blocking(move || {
            let mut messages = Vec::new();
            if limit == 0 {
                return Ok(messages);
            }
            let entries = match std::fs::read_dir(&route) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(messages),
                Err(err) => return Err(err).context("reading pending-message directory"),
            };
            for entry in entries {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue; // Ignore an interrupted atomic write's temporary file.
                }
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
        tokio::task::spawn_blocking(move || {
            match std::fs::remove_file(route.join(format!("{message_id}.json"))) {
                Ok(()) => sync_directory(&route),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err).context("removing completed message"),
            }
        })
        .await
        .context("joining completed-message removal")?
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
    async fn missing_durable_directory_requires_explicit_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let work = WorkStore::for_checkpoint(&dir.path().join("cp"));
        assert!(work.prepare_route(2, true).await.is_err());
        work.prepare_route(2, false).await.unwrap();
        work.prepare_route(2, true).await.unwrap();
    }
}
