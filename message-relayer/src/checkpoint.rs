//! Persistent per-watcher block cursors.
//!
//! Both the Outbox watcher (source chain `MessagePublished`) and the acknowledgment watcher
//! (destination chain `MessageDelivered`) scan chain logs by block range. Without persistence they
//! start from the chain head on every boot, so any event emitted while the relayer was down is
//! silently skipped. This store records the last block each watcher has fully processed and is
//! consulted on startup, so a restart resumes from `last_processed + 1` instead of the head — the
//! relayer never misses an on-chain event, even across downtime.
//!
//! Storage is a single JSON file written atomically (temp file + rename) so a crash mid-write
//! cannot corrupt it. Reprocessing the tail of a range after an unclean shutdown is safe:
//! delivery is idempotent (`MessageAlreadyValidated`) and acks are deduped + idempotent
//! (`MessageAlreadyAcknowledged`), so the cursor gives at-least-once, never at-most-once.
//!
//! Each entry is `{ "block": 1234, "outbox": "0x..." }` — `outbox` records which Outbox address
//! that block cursor was scanned against (Outbox watcher keys only; a bare block number can't
//! tell a valid checkpoint apart from one left over from a since-rotated-away Outbox, see
//! `events::watch_outbox`'s resume logic). Checkpoint files written before this field existed
//! store a bare number per key instead; both shapes deserialize, and any touched key is rewritten
//! in the current shape on its next save.
//!
//! Note: this covers durable *on-chain* events. Attestor votes travel over gossip (ephemeral) and
//! are out of scope here — a relayer that was down while votes were gossiped relies on the votes
//! being re-observed, not on this cursor.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One watcher's persisted state: the last fully-processed block, and (for the Outbox watcher
/// only) which Outbox address it was scanned against.
#[derive(Debug, Clone, Default, Serialize)]
struct Entry {
    block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    outbox: Option<String>,
}

/// Deserialization-only shape: a bare JSON number is a checkpoint file written before per-entry
/// Outbox tracking existed; an object is the current shape. Untagged so both parse from the same
/// JSON value without a version field or a migration pass.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawEntry {
    Legacy(u64),
    Full {
        block: u64,
        #[serde(default)]
        outbox: Option<String>,
    },
}

impl From<RawEntry> for Entry {
    fn from(raw: RawEntry) -> Self {
        match raw {
            RawEntry::Legacy(block) => Entry {
                block,
                ..Entry::default()
            },
            RawEntry::Full { block, outbox } => Entry { block, outbox },
        }
    }
}

/// A JSON-file-backed map of `watcher key -> last fully-processed block` (+ optional Outbox
/// address per key — see the module docs).
#[derive(Debug)]
pub struct CheckpointStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, Entry>>,
}

impl CheckpointStore {
    /// Load the store from `path`.
    ///
    /// A **missing** file is a legitimately empty store — first boot, nothing recorded yet.
    /// A **present but empty** file is not: it means a write was interrupted before its contents
    /// reached disk. Those two cases used to be conflated, and treating truncation as "no
    /// checkpoint" is the worst possible response — every watcher silently resumes at the chain
    /// head and every message published while the relayer was down is skipped, with no error.
    /// So an empty file fails the load, exactly like unparseable JSON already did: an operator can
    /// recover deliberately (restore, or delete the file to accept a head start), which is far
    /// better than losing messages quietly.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let inner: HashMap<String, Entry> = match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => anyhow::bail!(
                "checkpoint file {} exists but is empty — this indicates an interrupted write, not \
                 a fresh start. Resuming would skip every block since the last durable cursor. \
                 Restore the file from backup, or delete it to deliberately accept restarting from \
                 the chain head (or from `start_block`).",
                path.display()
            ),
            Ok(text) => {
                let raw: HashMap<String, RawEntry> = serde_json::from_str(&text)
                    .with_context(|| format!("parsing checkpoint file {}", path.display()))?;
                raw.into_iter().map(|(k, v)| (k, Entry::from(v))).collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading checkpoint file {}", path.display()))
            }
        };
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    /// The last fully-processed block for `key`, if any has been recorded.
    pub fn get(&self, key: &str) -> Option<u64> {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .get(key)
            .map(|e| e.block)
    }

    /// The Outbox address `key`'s block cursor was last scanned against, if any was recorded
    /// (via [`Self::set_with_outbox`]) — `None` for a key that has never recorded one (including
    /// every entry in a pre-migration checkpoint file).
    pub fn get_outbox(&self, key: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .get(key)
            .and_then(|e| e.outbox.clone())
    }

    /// Record `block` as the last fully-processed block for `key` and persist the whole store.
    /// Preserves whatever Outbox address (if any) was last recorded for `key` — this is the
    /// ordinary per-tick progress update, not an Outbox change; use [`Self::set_with_outbox`] for
    /// that.
    ///
    /// The lock is held across the file write so concurrent watchers cannot interleave a stale
    /// snapshot over a newer one; writes are small and infrequent (one per poll tick).
    pub fn set(&self, key: &str, block: u64) -> Result<()> {
        let mut guard = self.inner.lock().expect("checkpoint mutex");
        let outbox = guard.get(key).and_then(|e| e.outbox.clone());
        guard.insert(key.to_string(), Entry { block, outbox });
        Self::persist(&self.path, &guard)
    }

    /// Like [`Self::set`], but also records `outbox` as the Outbox address this block cursor was
    /// scanned against — call this whenever the scanned Outbox address is known (including when
    /// it hasn't changed), so a later restart can tell a valid long-running cursor apart from one
    /// left over from an Outbox since rotated away from.
    pub fn set_with_outbox(&self, key: &str, block: u64, outbox: &str) -> Result<()> {
        let mut guard = self.inner.lock().expect("checkpoint mutex");
        guard.insert(
            key.to_string(),
            Entry {
                block,
                outbox: Some(outbox.to_string()),
            },
        );
        Self::persist(&self.path, &guard)
    }

    fn persist(path: &Path, entries: &HashMap<String, Entry>) -> Result<()> {
        let serialized =
            serde_json::to_string_pretty(entries).context("serializing checkpoint store")?;
        write_atomic(path, serialized.as_bytes())
    }
}

/// Cross-task cursor holdback for the Outbox watchers (per `chain_key`).
///
/// The Outbox checkpoint is written by the watcher, but "is this message finished?" is pool state —
/// a message can sit undelivered (below quorum, or destination down) long after the scan cursor
/// passed its block. Persisting the raw cursor therefore loses undelivered messages across a
/// restart once they age out of the fixed lookback window: the rescan no longer reaches them, stray
/// votes are dropped by the chain-first allowlist, and no reobservation is ever requested. The pool
/// publishes the oldest unfinished (undelivered, non-terminal) message block per route here on its
/// prune tick; the watcher clamps the *persisted* cursor to `oldest - 1` so a restart always
/// re-indexes every unfinished message. The in-memory cursor is not clamped — the live scan never
/// re-reads.
#[derive(Debug, Default)]
pub struct CursorHoldback {
    /// `chain_key` → oldest unfinished message block (`None` = route has no unfinished messages).
    oldest: Mutex<HashMap<u64, Option<u64>>>,
}

impl CursorHoldback {
    /// Publish the oldest unfinished block for `chain_key` (`None` clears the holdback).
    pub fn update(&self, chain_key: u64, oldest_block: Option<u64>) {
        self.oldest
            .lock()
            .expect("holdback mutex")
            .insert(chain_key, oldest_block);
    }

    /// Clamp `cursor` so it does not advance past the oldest unfinished block for `chain_key`.
    /// Identity when the route has no unfinished messages (or has not reported yet).
    pub fn clamp(&self, chain_key: u64, cursor: u64) -> u64 {
        match self
            .oldest
            .lock()
            .expect("holdback mutex")
            .get(&chain_key)
            .copied()
            .flatten()
        {
            Some(oldest) => cursor.min(oldest.saturating_sub(1)),
            None => cursor,
        }
    }
}

/// Write `bytes` to `path` durably: sibling temp file, fsync, rename, fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating checkpoint dir {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("tmp");
    // Write, then **fsync the data before renaming**. `rename` orders the directory entry, not the
    // file contents, so without this a hard crash (power loss, SIGKILL at the end of a k8s grace
    // period) can leave the new name pointing at a zero-length or partially-written file. That
    // matters more here than it looks: a truncated checkpoint used to be read as "no checkpoint",
    // which restarts every watcher at the chain head and silently skips every message published
    // while the relayer was down.
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating checkpoint temp file {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing checkpoint temp file {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync checkpoint temp file {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming checkpoint temp file into {}", path.display()))?;

    // Also fsync the directory so the rename itself is durable. Best-effort: the contents are
    // already synced, so a failure here can at worst lose the rename and leave the *previous*
    // cursor in place — which is safe, we simply re-scan — whereas failing the whole save would
    // turn a durability nicety into a liveness problem.
    if let Some(parent) = path.parent() {
        let dir = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
            tracing::warn!(
                dir = %dir.display(), error = %e,
                "could not fsync checkpoint directory; the rename may not survive a hard crash"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");

        let store = CheckpointStore::load(&path).unwrap();
        assert_eq!(store.get("outbox:2"), None);
        store.set("outbox:2", 100).unwrap();
        store.set("ack:2", 250).unwrap();
        store.set("outbox:2", 150).unwrap(); // overwrite advances

        // A fresh load sees the persisted cursors.
        let reloaded = CheckpointStore::load(&path).unwrap();
        assert_eq!(reloaded.get("outbox:2"), Some(150));
        assert_eq!(reloaded.get("ack:2"), Some(250));
        assert_eq!(reloaded.get("missing"), None);
    }

    /// `set_with_outbox` records both fields; `set` (the ordinary per-tick progress update)
    /// preserves whatever Outbox address was last recorded rather than clearing it.
    #[test]
    fn set_with_outbox_round_trips_and_set_preserves_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        let store = CheckpointStore::load(&path).unwrap();

        store.set_with_outbox("outbox:2", 100, "0xaaa").unwrap();
        assert_eq!(store.get("outbox:2"), Some(100));
        assert_eq!(store.get_outbox("outbox:2"), Some("0xaaa".to_string()));

        // A plain `set` (no Outbox change) advances the block but keeps the recorded address.
        store.set("outbox:2", 200).unwrap();
        assert_eq!(store.get("outbox:2"), Some(200));
        assert_eq!(store.get_outbox("outbox:2"), Some("0xaaa".to_string()));

        // Both fields survive a reload.
        let reloaded = CheckpointStore::load(&path).unwrap();
        assert_eq!(reloaded.get("outbox:2"), Some(200));
        assert_eq!(reloaded.get_outbox("outbox:2"), Some("0xaaa".to_string()));

        // Rotating to a new Outbox overwrites the recorded address.
        store.set_with_outbox("outbox:2", 300, "0xbbb").unwrap();
        assert_eq!(store.get_outbox("outbox:2"), Some("0xbbb".to_string()));

        // A key that never recorded an address (e.g. an ack checkpoint) has none.
        store.set("ack:2", 50).unwrap();
        assert_eq!(store.get_outbox("ack:2"), None);
    }

    /// A checkpoint file written before per-entry Outbox tracking existed stores a bare number
    /// per key. It must still load, with no recorded Outbox address for any of its entries — and
    /// a `set` against one of its keys must not error out preserving a (nonexistent) address.
    #[test]
    fn legacy_bare_number_file_loads_with_no_outbox_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        std::fs::write(&path, r#"{"outbox:2": 1234, "ack:2": 5678}"#).unwrap();

        let store = CheckpointStore::load(&path).unwrap();
        assert_eq!(store.get("outbox:2"), Some(1234));
        assert_eq!(store.get_outbox("outbox:2"), None);
        assert_eq!(store.get("ack:2"), Some(5678));

        // Touching a legacy key with a plain `set` must not panic/error for lack of a prior
        // Outbox field, and the file must still be readable afterward.
        store.set("outbox:2", 1300).unwrap();
        assert_eq!(
            CheckpointStore::load(&path).unwrap().get("outbox:2"),
            Some(1300)
        );
    }

    #[test]
    fn holdback_clamps_only_when_unfinished_work_reported() {
        let hb = CursorHoldback::default();
        // Unreported route: identity.
        assert_eq!(hb.clamp(2, 1000), 1000);
        // Unfinished message at block 400 → cursor pinned to 399.
        hb.update(2, Some(400));
        assert_eq!(hb.clamp(2, 1000), 399);
        // A cursor already below the holdback is untouched.
        assert_eq!(hb.clamp(2, 300), 300);
        // Another route is independent.
        assert_eq!(hb.clamp(7, 1000), 1000);
        // Clearing (all delivered/terminal) releases the cursor.
        hb.update(2, None);
        assert_eq!(hb.clamp(2, 1000), 1000);
    }

    #[test]
    fn missing_file_is_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("cp.json");
        let store = CheckpointStore::load(&path).unwrap();
        assert_eq!(store.get("anything"), None);
        // First write creates the nested dir.
        store.set("ack:7", 42).unwrap();
        assert_eq!(CheckpointStore::load(&path).unwrap().get("ack:7"), Some(42));
    }

    /// A present-but-empty file means an interrupted write, not a fresh start. Loading it must
    /// fail loudly: silently treating it as "no checkpoint" restarts every watcher at the chain
    /// head and skips every block since the last durable cursor.
    #[test]
    fn empty_file_is_rejected_rather_than_treated_as_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        std::fs::write(&path, "").unwrap();

        let err = CheckpointStore::load(&path).expect_err("empty checkpoint must not load");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exists but is empty"),
            "error should explain the truncation, got: {msg}"
        );

        // Whitespace-only is the same case.
        std::fs::write(&path, "   \n").unwrap();
        assert!(CheckpointStore::load(&path).is_err());

        // ...and deleting it is the documented way to deliberately accept a fresh start.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(CheckpointStore::load(&path).unwrap().get("ack:7"), None);
    }

    /// The temp file must not survive a successful save, and the persisted value must be readable
    /// immediately (i.e. the fsync + rename sequence leaves a complete file behind).
    #[test]
    fn save_leaves_no_temp_file_and_is_immediately_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        let store = CheckpointStore::load(&path).unwrap();
        store.set("outbox:2", 1234).unwrap();

        assert!(
            !path.with_extension("tmp").exists(),
            "temp file should be renamed away"
        );
        assert_eq!(
            CheckpointStore::load(&path).unwrap().get("outbox:2"),
            Some(1234)
        );
    }
}
