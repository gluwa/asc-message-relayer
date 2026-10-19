//! Persistent per-watcher block cursors.
//!
//! Source and settlement watchers scan chain logs by block range. Source scans resume only
//! cursors backed by the durable unfinished-work journal; otherwise they replay from the
//! configured start block or genesis. Ack scans rewind their saved cursor by the lookback and
//! hold it behind pending settlements, so even long-delayed work is rediscovered after restart.
//! Without an ack checkpoint, the route's configured start block applies, or the current head.
//!
//! Storage is a single JSON file written atomically (temp file + rename + directory sync).
//! Reprocessing after a crash is safe because delivery and settlement reconcile on-chain state.
//! A source cursor advances only after its discovered work is durably recorded.
//!
//! Entries contain `block`, optional `outbox` metadata for a pinned source, and `durable_work`
//! marking source cursors backed by the unfinished-work journal. Source checkpoint keys separate
//! all-Outbox scans from pinned-address scans. Older bare-number entries and objects without the
//! journal marker still deserialize, but source discovery safely replays their history.
//!
//! Note: this covers durable *on-chain* events. Attestor votes travel over gossip (ephemeral) and
//! are out of scope here — a relayer that was down while votes were gossiped relies on the votes
//! being re-observed, not on this cursor.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One watcher's cursor, optional pinned Outbox, and source journal coverage marker.
#[derive(Debug, Clone, Default, Serialize)]
struct Entry {
    block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    outbox: Option<String>,
    /// Every message through this cursor was recorded in the unfinished-work store.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    durable_work: bool,
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
        #[serde(default)]
        durable_work: bool,
    },
}

impl From<RawEntry> for Entry {
    fn from(raw: RawEntry) -> Self {
        match raw {
            RawEntry::Legacy(block) => Entry {
                block,
                ..Entry::default()
            },
            RawEntry::Full {
                block,
                outbox,
                durable_work,
            } => Entry {
                block,
                outbox,
                durable_work,
            },
        }
    }
}

/// A JSON-file-backed map of `watcher key -> last fully-processed block` (+ optional Outbox
/// address and source journal marker per key — see the module docs).
#[derive(Debug)]
pub struct CheckpointStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, Entry>>,
}

impl CheckpointStore {
    /// Location used to keep independently persisted watcher metadata alongside its cursors.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
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

    /// Legacy scan cursors cannot vouch for unfinished messages: the old periodically updated
    /// holdback could lag ingestion or lose an evicted slot. Upgrade must rescan their history.
    pub fn has_durable_work(&self, key: &str) -> bool {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .get(key)
            .is_some_and(|e| e.durable_work)
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
        let mut entry = guard.get(key).cloned().unwrap_or_default();
        entry.block = block;
        Self::persist_entry(&self.path, &mut guard, key, entry)
    }

    /// Like [`Self::set`], but also records `outbox` as the Outbox address this block cursor was
    /// scanned against — call this whenever the scanned Outbox address is known (including when
    /// it hasn't changed), so a later restart can tell a valid long-running cursor apart from one
    /// left over from an Outbox since rotated away from.
    pub fn set_with_outbox(&self, key: &str, block: u64, outbox: &str) -> Result<()> {
        let mut guard = self.inner.lock().expect("checkpoint mutex");
        Self::persist_entry(
            &self.path,
            &mut guard,
            key,
            Entry {
                block,
                outbox: Some(outbox.to_string()),
                durable_work: false,
            },
        )
    }

    /// Commit a source scan only after all its message records have reached stable storage.
    pub fn set_with_work(&self, key: &str, block: u64, outbox: &str) -> Result<()> {
        self.set_journaled(key, block, Some(outbox))
    }

    /// Record a source cursor backed by durable unfinished work. An all-Outbox scope carries no
    /// single address: its key identifies the scope and historical authorization covers emitters.
    pub fn set_journaled(&self, key: &str, block: u64, outbox: Option<&str>) -> Result<()> {
        let mut guard = self.inner.lock().expect("checkpoint mutex");
        Self::persist_entry(
            &self.path,
            &mut guard,
            key,
            Entry {
                block,
                outbox: outbox.map(str::to_owned),
                durable_work: true,
            },
        )
    }

    fn persist_entry(
        path: &Path,
        entries: &mut HashMap<String, Entry>,
        key: &str,
        entry: Entry,
    ) -> Result<()> {
        let previous = entries.insert(key.to_string(), entry);
        if let Err(err) = Self::persist(path, entries) {
            if let Some(previous) = previous {
                entries.insert(key.to_string(), previous);
            } else {
                entries.remove(key);
            }
            return Err(err);
        }
        Ok(())
    }

    fn persist(path: &Path, entries: &HashMap<String, Entry>) -> Result<()> {
        let serialized =
            serde_json::to_string_pretty(entries).context("serializing checkpoint store")?;
        write_atomic(path, serialized.as_bytes())
    }
}

/// Write `bytes` to `path` durably: sibling temp file, fsync, rename, fsync the directory.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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
    fn only_journaled_source_cursors_are_marked_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        std::fs::write(
            &path,
            r#"{"outbox:2":1000,"outbox:3":{"block":2000,"outbox":"old"}}"#,
        )
        .unwrap();
        let store = CheckpointStore::load(&path).unwrap();
        assert!(!store.has_durable_work("outbox:2"));
        assert!(!store.has_durable_work("outbox:3"));
        store.set_with_work("outbox:2", 100, "new").unwrap();
        let reloaded = CheckpointStore::load(&path).unwrap();
        assert!(reloaded.has_durable_work("outbox:2"));
        assert!(!reloaded.has_durable_work("outbox:3"));
    }

    #[test]
    fn failed_persistence_rolls_back_in_memory_cursor_and_work_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");
        let store = CheckpointStore::load(&path).unwrap();
        std::fs::create_dir(&path).unwrap(); // Make the atomic rename fail.
        assert!(store.set_with_work("outbox:2", 1000, "outbox").is_err());
        assert_eq!(store.get("outbox:2"), None);
        assert!(!store.has_durable_work("outbox:2"));
    }

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
