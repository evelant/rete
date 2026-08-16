//! Path table CRUD operations.

use crate::path::Path;
use crate::snapshot;
use crate::storage::StorageMap;
use rete_core::{DestHash, IdentityHash};

use super::Transport;

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Look up a learned path to `dest`.
    pub fn get_path(&self, dest: &DestHash) -> Option<&Path> {
        self.paths.get(dest)
    }

    /// Update `last_accessed` on a path (call when the path is used for routing).
    pub fn touch_path(&mut self, dest: &DestHash, now: u64) {
        if let Some(p) = self.paths.get_mut(dest) {
            p.last_accessed = now;
        }
    }

    /// Store a learned path. When the table is full, evicts in Python's
    /// time-expiry cull order first, then falls back to a class-aware
    /// least-recently-used eviction that reserves shared-medium paths against
    /// point-to-point announce churn.
    ///
    /// Returns `false` only when the table is full, every retained entry is
    /// shared-medium, and the incoming path is point-to-point.
    pub fn insert_path(&mut self, dest: DestHash, path: Path) -> bool {
        match self.paths.insert(dest, path) {
            Ok(_) => true,
            Err((dest, path)) => {
                // Table full. `path` is the rejected incoming entry; its
                // `learned_at` is the current monotonic time used to judge
                // expiry.
                let now = path.learned_at;
                let shared_medium = path.shared_medium;

                // 1. Evict the entry closest to (or already past) its expiry
                //    boundary, mirroring Python's `prune_paths` cull rather
                //    than usage-based LRU.
                let expired_victim = self
                    .paths
                    .iter()
                    .filter(|(_, p)| now >= p.learned_at.saturating_add(p.expiry_time()))
                    .min_by_key(|(_, p)| p.learned_at.saturating_add(p.expiry_time()))
                    .map(|(k, _)| *k);

                // 2. Class-aware LRU fallback. A shared-medium entry may
                //    displace a point-to-point entry first, falling back to any
                //    entry only when none is point-to-point. A point-to-point
                //    entry may only displace another point-to-point entry, so
                //    it cannot evict reserved shared-medium routes.
                let victim = expired_victim.or_else(|| {
                    let point_to_point_victim = self
                        .paths
                        .iter()
                        .filter(|(_, p)| !p.shared_medium)
                        .min_by_key(|(_, p)| p.last_accessed)
                        .map(|(k, _)| *k);
                    if shared_medium && point_to_point_victim.is_none() {
                        self.paths
                            .iter()
                            .min_by_key(|(_, p)| p.last_accessed)
                            .map(|(k, _)| *k)
                    } else {
                        point_to_point_victim
                    }
                });

                match victim {
                    Some(victim) => {
                        self.paths.remove(&victim);
                        self.paths.insert(dest, path).is_ok()
                    }
                    None => false,
                }
            }
        }
    }

    /// Remove a path entry (expiry or explicit reset).
    pub fn remove_path(&mut self, dest: &DestHash) {
        self.paths.remove(dest);
    }

    /// Remove all paths that route via a specific next-hop identity.
    pub fn remove_paths_via(&mut self, via: &IdentityHash) {
        self.paths.retain(|_, p| p.via.as_ref() != Some(via));
    }

    /// Number of known paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Iterate over all known paths as `(dest_hash, path)` pairs.
    pub fn iter_paths(&self) -> impl Iterator<Item = (&DestHash, &Path)> {
        self.paths.iter()
    }

    /// Return cached raw announce packets from the path table.
    ///
    /// When a new interface connects, the node should forward these so the
    /// new peer learns about destinations we already know. This eliminates
    /// the need for synthetic announces via `--peer-seed`.
    pub fn cached_announces(&self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        for (_dest, path) in self.paths.iter() {
            if let Some(raw) = &path.announce_raw {
                out.push(raw.to_vec());
            }
        }
        out
    }

    /// Store a raw announce packet on an existing path entry.
    ///
    /// Used by `register_peer_with_announce` to cache a synthetic announce so
    /// that `cached_announces()` includes it for new-interface flush.
    pub fn store_announce_raw(&mut self, dest: &DestHash, raw: &[u8]) {
        if let Some(path) = self.paths.get_mut(dest) {
            path.announce_raw = crate::path::AnnounceCache::store(raw);
        }
    }

    /// Look up a previously announced identity's public key by destination hash.
    pub fn recall_identity(&self, dest: &DestHash) -> Option<&[u8; 64]> {
        self.known_identities.get(dest)
    }

    /// Pre-register a peer's identity and path (for use with deterministic seeds).
    pub fn register_identity(
        &mut self,
        dest_hash: DestHash,
        pub_key: [u8; 64],
        now: u64,
    ) {
        self.insert_identity(dest_hash, pub_key, true);
        let _ = self.insert_path(dest_hash, Path::direct(now));
    }

    /// Store a known identity. When the table is full, mirrors the class-aware
    /// path eviction so a retained shared-medium path keeps its recalled
    /// identity: it prefers to evict a point-to-point identity, and never
    /// evicts a shared-medium identity for a point-to-point insert. Identities
    /// without a retained path are treated as point-to-point and evicted first.
    pub(super) fn insert_identity(
        &mut self,
        dest_hash: DestHash,
        pub_key: [u8; 64],
        shared_medium: bool,
    ) {
        if self.known_identities.insert(dest_hash, pub_key).is_ok() {
            return;
        }
        let point_to_point_victim = self
            .known_identities
            .keys()
            .filter(|k| !self.paths.get(*k).is_some_and(|p| p.shared_medium))
            .min_by_key(|k| self.paths.get(*k).map(|p| p.last_accessed).unwrap_or(0))
            .copied();
        let victim = point_to_point_victim.or_else(|| {
            if shared_medium {
                self.known_identities
                    .keys()
                    .min_by_key(|k| self.paths.get(*k).map(|p| p.last_accessed).unwrap_or(0))
                    .copied()
            } else {
                None
            }
        });
        if let Some(victim) = victim {
            self.known_identities.remove(&victim);
            let _ = self.known_identities.insert(dest_hash, pub_key);
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot — save / load
    // -----------------------------------------------------------------------

    /// Capture the current path table and known identities into a [`Snapshot`].
    ///
    /// `detail` controls whether the announce cache is included (see
    /// [`SnapshotDetail`]).
    pub fn save_snapshot(
        &self,
        detail: snapshot::SnapshotDetail,
    ) -> snapshot::Snapshot {
        use crate::snapshot::{IdentityEntry, PathEntry, Snapshot, SnapshotDetail};

        let include_announce = matches!(detail, SnapshotDetail::Standard | SnapshotDetail::Full);

        let paths = self
            .paths
            .iter()
            .map(|(k, p)| PathEntry {
                dest_hash: *k,
                via: p.via,
                learned_at: p.learned_at,
                last_accessed: p.last_accessed,
                last_snr: p.last_snr,
                hops: p.hops,
                announce_raw: if include_announce {
                    p.announce_raw.as_ref().map(|raw| raw.to_vec())
                } else {
                    None
                },
            })
            .collect();

        let identities = self
            .known_identities
            .iter()
            .map(|(k, v)| IdentityEntry {
                dest_hash: *k,
                pub_key: *v,
            })
            .collect();

        Snapshot {
            version: 1,
            paths,
            identities,
        }
    }

    /// Restore identities from a previously saved [`Snapshot`].
    ///
    /// Persisted paths are observations tied to transient interface indices.
    /// Until snapshots carry a stable interface identity and the runtime can
    /// explicitly rebind it, restoring those paths would make this node
    /// advertise routes it cannot forward on. They therefore remain inactive
    /// and must be learned again after restart. Identity entries that would
    /// overflow the table are silently dropped.
    pub fn load_snapshot(&mut self, snap: &snapshot::Snapshot) {
        for ie in &snap.identities {
            self.insert_identity(ie.dest_hash, ie.pub_key, false);
        }
    }
}
