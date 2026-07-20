//! Transport snapshot persistence for restart recovery.
//!
//! `Transport::save_snapshot()` captures learned path observations and cached
//! identities into a portable `Snapshot` struct. `Transport::load_snapshot()`
//! currently restores identities only: path observations refer to transient
//! interface indices and cannot safely become active routes after a power
//! cycle. They remain in the format for compatibility and future explicit
//! rebinding to stable interface identities. All structs derive
//! `serde::{Serialize, Deserialize}` when the optional `serde` feature is
//! enabled.

extern crate alloc;

use alloc::vec::Vec;
use rete_core::{DestHash, IdentityHash};

/// Controls how much state is captured in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SnapshotDetail {
    /// Paths + identities only.  No announce cache.
    /// Best for: leaf MCUs, flash-constrained targets.
    Minimal,
    /// Paths (with announce cache) + identities.
    /// Best for: transport relays, desktop nodes.
    Standard,
    /// Everything persistable.  Currently same as Standard.
    /// Future: link table hints, announce queue, etc.
    Full,
}

/// A persisted path observation.
///
/// This entry is not activated by `Transport::load_snapshot()` until snapshots
/// can identify and explicitly rebind the interface on which it was learned.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathEntry {
    pub dest_hash: DestHash,
    pub via: Option<IdentityHash>,
    pub learned_at: u64,
    pub last_accessed: u64,
    pub last_snr: i8,
    pub hops: u8,
    pub announce_raw: Option<Vec<u8>>,
}

/// A persisted identity entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IdentityEntry {
    pub dest_hash: DestHash,
    #[cfg_attr(feature = "serde", serde(with = "pub_key_serde"))]
    pub pub_key: [u8; 64],
}

/// Serialisable snapshot of transport state.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Snapshot {
    /// Format version for forward compatibility.
    pub version: u8,
    /// Saved observations retained for compatibility and future rebinding.
    /// They are not restored as active routes by `Transport::load_snapshot()`.
    pub paths: Vec<PathEntry>,
    /// Identities that can be safely restored without an interface binding.
    pub identities: Vec<IdentityEntry>,
}

/// Storage backend for transport state snapshots.
///
/// Implementors handle serialization format and storage medium:
/// - Hosted: JSON file on filesystem
/// - Embedded: postcard to flash via embedded-storage traits
pub trait SnapshotStore {
    /// Error type for storage operations.
    type Error: core::fmt::Debug;

    /// Persist a snapshot to the backing store.
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), Self::Error>;

    /// Load a previously persisted snapshot, or `None` if no snapshot exists.
    fn load(&mut self) -> Result<Option<Snapshot>, Self::Error>;
}

/// Custom serde for `[u8; 64]` — serde doesn't implement Serialize/Deserialize
/// for arrays larger than 32 elements.
#[cfg(feature = "serde")]
mod pub_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        let v: &[u8] = key;
        v.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: alloc::vec::Vec<u8> = Deserialize::deserialize(de)?;
        v.try_into().map_err(|v: alloc::vec::Vec<u8>| {
            serde::de::Error::invalid_length(v.len(), &"64 bytes")
        })
    }
}
