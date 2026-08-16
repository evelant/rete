//! Path table entries — learned routes to destinations.

extern crate alloc;

use alloc::vec::Vec;
use rete_core::IdentityHash;

/// Maximum retained raw announce bytes cached inline on one path.
///
/// One complete Reticulum announce never exceeds the transport MTU, so this
/// inline capacity retains every announce without a heap allocation.
pub const ANNOUNCE_CACHE_CAPACITY: usize = rete_core::MTU;

/// Inline, fixed-capacity cache for one raw announce packet.
///
/// Retained inline on the owning [`Path`] rather than in a heap `Vec` so a
/// large path table keeps its announce cache in the caller's backing storage
/// (PSRAM on embedded products) instead of consuming the strict internal heap
/// required by a Wi-Fi or BLE controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceCache {
    bytes: [u8; ANNOUNCE_CACHE_CAPACITY],
    len: u16,
}

impl AnnounceCache {
    /// Retain `raw` when it fits the fixed inline capacity.
    pub fn store(raw: &[u8]) -> Option<Self> {
        if raw.len() > ANNOUNCE_CACHE_CAPACITY {
            return None;
        }
        let mut bytes = [0_u8; ANNOUNCE_CACHE_CAPACITY];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self {
            bytes,
            len: raw.len() as u16,
        })
    }

    /// Borrow the cached announce bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Copy the cached announce bytes into a transient heap vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

/// Interface mode — determines path expiry timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    /// Default mode: 7-day path expiry.
    Default,
    /// Access Point mode: 1-day path expiry.
    AccessPoint,
    /// Roaming mode: 6-hour path expiry.
    Roaming,
}

/// Path expiry time for AccessPoint mode (1 day).
pub const PATH_EXPIRES_AP: u64 = 86400;
/// Path expiry time for Roaming mode (6 hours).
pub const PATH_EXPIRES_ROAMING: u64 = 21600;

/// A learned path to a destination.
#[derive(Debug, Clone)]
pub struct Path {
    /// Identity hash of the next-hop repeater, or `None` for direct.
    pub via: Option<IdentityHash>,
    /// Monotonic timestamp (ticks or seconds) when this path was learned.
    pub learned_at: u64,
    /// Monotonic timestamp of last access (for LRU eviction).
    pub last_accessed: u64,
    /// Last observed SNR × 4 (as in the Python reference).
    pub last_snr: i8,
    /// Hop count to destination.
    pub hops: u8,
    /// Cached raw announce packet (for path request responses).
    pub announce_raw: Option<AnnounceCache>,
    /// Interface mode this path was learned on.
    pub interface_mode: InterfaceMode,
    /// Interface index the announce was received on (for relay routing).
    /// Matches Python `IDX_PT_RVCD_IF`.
    pub received_on: Option<u8>,
}

impl Path {
    /// Create a direct path (no intermediate repeater).
    pub fn direct(learned_at: u64) -> Self {
        Path {
            via: None,
            learned_at,
            last_accessed: learned_at,
            last_snr: 0,
            hops: 1,
            announce_raw: None,
            interface_mode: InterfaceMode::Default,
            received_on: None,
        }
    }

    /// Create a path via an intermediate repeater.
    pub fn via_repeater(repeater: IdentityHash, hops: u8, learned_at: u64) -> Self {
        Path {
            via: Some(repeater),
            learned_at,
            last_accessed: learned_at,
            last_snr: 0,
            hops,
            announce_raw: None,
            interface_mode: InterfaceMode::Default,
            received_on: None,
        }
    }

    /// Get the path expiry duration based on interface mode.
    pub fn expiry_time(&self) -> u64 {
        match self.interface_mode {
            InterfaceMode::Default => super::transport::PATH_EXPIRES,
            InterfaceMode::AccessPoint => PATH_EXPIRES_AP,
            InterfaceMode::Roaming => PATH_EXPIRES_ROAMING,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_direct_creation() {
        let path = Path::direct(100);
        assert!(path.via.is_none());
        assert_eq!(path.hops, 1);
        assert_eq!(path.learned_at, 100);
        assert!(path.announce_raw.is_none());
    }

    #[test]
    fn test_path_via_repeater_creation() {
        let repeater = IdentityHash::from([0xAAu8; 16]);
        let path = Path::via_repeater(repeater, 3, 200);
        assert_eq!(path.via, Some(repeater));
        assert_eq!(path.hops, 3);
        assert_eq!(path.learned_at, 200);
        assert!(path.announce_raw.is_none());
    }

    #[test]
    fn test_path_announce_raw_storage() {
        let mut path = Path::direct(50);
        assert!(path.announce_raw.is_none());

        let raw_data = alloc::vec![0x01, 0x02, 0x03];
        path.announce_raw = AnnounceCache::store(&raw_data);
        assert_eq!(path.announce_raw.as_ref().unwrap().as_slice(), &raw_data[..]);
    }
}
