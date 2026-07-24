//! Packet receipt tracking — validates delivery proofs for sent packets.
//!
//! When the node sends a DATA packet, it registers a [`PacketReceipt`] keyed
//! by the truncated packet hash. When a PROOF arrives, the receipt table
//! validates the signature and fires a callback.
//!
//! Generic over [`StorageMap`] so it works with both fixed-size
//! (`FnvIndexMap`) and growable (`HashMap`) backends.

extern crate alloc;

use crate::storage::StorageMap;
use alloc::vec::Vec;
use rete_core::{Identity, LinkId, TRUNCATED_HASH_LEN};

/// Terminal state for a DATA, Link DATA, or proven channel delivery.
///
/// Channel proof success produces [`Self::Delivered`]. Channel receipt timeout
/// is currently maintained separately and does not produce [`Self::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptTerminal {
    /// A valid delivery proof covered this full packet hash.
    Delivered([u8; 32]),
    /// A DATA receipt reached its configured timeout without a valid proof.
    Failed([u8; 32]),
}

impl ReceiptTerminal {
    /// Full packet hash used to correlate the terminal state.
    pub const fn packet_hash(&self) -> &[u8; 32] {
        match self {
            Self::Delivered(packet_hash) | Self::Failed(packet_hash) => packet_hash,
        }
    }
}

/// Receipt class whose terminal notification is about to be produced.
///
/// This distinction lets product-owned sinks route DATA and channel delivery
/// state to different bounded records before transport mutates either receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    /// A receipt registered for an outbound Reticulum DATA packet.
    Data,
    /// A receipt registered for ordinary context-NONE DATA on an owned Link.
    LinkData,
    /// A receipt registered for an outbound channel message.
    Channel,
}

/// Exact receipt terminal candidate presented before receipt state is mutated.
///
/// The full packet hash avoids forcing a sink to reconstruct identity from the
/// truncated receipt-table key. A reservation is bound to both this hash and
/// [`ReceiptKind`], even if later proof validation rejects the packet and the
/// reservation is dropped unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptCandidate {
    /// Class of receipt that may reach a terminal state.
    pub kind: ReceiptKind,
    /// Full packet hash used to correlate the terminal state.
    pub packet_hash: [u8; 32],
}

impl ReceiptCandidate {
    /// Construct a candidate for an outbound DATA receipt.
    pub const fn data(packet_hash: [u8; 32]) -> Self {
        Self {
            kind: ReceiptKind::Data,
            packet_hash,
        }
    }

    /// Construct a candidate for an outbound channel receipt.
    pub const fn channel(packet_hash: [u8; 32]) -> Self {
        Self {
            kind: ReceiptKind::Channel,
            packet_hash,
        }
    }

    /// Construct a candidate for an outbound ordinary Link DATA receipt.
    pub const fn link_data(packet_hash: [u8; 32]) -> Self {
        Self {
            kind: ReceiptKind::LinkData,
            packet_hash,
        }
    }
}

/// A terminal-event sink cannot reserve another infallible commit slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSinkFull;

/// One terminal-event slot reserved before receipt state is mutated.
pub trait ReceiptTerminalReservation {
    /// Commit the terminal state without allocation or failure.
    ///
    /// The terminal packet hash must equal the full hash supplied to
    /// [`ReceiptTerminalSink::try_reserve`] for this reservation.
    fn commit(self, terminal: ReceiptTerminal);
}

/// Reservable destination for receipt terminal states.
///
/// A successful reservation must make [`ReceiptTerminalReservation::commit`]
/// infallible. Dropping an unused reservation releases it. Implementations may
/// use a fixed queue slot, a pre-reserved vector element, or a product-owned
/// submission record.
pub trait ReceiptTerminalSink {
    /// Reservation borrowing this sink until it is committed or dropped.
    type Reservation<'a>: ReceiptTerminalReservation
    where
        Self: 'a;

    /// Reserve one exact terminal candidate before its receipt is removed.
    fn try_reserve(
        &mut self,
        candidate: ReceiptCandidate,
    ) -> Result<Self::Reservation<'_>, ReceiptSinkFull>;
}

/// Heapless fixed-capacity sink for receipt terminal states.
///
/// Reserving a slot does not change the visible length. The reservation's
/// exclusive borrow guarantees that its later commit can push without
/// competing for capacity. Dropping it without committing immediately makes
/// the capacity available again.
#[derive(Debug)]
pub struct FixedReceiptTerminalSink<const N: usize> {
    terminals: heapless::Vec<ReceiptTerminal, N>,
}

impl<const N: usize> FixedReceiptTerminalSink<N> {
    /// Construct an empty sink.
    pub const fn new() -> Self {
        Self {
            terminals: heapless::Vec::new(),
        }
    }

    /// Number of committed terminal states.
    pub fn len(&self) -> usize {
        self.terminals.len()
    }

    /// Whether no terminal states are committed.
    pub fn is_empty(&self) -> bool {
        self.terminals.is_empty()
    }

    /// Whether another terminal state cannot currently be reserved.
    pub fn is_full(&self) -> bool {
        self.terminals.is_full()
    }

    /// View committed terminal states in commit order.
    pub fn as_slice(&self) -> &[ReceiptTerminal] {
        self.terminals.as_slice()
    }

    /// Remove and return the most recently committed terminal state.
    pub fn pop(&mut self) -> Option<ReceiptTerminal> {
        self.terminals.pop()
    }

    /// Remove all committed terminal states.
    pub fn clear(&mut self) {
        self.terminals.clear();
    }
}

impl<const N: usize> Default for FixedReceiptTerminalSink<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Reserved slot in a [`FixedReceiptTerminalSink`].
pub struct FixedReceiptTerminalReservation<'a, const N: usize> {
    terminals: &'a mut heapless::Vec<ReceiptTerminal, N>,
    candidate: ReceiptCandidate,
}

impl<const N: usize> ReceiptTerminalSink for FixedReceiptTerminalSink<N> {
    type Reservation<'a>
        = FixedReceiptTerminalReservation<'a, N>
    where
        Self: 'a;

    fn try_reserve(
        &mut self,
        candidate: ReceiptCandidate,
    ) -> Result<Self::Reservation<'_>, ReceiptSinkFull> {
        if self.terminals.is_full() {
            Err(ReceiptSinkFull)
        } else {
            Ok(FixedReceiptTerminalReservation {
                terminals: &mut self.terminals,
                candidate,
            })
        }
    }
}

impl<const N: usize> ReceiptTerminalReservation for FixedReceiptTerminalReservation<'_, N> {
    fn commit(self, terminal: ReceiptTerminal) {
        assert_eq!(
            terminal.packet_hash(),
            &self.candidate.packet_hash,
            "receipt terminal must match its reserved candidate"
        );
        self.terminals
            .push(terminal)
            .expect("reserved fixed receipt slot must accept commit");
    }
}

/// Allocation-free outcome of one receipt-failure scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptTickSummary {
    /// Terminal failures committed to the supplied sink.
    pub emitted: usize,
    /// At least one failed receipt remains because the sink was full.
    pub deferred: bool,
}

/// Status of a packet receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Waiting for proof.
    Sent,
    /// Proof received and validated.
    Delivered,
    /// Timed out without proof.
    Failed,
}

/// Why a delivery receipt could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRegistrationError {
    /// Another outstanding receipt already uses the same truncated packet
    /// hash. Replacing it would make one of the proofs ambiguous.
    HashAlreadyTracked,
    /// The bounded receipt table has no free entry.
    TableFull,
}

/// A receipt for a sent packet, awaiting delivery proof.
#[derive(Debug, Clone)]
pub struct PacketReceipt {
    /// Full 32-byte packet hash. Truncated hash = `packet_hash[..16]`.
    pub packet_hash: [u8; 32],
    /// Destination's public key (64 bytes) — used to verify the proof signature.
    pub dest_pub_key: [u8; 64],
    /// Current receipt status.
    pub status: ReceiptStatus,
    /// Monotonic timestamp when the packet was sent.
    pub sent_at: u64,
    /// Timeout in seconds (0 = no timeout).
    pub timeout: u64,
}

/// A receipt for ordinary context-NONE DATA sent on an established Link.
///
/// Link proofs address the Link ID, not the truncated packet hash used by
/// ordinary DATA receipts. The explicit proof payload carries the complete
/// packet hash and is signed by the peer's Link signing key, so all three
/// values are retained until the receipt reaches a terminal state.
#[derive(Debug, Clone)]
pub struct LinkDataReceipt {
    /// Full 32-byte packet hash covered by the expected explicit proof.
    pub packet_hash: [u8; 32],
    /// Link ID required in the proof packet destination field.
    pub link_id: LinkId,
    /// Peer's Ed25519 Link signing key captured from the authenticated handshake.
    pub peer_ed25519_pub: [u8; 32],
    /// Current receipt status.
    pub status: ReceiptStatus,
    /// Monotonic timestamp when the packet was sent.
    pub sent_at: u64,
    /// Timeout in seconds (0 = no timeout).
    pub timeout: u64,
}

/// Outstanding ordinary Link DATA receipts keyed by truncated packet hash.
///
/// The truncated key only selects a candidate. Every proof and cancellation
/// also has to match the complete hash retained in [`LinkDataReceipt`].
pub struct LinkDataReceiptTable<
    M: StorageMap<[u8; TRUNCATED_HASH_LEN], LinkDataReceipt>,
> {
    entries: M,
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], LinkDataReceipt>> Default
    for LinkDataReceiptTable<M>
{
    fn default() -> Self {
        Self {
            entries: M::default(),
        }
    }
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], LinkDataReceipt>> LinkDataReceiptTable<M> {
    fn key(packet_hash: &[u8; 32]) -> [u8; TRUNCATED_HASH_LEN] {
        packet_hash[..TRUNCATED_HASH_LEN]
            .try_into()
            .expect("truncated packet hash length is fixed")
    }

    /// Whether the backing map cannot admit another receipt.
    pub fn is_full(&self) -> bool {
        self.entries.is_full()
    }

    /// Register one ordinary Link DATA receipt without replacing a collision.
    pub fn register(
        &mut self,
        packet_hash: [u8; 32],
        link_id: LinkId,
        peer_ed25519_pub: [u8; 32],
        now: u64,
        timeout: u64,
    ) -> Result<(), ReceiptRegistrationError> {
        let key = Self::key(&packet_hash);
        if self.entries.contains_key(&key) {
            return Err(ReceiptRegistrationError::HashAlreadyTracked);
        }
        if self.entries.is_full() {
            return Err(ReceiptRegistrationError::TableFull);
        }

        let receipt = LinkDataReceipt {
            packet_hash,
            link_id,
            peer_ed25519_pub,
            status: ReceiptStatus::Sent,
            sent_at: now,
            timeout,
        };
        self.entries
            .insert(key, receipt)
            .map(|_| ())
            .map_err(|_| ReceiptRegistrationError::TableFull)
    }

    /// Number of tracked Link DATA receipts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no Link DATA receipts are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current status for an outstanding receipt with this complete hash.
    pub fn status(&self, packet_hash: &[u8; 32]) -> Option<ReceiptStatus> {
        let receipt = self.entries.get(&Self::key(packet_hash))?;
        (receipt.packet_hash == *packet_hash).then_some(receipt.status)
    }

    /// Look up the exact candidate selected by a canonical explicit Link proof.
    ///
    /// Canonical proofs are exactly `packet_hash[32] || signature[64]`.
    pub fn proof_candidate(
        &self,
        link_id: &LinkId,
        proof_payload: &[u8],
    ) -> Option<&LinkDataReceipt> {
        if proof_payload.len() != 96 {
            return None;
        }
        let packet_hash: [u8; 32] = proof_payload[..32].try_into().ok()?;
        self.entries
            .get(&Self::key(&packet_hash))
            .filter(|receipt| {
                receipt.status == ReceiptStatus::Sent
                    && receipt.link_id == *link_id
                    && receipt.packet_hash == packet_hash
            })
    }

    /// Validate and atomically reclaim a canonical explicit Link proof.
    pub fn validate_proof(
        &mut self,
        link_id: &LinkId,
        proof_payload: &[u8],
    ) -> Option<[u8; 32]> {
        let receipt = self.proof_candidate(link_id, proof_payload)?;
        let packet_hash = receipt.packet_hash;
        Identity::verify_raw_ed25519(
            &receipt.peer_ed25519_pub,
            &packet_hash,
            &proof_payload[32..],
        )
        .ok()?;

        let key = Self::key(&packet_hash);
        let removed = self.entries.remove(&key);
        debug_assert!(matches!(
            removed,
            Some(receipt)
                if receipt.packet_hash == packet_hash && receipt.link_id == *link_id
        ));
        Some(packet_hash)
    }

    /// Cancel an outstanding Link DATA receipt by its complete packet hash.
    pub fn remove_full(&mut self, packet_hash: &[u8; 32]) -> bool {
        let key = Self::key(packet_hash);
        if !matches!(
            self.entries.get(&key),
            Some(receipt) if receipt.packet_hash == *packet_hash
        ) {
            return false;
        }
        self.entries.remove(&key).is_some()
    }

    /// Fail receipts whose timeout elapsed or whose owned Link no longer exists.
    ///
    /// Each sink slot is reserved before the corresponding receipt is removed.
    /// A full sink leaves that receipt intact for a later retry.
    pub fn tick_into<T, F>(
        &mut self,
        now: u64,
        sink: &mut T,
        mut link_exists: F,
    ) -> ReceiptTickSummary
    where
        T: ReceiptTerminalSink,
        F: FnMut(&LinkId) -> bool,
    {
        let mut emitted = 0;
        loop {
            let failed = self.entries.iter().find_map(|(key, receipt)| {
                (receipt.status == ReceiptStatus::Sent
                    && (!link_exists(&receipt.link_id)
                        || (receipt.timeout > 0
                            && now.saturating_sub(receipt.sent_at) > receipt.timeout)))
                .then_some((*key, receipt.packet_hash))
            });
            let Some((key, packet_hash)) = failed else {
                return ReceiptTickSummary {
                    emitted,
                    deferred: false,
                };
            };
            let reservation = match sink.try_reserve(ReceiptCandidate::link_data(packet_hash)) {
                Ok(reservation) => reservation,
                Err(ReceiptSinkFull) => {
                    return ReceiptTickSummary {
                        emitted,
                        deferred: true,
                    };
                }
            };
            let removed = self.entries.remove(&key);
            debug_assert!(matches!(
                removed,
                Some(receipt) if receipt.packet_hash == packet_hash
            ));
            reservation.commit(ReceiptTerminal::Failed(packet_hash));
            emitted += 1;
        }
    }

    /// Expire Link DATA receipts into an owned list of complete packet hashes.
    pub fn tick<F>(&mut self, now: u64, link_exists: F) -> Vec<[u8; 32]>
    where
        F: FnMut(&LinkId) -> bool,
    {
        let mut failed = Vec::new();
        failed.reserve_exact(self.entries.len());
        let mut sink = LinkDataFailedHashVecSink {
            hashes: &mut failed,
        };
        let summary = self.tick_into(now, &mut sink, link_exists);
        debug_assert!(!summary.deferred);
        failed
    }
}

struct LinkDataFailedHashVecSink<'a> {
    hashes: &'a mut Vec<[u8; 32]>,
}

struct LinkDataFailedHashVecReservation<'a> {
    hashes: &'a mut Vec<[u8; 32]>,
    candidate: ReceiptCandidate,
}

impl ReceiptTerminalSink for LinkDataFailedHashVecSink<'_> {
    type Reservation<'a>
        = LinkDataFailedHashVecReservation<'a>
    where
        Self: 'a;

    fn try_reserve(
        &mut self,
        candidate: ReceiptCandidate,
    ) -> Result<Self::Reservation<'_>, ReceiptSinkFull> {
        debug_assert!(self.hashes.len() < self.hashes.capacity());
        debug_assert_eq!(candidate.kind, ReceiptKind::LinkData);
        Ok(LinkDataFailedHashVecReservation {
            hashes: self.hashes,
            candidate,
        })
    }
}

impl ReceiptTerminalReservation for LinkDataFailedHashVecReservation<'_> {
    fn commit(self, terminal: ReceiptTerminal) {
        let ReceiptTerminal::Failed(packet_hash) = terminal else {
            unreachable!("Link DATA timeout scan cannot deliver a receipt")
        };
        assert_eq!(packet_hash, self.candidate.packet_hash);
        self.hashes.push(packet_hash);
    }
}

/// Table of outstanding packet receipts.
///
/// Generic over `M` — the map backend (fixed-size or growable).
pub struct ReceiptTable<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> {
    entries: M,
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> Default for ReceiptTable<M> {
    fn default() -> Self {
        ReceiptTable {
            entries: M::default(),
        }
    }
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> ReceiptTable<M> {
    fn key(packet_hash: &[u8; 32]) -> [u8; TRUNCATED_HASH_LEN] {
        let mut truncated = [0u8; TRUNCATED_HASH_LEN];
        truncated.copy_from_slice(&packet_hash[..TRUNCATED_HASH_LEN]);
        truncated
    }

    /// Whether the backing map cannot admit another receipt.
    pub fn is_full(&self) -> bool {
        self.entries.is_full()
    }

    /// Register a receipt for a sent packet.
    ///
    /// Registration never replaces an existing truncated hash. Doing so would
    /// orphan the previous packet and make an eventual proof ambiguous.
    pub fn register(
        &mut self,
        packet_hash: [u8; 32],
        dest_pub_key: [u8; 64],
        now: u64,
        timeout: u64,
    ) -> Result<(), ReceiptRegistrationError> {
        let truncated = Self::key(&packet_hash);
        if self.entries.contains_key(&truncated) {
            return Err(ReceiptRegistrationError::HashAlreadyTracked);
        }
        if self.entries.is_full() {
            return Err(ReceiptRegistrationError::TableFull);
        }
        let receipt = PacketReceipt {
            packet_hash,
            dest_pub_key,
            status: ReceiptStatus::Sent,
            sent_at: now,
            timeout,
        };
        self.entries
            .insert(truncated, receipt)
            .map(|_| ())
            .map_err(|_| ReceiptRegistrationError::TableFull)
    }

    /// Look up a receipt by truncated hash.
    pub fn get(&self, truncated_hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&PacketReceipt> {
        self.entries.get(truncated_hash)
    }

    /// Look up a receipt status by its full packet hash.
    pub fn status(&self, packet_hash: &[u8; 32]) -> Option<ReceiptStatus> {
        let receipt = self.entries.get(&Self::key(packet_hash))?;
        (receipt.packet_hash == *packet_hash).then_some(receipt.status)
    }

    /// Cancel an outstanding receipt by its complete packet hash.
    ///
    /// A truncated-hash collision never removes the tracked sibling.
    pub fn remove_full(&mut self, packet_hash: &[u8; 32]) -> bool {
        let key = Self::key(packet_hash);
        if !matches!(self.entries.get(&key), Some(receipt) if receipt.packet_hash == *packet_hash) {
            return false;
        }
        self.entries.remove(&key).is_some()
    }

    /// Validate a proof against a registered receipt.
    ///
    /// # Proof formats
    /// - **Explicit proof** (96 bytes): `packet_hash[32] || signature[64]`
    /// - **Implicit proof** (64 bytes): `signature[64]` (packet_hash recalled from receipt)
    ///
    /// Returns the full packet hash on success, or `None` if validation fails.
    /// A successfully validated receipt is removed before this method returns.
    pub fn validate_proof(
        &mut self,
        truncated_hash: &[u8; TRUNCATED_HASH_LEN],
        proof_payload: &[u8],
    ) -> Option<[u8; 32]> {
        let receipt = self.entries.get(truncated_hash)?;
        if receipt.status != ReceiptStatus::Sent {
            return None;
        }

        let (packet_hash, signature) = if proof_payload.len() >= 96 {
            // Explicit proof: packet_hash[32] || signature[64]
            let mut ph = [0u8; 32];
            ph.copy_from_slice(&proof_payload[..32]);
            // Verify the packet hash matches
            if ph != receipt.packet_hash {
                return None;
            }
            (ph, &proof_payload[32..96])
        } else if proof_payload.len() >= 64 {
            // Implicit proof: signature[64] only
            (receipt.packet_hash, &proof_payload[..64])
        } else {
            return None;
        };

        // Verify signature using the destination's public key
        let identity = Identity::from_public_key(&receipt.dest_pub_key).ok()?;
        identity.verify(&packet_hash, signature).ok()?;

        // A validated proof is itself the complete terminal notification.
        // Reclaim the entry before returning so low-level Transport callers
        // cannot accidentally leak delivered receipts by omitting a separate
        // drain operation.
        let removed = self.entries.remove(truncated_hash);
        debug_assert!(matches!(removed, Some(receipt) if receipt.packet_hash == packet_hash));

        Some(packet_hash)
    }

    /// Expire DATA receipts into a caller-reserved terminal sink.
    ///
    /// Each sink slot is reserved before its receipt is removed. If the sink is
    /// full, the expired receipt remains `Sent` and can be reported on a later
    /// call; a valid proof received before that retry may still complete it as
    /// delivered. The bounded implementation rescans after each removal,
    /// making a full expiry pass O(P²) in the number of outstanding receipts.
    pub fn tick_into<T: ReceiptTerminalSink>(
        &mut self,
        now: u64,
        sink: &mut T,
    ) -> ReceiptTickSummary {
        let mut emitted = 0;
        loop {
            let expired = self.entries.iter().find_map(|(key, receipt)| {
                (receipt.status == ReceiptStatus::Sent
                    && receipt.timeout > 0
                    && now.saturating_sub(receipt.sent_at) > receipt.timeout)
                    .then_some((*key, receipt.packet_hash))
            });
            let Some((key, packet_hash)) = expired else {
                return ReceiptTickSummary {
                    emitted,
                    deferred: false,
                };
            };
            let candidate = ReceiptCandidate::data(packet_hash);
            let reservation = match sink.try_reserve(candidate) {
                Ok(reservation) => reservation,
                Err(ReceiptSinkFull) => {
                    return ReceiptTickSummary {
                        emitted,
                        deferred: true,
                    };
                }
            };
            let removed = self.entries.remove(&key);
            debug_assert!(matches!(removed, Some(receipt) if receipt.packet_hash == packet_hash));
            reservation.commit(ReceiptTerminal::Failed(packet_hash));
            emitted += 1;
        }
    }

    /// Expire and remove receipts that have timed out.
    ///
    /// Returned hashes are the complete failure notification: expired entries
    /// no longer consume table capacity when this method returns. The complete
    /// output capacity is reserved before any receipt is removed.
    pub fn tick(&mut self, now: u64) -> Vec<[u8; 32]> {
        let mut failed = Vec::new();
        failed.reserve_exact(self.entries.len());
        let mut sink = FailedHashVecSink {
            hashes: &mut failed,
        };
        let summary = self.tick_into(now, &mut sink);
        debug_assert!(!summary.deferred);
        failed
    }
}

struct FailedHashVecSink<'a> {
    hashes: &'a mut Vec<[u8; 32]>,
}

struct FailedHashVecReservation<'a> {
    hashes: &'a mut Vec<[u8; 32]>,
    candidate: ReceiptCandidate,
}

impl ReceiptTerminalSink for FailedHashVecSink<'_> {
    type Reservation<'a>
        = FailedHashVecReservation<'a>
    where
        Self: 'a;

    fn try_reserve(
        &mut self,
        candidate: ReceiptCandidate,
    ) -> Result<Self::Reservation<'_>, ReceiptSinkFull> {
        debug_assert!(self.hashes.len() < self.hashes.capacity());
        debug_assert_eq!(candidate.kind, ReceiptKind::Data);
        Ok(FailedHashVecReservation {
            hashes: self.hashes,
            candidate,
        })
    }
}

impl ReceiptTerminalReservation for FailedHashVecReservation<'_> {
    fn commit(self, terminal: ReceiptTerminal) {
        let ReceiptTerminal::Failed(packet_hash) = terminal else {
            unreachable!("timeout scan cannot deliver a receipt")
        };
        assert_eq!(
            packet_hash, self.candidate.packet_hash,
            "receipt timeout must match its reserved candidate"
        );
        self.hashes.push(packet_hash);
    }
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> ReceiptTable<M> {
    /// Number of tracked receipts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove a receipt (after delivery or failure).
    pub fn remove(&mut self, truncated_hash: &[u8; TRUNCATED_HASH_LEN]) {
        self.entries.remove(truncated_hash);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use heapless::FnvIndexMap;

    type TestTable = ReceiptTable<FnvIndexMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt, 16>>;
    type SmallTable = ReceiptTable<FnvIndexMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt, 4>>;
    type LinkDataTestTable =
        LinkDataReceiptTable<FnvIndexMap<[u8; TRUNCATED_HASH_LEN], LinkDataReceipt, 4>>;

    fn make_test_identity() -> Identity {
        Identity::from_seed(b"receipt-test-identity").unwrap()
    }

    #[test]
    fn receipt_register_and_lookup() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0xABu8; 32];

        assert_eq!(
            table.register(packet_hash, identity.public_key(), 100, 30),
            Ok(())
        );
        assert_eq!(table.len(), 1);

        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
        let receipt = table.get(&trunc).unwrap();
        assert_eq!(receipt.packet_hash, packet_hash);
        assert_eq!(receipt.status, ReceiptStatus::Sent);
    }

    #[test]
    fn receipt_validate_explicit_proof() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Build explicit proof: packet_hash[32] || signature[64]
        let sig = identity.sign(&packet_hash).unwrap();
        let mut proof = [0u8; 96];
        proof[..32].copy_from_slice(&packet_hash);
        proof[32..].copy_from_slice(&sig);

        let result = table.validate_proof(&trunc, &proof);
        assert_eq!(result, Some(packet_hash));
        assert!(table.get(&trunc).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn receipt_validate_implicit_proof() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Build implicit proof: signature[64] only
        let sig = identity.sign(&packet_hash).unwrap();

        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, Some(packet_hash));
        assert!(table.is_empty());
    }

    #[test]
    fn receipt_bad_signature_rejected() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Corrupt signature
        let mut sig = identity.sign(&packet_hash).unwrap();
        sig[0] ^= 0xFF;

        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, None);
        // Status should still be Sent
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Sent);
    }

    #[test]
    fn receipt_timeout_expiry() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Before timeout
        assert!(table.tick(129).is_empty());
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Sent);

        // After timeout
        assert_eq!(table.tick(131), vec![packet_hash]);
        assert!(table.get(&trunc).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn full_terminal_sink_defers_timeout_without_removing_receipt() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];
        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let mut sink = FixedReceiptTerminalSink::<0>::default();

        assert_eq!(
            table.tick_into(131, &mut sink),
            ReceiptTickSummary {
                emitted: 0,
                deferred: true,
            }
        );
        assert_eq!(table.status(&packet_hash), Some(ReceiptStatus::Sent));
    }

    #[test]
    fn valid_proof_can_win_while_expired_timeout_is_deferred() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x43u8; 32];
        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let mut full_sink = FixedReceiptTerminalSink::<0>::new();
        assert!(table.tick_into(131, &mut full_sink).deferred);

        let key = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
        let signature = identity.sign(&packet_hash).unwrap();
        assert_eq!(table.validate_proof(&key, &signature), Some(packet_hash));
        assert!(table.is_empty());
    }

    #[test]
    fn dropped_fixed_sink_reservation_restores_capacity() {
        let mut sink = FixedReceiptTerminalSink::<1>::new();
        let candidate = ReceiptCandidate::data([0x44; 32]);
        let reservation = sink.try_reserve(candidate).unwrap();
        drop(reservation);

        assert!(sink.is_empty());
        assert!(!sink.is_full());
        sink.try_reserve(candidate)
            .unwrap()
            .commit(ReceiptTerminal::Failed([0x44; 32]));
        assert_eq!(sink.len(), 1);
        assert!(sink.is_full());
    }

    #[test]
    fn timeout_scan_commits_only_reserved_slots_and_retries_remainder() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let first = [0x41u8; 32];
        let second = [0x42u8; 32];
        table
            .register(first, identity.public_key(), 100, 30)
            .unwrap();
        table
            .register(second, identity.public_key(), 100, 30)
            .unwrap();

        let mut first_sink = FixedReceiptTerminalSink::<1>::default();
        assert_eq!(
            table.tick_into(131, &mut first_sink),
            ReceiptTickSummary {
                emitted: 1,
                deferred: true,
            }
        );
        assert_eq!(table.len(), 1);

        let mut second_sink = FixedReceiptTerminalSink::<1>::default();
        assert_eq!(
            table.tick_into(131, &mut second_sink),
            ReceiptTickSummary {
                emitted: 1,
                deferred: false,
            }
        );
        assert!(table.is_empty());

        let delivered: alloc::vec::Vec<_> = first_sink
            .terminals
            .into_iter()
            .chain(second_sink.terminals)
            .collect();
        assert!(delivered.contains(&ReceiptTerminal::Failed(first)));
        assert!(delivered.contains(&ReceiptTerminal::Failed(second)));
    }

    #[test]
    fn test_receipt_table_full() {
        let mut table = SmallTable::default();
        let identity = make_test_identity();

        for i in 0u8..4 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            assert_eq!(
                table.register(hash, identity.public_key(), 100, 30),
                Ok(()),
                "slot {} should succeed",
                i
            );
        }
        assert_eq!(table.len(), 4);

        // 5th registration should fail without replacing an entry.
        let mut overflow_hash = [0u8; 32];
        overflow_hash[0] = 0xFF;
        assert_eq!(
            table.register(overflow_hash, identity.public_key(), 100, 30),
            Err(ReceiptRegistrationError::TableFull),
            "table full should be explicit"
        );
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn validated_proof_is_reclaimed_and_duplicate_ignored() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table
            .register(packet_hash, identity.public_key(), 100, 30)
            .unwrap();
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // First proof — should succeed
        let sig = identity.sign(&packet_hash).unwrap();
        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, Some(packet_hash));
        assert!(table.get(&trunc).is_none());

        // Second proof on the reclaimed receipt should return None.
        let result2 = table.validate_proof(&trunc, &sig);
        assert_eq!(
            result2, None,
            "already-delivered receipt should reject proof"
        );
    }

    #[test]
    fn duplicate_truncated_hash_never_replaces_outstanding_receipt() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let first = [0x42u8; 32];
        let mut colliding = first;
        colliding[31] ^= 0xff;

        table
            .register(first, identity.public_key(), 100, 30)
            .unwrap();
        assert_eq!(
            table.register(colliding, identity.public_key(), 101, 30),
            Err(ReceiptRegistrationError::HashAlreadyTracked)
        );
        assert_eq!(table.status(&first), Some(ReceiptStatus::Sent));
        assert_eq!(table.status(&colliding), None);
        assert!(!table.remove_full(&colliding));
        assert_eq!(table.status(&first), Some(ReceiptStatus::Sent));
        assert!(table.remove_full(&first));
        assert!(table.is_empty());
    }

    #[test]
    fn delivered_and_timed_out_receipts_are_removed_atomically() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let delivered_hash = [0x42u8; 32];
        table
            .register(delivered_hash, identity.public_key(), 100, 30)
            .unwrap();

        let trunc = delivered_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
        let signature = identity.sign(&delivered_hash).unwrap();
        assert_eq!(
            table.validate_proof(&trunc, &signature),
            Some(delivered_hash)
        );
        assert_eq!(table.status(&delivered_hash), None);

        let timed_out_hash = [0x43u8; 32];
        table
            .register(timed_out_hash, identity.public_key(), 100, 30)
            .unwrap();
        assert_eq!(table.tick(131), vec![timed_out_hash]);
        assert_eq!(table.status(&timed_out_hash), None);
        assert!(table.is_empty());
    }

    #[test]
    fn link_data_receipt_requires_canonical_explicit_proof() {
        let mut table = LinkDataTestTable::default();
        let signer = make_test_identity();
        let wrong_signer = Identity::from_seed(b"wrong-link-data-proof").unwrap();
        let link_id = LinkId::from([0x21; TRUNCATED_HASH_LEN]);
        let wrong_link = LinkId::from([0x22; TRUNCATED_HASH_LEN]);
        let packet_hash = [0x31; 32];
        table
            .register(
                packet_hash,
                link_id,
                *signer.ed25519_pub(),
                100,
                30,
            )
            .unwrap();

        let mut proof = [0u8; 96];
        proof[..32].copy_from_slice(&packet_hash);
        proof[32..].copy_from_slice(&wrong_signer.sign(&packet_hash).unwrap());
        assert!(table.proof_candidate(&link_id, &proof).is_some());
        assert_eq!(table.validate_proof(&link_id, &proof), None);
        assert_eq!(table.status(&packet_hash), Some(ReceiptStatus::Sent));

        proof[32..].copy_from_slice(&signer.sign(&packet_hash).unwrap());
        assert!(table.proof_candidate(&wrong_link, &proof).is_none());
        let mut wrong_hash = proof;
        wrong_hash[0] ^= 0xff;
        assert!(table.proof_candidate(&link_id, &wrong_hash).is_none());
        let mut noncanonical = proof.to_vec();
        noncanonical.push(0);
        assert!(table.proof_candidate(&link_id, &noncanonical).is_none());
        assert_eq!(
            table.validate_proof(&link_id, &proof),
            Some(packet_hash)
        );
        assert!(table.is_empty());
    }
}
