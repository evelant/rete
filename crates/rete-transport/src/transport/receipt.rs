//! Delivery proofs and receipts.

use rete_core::{DestType, Identity, LinkId, PacketBuilder, PacketType, TRUNCATED_HASH_LEN};

use crate::{ReceiptRegistrationError, ReceiptStatus};

use super::Transport;

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Register a receipt for a sent packet.
    pub fn register_receipt(
        &mut self,
        packet_hash: [u8; 32],
        dest_pub_key: [u8; 64],
        now: u64,
        timeout: u64,
    ) -> Result<(), ReceiptRegistrationError> {
        self.receipts
            .register(packet_hash, dest_pub_key, now, timeout)
    }

    /// Whether the receipt table cannot admit another packet.
    pub fn receipt_table_is_full(&self) -> bool {
        self.receipts.is_full()
    }

    /// Number of tracked receipts.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Current status for an outstanding receipt with this full packet hash.
    /// Delivered and timed-out receipts are reclaimed atomically and return
    /// `None`; their terminal outcome is reported by `IngestResult` or
    /// `TickResult`, respectively.
    pub fn receipt_status(&self, packet_hash: &[u8; 32]) -> Option<ReceiptStatus> {
        self.receipts.status(packet_hash)
    }

    /// Cancel an outstanding receipt using its complete packet hash.
    ///
    /// This is used when a higher-level transaction has multiple in-flight
    /// attempts and one sibling proof makes the remaining attempts obsolete.
    pub fn cancel_receipt(&mut self, packet_hash: &[u8; 32]) -> bool {
        self.receipts.remove_full(packet_hash)
    }

    /// Register a receipt for ordinary context-NONE DATA sent on an owned Link.
    pub(crate) fn register_link_data_receipt(
        &mut self,
        packet_hash: [u8; 32],
        link_id: LinkId,
        peer_ed25519_pub: [u8; 32],
        now: u64,
        timeout: u64,
    ) -> Result<(), ReceiptRegistrationError> {
        self.link_data_receipts.register(
            packet_hash,
            link_id,
            peer_ed25519_pub,
            now,
            timeout,
        )
    }

    /// Whether the Link DATA receipt table cannot admit another packet.
    pub fn link_data_receipt_table_is_full(&self) -> bool {
        self.link_data_receipts.is_full()
    }

    /// Number of tracked ordinary Link DATA receipts.
    pub fn link_data_receipt_count(&self) -> usize {
        self.link_data_receipts.len()
    }

    /// Current status for an outstanding ordinary Link DATA receipt.
    pub fn link_data_receipt_status(
        &self,
        packet_hash: &[u8; 32],
    ) -> Option<ReceiptStatus> {
        self.link_data_receipts.status(packet_hash)
    }

    /// Cancel an outstanding ordinary Link DATA receipt by complete hash.
    pub fn cancel_link_data_receipt(&mut self, packet_hash: &[u8; 32]) -> bool {
        self.link_data_receipts.remove_full(packet_hash)
    }

    // -----------------------------------------------------------------------
    // Proof packet construction
    // -----------------------------------------------------------------------

    /// Build a PROOF packet with the given dest_type and destination_hash.
    ///
    /// Payload: `packet_hash[32] || Ed25519_signature[64]`.
    fn build_proof_inner(
        identity: &Identity,
        packet_hash: &[u8; 32],
        dest_type: DestType,
        destination_hash: &[u8; TRUNCATED_HASH_LEN], // truncated packet hash, NOT DestHash
    ) -> Option<alloc::vec::Vec<u8>> {
        let signature = identity.sign(packet_hash).ok()?;
        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(packet_hash);
        payload[32..96].copy_from_slice(&signature);

        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Proof)
            .dest_type(dest_type)
            .destination_hash(destination_hash)
            .context(0x00)
            .payload(&payload)
            .build()
            .ok()?;
        Some(buf[..n].to_vec())
    }

    /// Build a PROOF packet for a received data packet (non-link proofs).
    ///
    /// Uses `dest_type=Single` and `destination_hash=packet_hash[0:16]`.
    /// For link-related proofs (channel, link data), use [`build_link_proof_packet`] instead.
    pub fn build_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
    ) -> Option<alloc::vec::Vec<u8>> {
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().ok()?;
        Self::build_proof_inner(identity, packet_hash, DestType::Single, &trunc)
    }

    /// Build a PROOF packet for a link-related packet (channel messages, link data).
    ///
    /// Uses `dest_type=Link` and `destination_hash=link_id` so that transport
    /// relays (rnsd) can route the proof back through their link table.
    pub fn build_link_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
        link_id: &LinkId,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link_id_bytes: [u8; TRUNCATED_HASH_LEN] = (*link_id).into();
        Self::build_proof_inner(identity, packet_hash, DestType::Link, &link_id_bytes)
    }
}
