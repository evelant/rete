//! Outbound message queue — handle_outbound, process_outbound, delivery receipts.

use rete_core::{DestHash, LinkId, TRUNCATED_HASH_LEN};
use rete_stack::{NodeCore, OutboundPacket, ReceiptTerminal, SendError};

use crate::LXMessage;
use crate::message::DeliveryMethod;
use crate::propagation::MessageStore;

use super::{LxmfEvent, LxmfRouter};

/// Maximum delivery attempts before marking a message as failed.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;

/// Seconds to wait between delivery retry attempts.
pub const DELIVERY_RETRY_WAIT: u64 = 10;

/// Maximum age (seconds) for stamp cost cache entries before pruning.
pub const STAMP_COST_MAX_AGE: u64 = 30 * 24 * 3600; // 30 days

/// Current state of an outbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutboundState {
    /// Queued, not yet attempted.
    Queued,
    /// Actively being sent (link establishing or resource in flight).
    Sending,
    /// Delivered (proof received). Terminal.
    Delivered,
    /// Failed after max attempts. Terminal.
    Failed,
}

/// Tracking entry for an outbound message.
pub(super) struct OutboundEntry {
    /// The LXMF message being sent.
    pub message: LXMessage,
    /// SHA-256 hash of the packed message (for dedup and receipt tracking).
    pub message_hash: [u8; 32],
    /// Packet hashes for every send attempt still awaiting a terminal receipt.
    ///
    /// The vector is bounded by [`MAX_DELIVERY_ATTEMPTS`]: only successful
    /// packet preparation appends a hash, and no more attempts are prepared
    /// after that budget is exhausted.
    pub receipt_hashes: Vec<[u8; 32]>,
    /// Number of delivery attempts so far.
    pub delivery_attempts: u32,
    /// Monotonic timestamp of next allowed delivery attempt.
    pub next_delivery_attempt: u64,
    /// Current outbound state.
    pub state: OutboundState,
}

/// State machine for outbound direct delivery over a link.
pub(super) enum OutboundDirectJob {
    /// Link is being established to the destination.
    Linking {
        dest_hash: DestHash,
        link_id: LinkId,
        message_hash: [u8; 32],
    },
    /// Link established, resource being sent.
    Sending {
        dest_hash: DestHash,
        link_id: LinkId,
        message_hash: [u8; 32],
    },
}

impl OutboundDirectJob {
    pub fn link_id(&self) -> &LinkId {
        match self {
            Self::Linking { link_id, .. } | Self::Sending { link_id, .. } => link_id,
        }
    }

    pub fn message_hash(&self) -> &[u8; 32] {
        match self {
            Self::Linking { message_hash, .. } | Self::Sending { message_hash, .. } => message_hash,
        }
    }

    pub fn dest_hash(&self) -> &DestHash {
        match self {
            Self::Linking { dest_hash, .. } | Self::Sending { dest_hash, .. } => dest_hash,
        }
    }
}

impl<S: MessageStore> LxmfRouter<S> {
    /// Queue an outbound LXMF message for delivery.
    ///
    /// Returns the message hash (SHA-256 of packed representation) for tracking.
    /// The message will be sent on the next `process_outbound()` call.
    ///
    /// If the destination has a cached stamp cost (from their announce),
    /// a stamp is auto-generated if the message doesn't already have one.
    /// A reply ticket is included in the message fields so the recipient
    /// can reply without performing proof-of-work.
    pub fn handle_outbound<R: rand_core::RngCore>(
        &mut self,
        mut message: LXMessage,
        now: u64,
        rng: &mut R,
    ) -> [u8; 32] {
        // Include a reply ticket so recipient can reply without PoW
        if !message.fields.contains_key(&crate::FIELD_TICKET) {
            let entry = self
                .tickets
                .generate_ticket(message.destination_hash, rng, now);
            // Encode as msgpack [expires, ticket_bytes]
            let mut ticket_field = Vec::new();
            ticket_field.push(0x92); // fixarray(2)
            rete_core::msgpack::write_uint(&mut ticket_field, entry.expires);
            rete_core::msgpack::write_bin(&mut ticket_field, &entry.ticket);
            message.fields.insert(crate::FIELD_TICKET, ticket_field);
        }

        // Auto-assign stamp cost from cache if not already set on message
        if message.stamp.is_none() {
            if let Some(&(_, cost)) = self.outbound_stamp_costs.get(&message.destination_hash) {
                if cost > 0 {
                    if let Some(ticket) = self
                        .tickets
                        .get_outbound_ticket(&message.destination_hash, now)
                    {
                        let mid = message.message_id();
                        message.stamp = Some(crate::stamp::ticket_stamp(&ticket, &mid));
                    } else {
                        message.generate_stamp(cost);
                    }
                }
            }
        }

        // Compute hash after all mutations (ticket field, stamp)
        let message_hash = message.hash();

        // Dedup: don't enqueue the same message twice
        if self
            .pending_outbound
            .iter()
            .any(|e| e.message_hash == message_hash)
        {
            return message_hash;
        }

        self.pending_outbound.push(OutboundEntry {
            message,
            message_hash,
            receipt_hashes: Vec::new(),
            delivery_attempts: 0,
            next_delivery_attempt: now,
            state: OutboundState::Queued,
        });

        message_hash
    }

    /// Process the outbound queue — attempt delivery for pending messages.
    ///
    /// Should be called periodically from the application event loop.
    /// Returns outbound packets to send and events to emit. Callers must
    /// consume both vectors on every call, including when packets are present;
    /// dropping the event vector loses terminal delivery/failure status.
    pub fn process_outbound<R, TS: rete_transport::TransportStorage>(
        &mut self,
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> (Vec<OutboundPacket>, Vec<LxmfEvent>)
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut packets = Vec::new();
        let mut events = Vec::new();

        // Reserve every terminal-event slot before removing any queue entry.
        // If the hosted allocator cannot provide them, leave all terminal
        // entries intact for a later processing pass.
        let terminal_count = self
            .pending_outbound
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    OutboundState::Delivered | OutboundState::Failed
                )
            })
            .count();
        if events.try_reserve_exact(terminal_count).is_err() {
            return (packets, events);
        }

        // Collect indices to process (avoid borrow issues)
        let indices: Vec<usize> = (0..self.pending_outbound.len()).collect();

        for &i in indices.iter().rev() {
            if i >= self.pending_outbound.len() {
                continue;
            }

            let entry = &self.pending_outbound[i];

            // Remove delivered entries
            if entry.state == OutboundState::Delivered {
                let removed = self.pending_outbound.remove(i);
                events.push(LxmfEvent::MessageDelivered {
                    message_hash: removed.message_hash,
                    dest_hash: removed.message.destination_hash,
                });
                continue;
            }

            // Remove failed entries
            if entry.state == OutboundState::Failed {
                let removed = self.pending_outbound.remove(i);
                events.push(LxmfEvent::MessageFailed {
                    message_hash: removed.message_hash,
                    dest_hash: removed.message.destination_hash,
                });
                continue;
            }

            // Skip entries actively sending via direct link
            if entry.state == OutboundState::Sending {
                continue;
            }

            // Skip if not yet time for retry
            if now < entry.next_delivery_attempt {
                continue;
            }

            let entry = &mut self.pending_outbound[i];

            // Check max attempts
            if entry.delivery_attempts >= MAX_DELIVERY_ATTEMPTS {
                // A delayed proof for any in-flight attempt still establishes
                // delivery. Do not fail the LXMF message until every receipt
                // has reached a terminal failure.
                if entry.receipt_hashes.is_empty() {
                    entry.state = OutboundState::Failed;
                }
                continue;
            }

            // Attempt delivery based on method
            match entry.message.method {
                DeliveryMethod::Opportunistic => {
                    let payload = Self::pack_opportunistic(&entry.message);
                    // Reserve both post-commit destinations before preparing
                    // DATA. Once NodeCore registers the receipt, neither push
                    // below is allowed to allocate or fail.
                    if entry.receipt_hashes.try_reserve_exact(1).is_err()
                        || packets.try_reserve_exact(1).is_err()
                    {
                        entry.next_delivery_attempt = now.saturating_add(DELIVERY_RETRY_WAIT);
                        continue;
                    }
                    match core.prepare_data_packet(
                        &entry.message.destination_hash,
                        &payload,
                        rng,
                        now,
                    ) {
                        Ok(prepared) => {
                            debug_assert!(
                                entry.receipt_hashes.len() < MAX_DELIVERY_ATTEMPTS as usize
                            );
                            entry.receipt_hashes.push(*prepared.receipt.packet_hash());
                            packets.push(OutboundPacket::broadcast(prepared.data));
                        }
                        Err(
                            SendError::ReceiptTableFull
                            | SendError::ReceiptHashAlreadyTracked
                            | SendError::OutputAllocationFailed,
                        ) => {
                            // No transmission occurred. Preserve the delivery
                            // attempt budget while backing off for receipt
                            // capacity or truncated-hash ambiguity to clear.
                            entry.next_delivery_attempt = now.saturating_add(DELIVERY_RETRY_WAIT);
                            continue;
                        }
                        Err(_) => {
                            // Identity not cached — can't send yet
                        }
                    }
                    entry.delivery_attempts += 1;
                    entry.next_delivery_attempt = now.saturating_add(DELIVERY_RETRY_WAIT);
                }
                DeliveryMethod::Direct => {
                    // Check if we already have an active direct job for this message
                    let has_job = self
                        .outbound_direct_jobs
                        .iter()
                        .any(|j| *j.message_hash() == entry.message_hash);

                    if !has_job {
                        // Try to establish a link
                        match core.initiate_link(entry.message.destination_hash, now, rng) {
                            Ok((pkt, link_id)) => {
                                self.outbound_direct_jobs.push(OutboundDirectJob::Linking {
                                    dest_hash: entry.message.destination_hash,
                                    link_id,
                                    message_hash: entry.message_hash,
                                });
                                entry.state = OutboundState::Sending;
                                packets.push(pkt);
                            }
                            Err(_) => {
                                // No path — can't initiate link
                            }
                        }
                        entry.delivery_attempts += 1;
                        entry.next_delivery_attempt = now.saturating_add(DELIVERY_RETRY_WAIT);
                    }
                }
                _ => {
                    // Propagation delivery not yet implemented in outbound queue
                    entry.delivery_attempts += 1;
                    entry.next_delivery_attempt = now.saturating_add(DELIVERY_RETRY_WAIT);
                }
            }
        }

        (packets, events)
    }

    /// Advance an outbound direct job when a link is established.
    ///
    /// Returns outbound packets (resource advertisement) if a job matches.
    pub fn advance_outbound_on_link_established<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &LinkId,
        core: &mut NodeCore<TS>,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let mut packets = Vec::new();

        for job in &mut self.outbound_direct_jobs {
            if let OutboundDirectJob::Linking {
                dest_hash,
                link_id: job_link_id,
                message_hash,
            } = job
            {
                if job_link_id == link_id {
                    // Find the matching outbound entry and send it
                    if let Some(entry) = self
                        .pending_outbound
                        .iter()
                        .find(|e| e.message_hash == *message_hash)
                    {
                        let data = Self::pack_direct(&entry.message);
                        if let Ok(pkt) = core.start_resource(link_id, &data, rng) {
                            packets.push(pkt);
                        }
                    }
                    *job = OutboundDirectJob::Sending {
                        dest_hash: *dest_hash,
                        link_id: *link_id,
                        message_hash: *message_hash,
                    };
                }
            }
        }

        packets
    }

    /// Handle resource completion for an outbound direct delivery.
    pub fn advance_outbound_on_resource_complete(&mut self, link_id: &LinkId) {
        // Find and remove matching direct job
        if let Some(idx) = self
            .outbound_direct_jobs
            .iter()
            .position(|j| *j.link_id() == *link_id)
        {
            let job = self.outbound_direct_jobs.remove(idx);
            // Mark the outbound entry as delivered
            if let Some(entry) = self
                .pending_outbound
                .iter_mut()
                .find(|e| e.message_hash == *job.message_hash())
            {
                entry.state = OutboundState::Delivered;
            }
        }
    }

    /// Clean up outbound direct jobs when a link closes.
    pub fn cleanup_outbound_jobs_for_link(&mut self, link_id: &LinkId) {
        // Reset matching outbound entries back to Queued for retry
        let message_hashes: Vec<[u8; 32]> = self
            .outbound_direct_jobs
            .iter()
            .filter(|j| *j.link_id() == *link_id)
            .map(|j| *j.message_hash())
            .collect();

        for mh in &message_hashes {
            if let Some(entry) = self
                .pending_outbound
                .iter_mut()
                .find(|e| e.message_hash == *mh)
            {
                entry.state = OutboundState::Queued;
            }
        }

        self.outbound_direct_jobs
            .retain(|j| *j.link_id() != *link_id);
    }

    /// Prune expired stamp cost cache entries. Returns count removed.
    pub fn prune_stamp_costs(&mut self, now: u64) -> usize {
        let before = self.outbound_stamp_costs.len();
        self.outbound_stamp_costs
            .retain(|_, &mut (ts, _)| now.saturating_sub(ts) < STAMP_COST_MAX_AGE);
        before - self.outbound_stamp_costs.len()
    }

    // -----------------------------------------------------------------------
    // Serialization for persistence
    // -----------------------------------------------------------------------

    /// Export outbound stamp cost cache as msgpack bytes.
    pub fn export_stamp_costs(&self) -> Vec<u8> {
        use rete_core::msgpack;
        let mut buf = Vec::new();
        msgpack::write_array_header(&mut buf, self.outbound_stamp_costs.len());
        for (dh, &(ts, cost)) in &self.outbound_stamp_costs {
            buf.push(0x93); // fixarray(3)
            msgpack::write_bin(&mut buf, dh.as_ref());
            msgpack::write_uint(&mut buf, ts);
            msgpack::write_uint(&mut buf, cost as u64);
        }
        buf
    }

    /// Import outbound stamp cost cache from msgpack bytes.
    pub fn import_stamp_costs(&mut self, data: &[u8]) {
        use rete_core::msgpack;
        let mut pos = 0;
        let count = match msgpack::read_array_len(data, &mut pos) {
            Ok(n) => n,
            Err(_) => return,
        };
        for _ in 0..count {
            if let Ok(arr_len) = msgpack::read_array_len(data, &mut pos) {
                if arr_len >= 3 {
                    if let Ok(dh_bytes) = msgpack::read_bin_or_str(data, &mut pos) {
                        if let Ok(ts) = msgpack::read_uint(data, &mut pos) {
                            if let Ok(cost) = msgpack::read_uint(data, &mut pos) {
                                if dh_bytes.len() >= TRUNCATED_HASH_LEN {
                                    self.outbound_stamp_costs.insert(
                                        DestHash::from_slice(&dh_bytes[..TRUNCATED_HASH_LEN]),
                                        (ts, cost as u8),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Export ticket cache for persistence.
    pub fn export_tickets(&self) -> Vec<u8> {
        self.tickets.export()
    }

    /// Import ticket cache from persistence.
    pub fn import_tickets(&mut self, data: &[u8]) {
        self.tickets.import(data);
    }

    /// Export outbound queue for persistence.
    ///
    /// Returns a list of packed LXMF messages (only non-terminal entries).
    pub fn export_outbound_queue(&self) -> Vec<Vec<u8>> {
        self.pending_outbound
            .iter()
            .filter(|e| e.state != OutboundState::Delivered && e.state != OutboundState::Failed)
            .map(|e| e.message.pack())
            .collect()
    }

    /// Import outbound queue from persistence.
    ///
    /// Each entry is a packed LXMF message. Re-enqueues them with Queued state.
    pub fn import_outbound_queue(&mut self, entries: &[Vec<u8>], now: u64) {
        for packed in entries {
            if let Ok(msg) = LXMessage::unpack(packed, None) {
                let message_hash = msg.hash();
                // Skip if already in queue
                if self
                    .pending_outbound
                    .iter()
                    .any(|e| e.message_hash == message_hash)
                {
                    continue;
                }
                self.pending_outbound.push(OutboundEntry {
                    message: msg,
                    message_hash,
                    receipt_hashes: Vec::new(),
                    delivery_attempts: 0,
                    next_delivery_attempt: now,
                    state: OutboundState::Queued,
                });
            }
        }
    }

    /// Check if a ProofReceived event corresponds to any send attempt.
    ///
    /// A proof for any outstanding attempt delivers the message. The queue
    /// entry is removed atomically with producing the delivery event so a
    /// later outbound-processing pass cannot emit the event a second time.
    pub(super) fn check_delivery_receipt_with(
        &mut self,
        packet_hash: &[u8; 32],
        mut cancel_sibling: impl FnMut(&[u8; 32]),
    ) -> Option<LxmfEvent> {
        let index = self
            .pending_outbound
            .iter()
            .position(|entry| entry.receipt_hashes.contains(packet_hash))?;
        let entry = self.pending_outbound.remove(index);
        for sibling_hash in &entry.receipt_hashes {
            if sibling_hash != packet_hash {
                cancel_sibling(sibling_hash);
            }
        }
        Some(LxmfEvent::MessageDelivered {
            message_hash: entry.message_hash,
            dest_hash: entry.message.destination_hash,
        })
    }

    /// Check if a ProofReceived event corresponds to any send attempt.
    ///
    /// This compatibility method does not have access to transport state, so
    /// sibling attempt receipts remain until timeout. New stateful callers
    /// should use [`Self::handle_receipt_terminal`] or
    /// [`Self::handle_event_mut_with_core`].
    pub fn check_delivery_receipt(&mut self, packet_hash: &[u8; 32]) -> Option<LxmfEvent> {
        self.check_delivery_receipt_with(packet_hash, |_| {})
    }

    fn check_delivery_receipt_with_core<TS: rete_transport::TransportStorage>(
        &mut self,
        packet_hash: &[u8; 32],
        core: &mut NodeCore<TS>,
    ) -> Option<LxmfEvent> {
        self.check_delivery_receipt_with(packet_hash, |sibling_hash| {
            core.transport.cancel_receipt(sibling_hash);
        })
    }

    pub(super) fn handle_delivery_failure_terminal(
        &mut self,
        packet_hash: &[u8; 32],
    ) -> Option<LxmfEvent> {
        let index = self
            .pending_outbound
            .iter()
            .position(|entry| entry.receipt_hashes.contains(packet_hash))?;
        let entry = &mut self.pending_outbound[index];
        entry.receipt_hashes.retain(|hash| hash != packet_hash);
        if entry.delivery_attempts < MAX_DELIVERY_ATTEMPTS || !entry.receipt_hashes.is_empty() {
            return None;
        }
        let entry = self.pending_outbound.remove(index);
        Some(LxmfEvent::MessageFailed {
            message_hash: entry.message_hash,
            dest_hash: entry.message.destination_hash,
        })
    }

    /// Correlate an allocation-safe stack receipt terminal with the outbound
    /// LXMF queue.
    ///
    /// A delivered attempt immediately removes its message and cancels sibling
    /// transport receipts. A failed attempt is retired; failure of the final
    /// outstanding attempt after the retry budget is exhausted immediately
    /// returns [`LxmfEvent::MessageFailed`]. The returned event contains only
    /// fixed-size fields and requires no intermediate event vector.
    pub fn handle_receipt_terminal<TS: rete_transport::TransportStorage>(
        &mut self,
        terminal: ReceiptTerminal,
        core: &mut NodeCore<TS>,
    ) -> Option<LxmfEvent> {
        match terminal {
            ReceiptTerminal::Delivered(packet_hash) => {
                self.check_delivery_receipt_with_core(&packet_hash, core)
            }
            ReceiptTerminal::Failed(packet_hash) => {
                self.handle_delivery_failure_terminal(&packet_hash)
            }
        }
    }

    /// Record terminal failure for one DATA send attempt.
    ///
    /// Returns `true` when the hash belonged to an outbound LXMF message. Once
    /// the attempt budget is exhausted, failure of the final outstanding
    /// receipt makes the message eligible for normal failed-entry emission.
    pub fn check_delivery_failure(&mut self, packet_hash: &[u8; 32]) -> bool {
        let Some(entry) = self
            .pending_outbound
            .iter_mut()
            .find(|entry| entry.receipt_hashes.contains(packet_hash))
        else {
            return false;
        };

        entry.receipt_hashes.retain(|hash| hash != packet_hash);
        if entry.delivery_attempts >= MAX_DELIVERY_ATTEMPTS && entry.receipt_hashes.is_empty() {
            entry.state = OutboundState::Failed;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LxmfRouter;
    use crate::propagation::InMemoryMessageStore;
    use crate::router::codec::parse_lxmf_announce_data;
    use rete_core::DestHash;
    use rete_core::Identity;
    use std::collections::BTreeMap;

    type TestNodeCore = NodeCore<rete_transport::HeaplessStorage<64, 16, 128, 4>>;
    type SmallReceiptNodeCore = NodeCore<rete_transport::HeaplessStorage<4, 16, 128, 4>>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let id = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(id, "testapp", &["aspect1"]).unwrap()
    }

    fn make_small_receipt_core(seed: &[u8]) -> SmallReceiptNodeCore {
        let id = Identity::from_seed(seed).unwrap();
        SmallReceiptNodeCore::new(id, "testapp", &["aspect1"]).unwrap()
    }

    fn make_test_msg_at(dest_hash: DestHash, timestamp: f64) -> LXMessage {
        let source = Identity::from_seed(b"outbound-test-source").unwrap();
        LXMessage::new(
            dest_hash,
            DestHash::from_slice(source.hash().as_ref()),
            &source,
            b"Test",
            b"Hello",
            BTreeMap::new(),
            timestamp,
        )
        .unwrap()
    }

    fn make_test_msg(dest_hash: DestHash) -> LXMessage {
        make_test_msg_at(dest_hash, 1700000000.0)
    }

    struct FixedRng;

    impl rand_core::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for FixedRng {}

    #[test]
    fn test_handle_outbound_enqueues() {
        let mut core = make_core(b"outbound-enqueue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0xAA; 16]));

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(hash.len(), 32);
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].message_hash, hash);
        assert_eq!(router.pending_outbound[0].state, OutboundState::Queued);
    }

    #[test]
    fn test_handle_outbound_returns_message_hash() {
        let mut core = make_core(b"outbound-hash");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0xBB; 16]));

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(hash.len(), 32);
        // Hash should match the packed message (which now includes ticket field)
        let actual_hash = router.pending_outbound[0].message.hash();
        assert_eq!(hash, actual_hash);
    }

    #[test]
    fn test_handle_outbound_dedup() {
        let mut core = make_core(b"outbound-dedup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg1 = make_test_msg(DestHash::from([0xCC; 16]));

        let h1 = router.handle_outbound(msg1, 1000, &mut rand::thread_rng());
        // Try to enqueue a message with the same hash (already in queue)
        // The ticket is random, so a new message won't dedup unless it's truly the same.
        // Instead, test dedup by trying to re-enqueue with the same hash manually.
        let msg2 = router.pending_outbound[0].message.pack();
        let msg2 = LXMessage::unpack(&msg2, None).unwrap();
        let h2 = router.handle_outbound(msg2, 1000, &mut rand::thread_rng());
        // The second enqueue finds the same hash already in queue → dedup
        assert_eq!(h1, h2);
        assert_eq!(router.pending_outbound.len(), 1);
    }

    #[test]
    fn test_handle_outbound_auto_assigns_stamp_cost() {
        let mut core = make_core(b"outbound-stamp");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let dest_hash = DestHash::from([0xDD; 16]);
        router.outbound_stamp_costs.insert(dest_hash, (1000, 1)); // cost=1

        let msg = make_test_msg(dest_hash);
        assert!(msg.stamp.is_none());

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        // Stamp should have been generated
        assert!(router.pending_outbound[0].message.stamp.is_some());
    }

    #[test]
    fn test_handle_outbound_uses_ticket_when_available() {
        let mut core = make_core(b"outbound-ticket");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let dest_hash = DestHash::from([0xEE; 16]);
        router.outbound_stamp_costs.insert(dest_hash, (1000, 8)); // cost=8
        router.tickets.store_outbound(dest_hash, [0x42, 0x37], 5000);

        let msg = make_test_msg(dest_hash);
        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        // Should have a ticket-based stamp, not a PoW stamp
        let stamp = router.pending_outbound[0].message.stamp.unwrap();
        // Verify it's a ticket stamp (derived from ticket + message_id)
        let mid = router.pending_outbound[0].message.message_id();
        let expected = crate::stamp::ticket_stamp(&[0x42, 0x37], &mid);
        assert_eq!(stamp, expected);
    }

    #[test]
    fn test_process_outbound_skips_before_retry_time() {
        let mut core = make_core(b"outbound-skip");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0xFF; 16]));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        // Set next attempt in the future
        router.pending_outbound[0].next_delivery_attempt = 2000;
        router.pending_outbound[0].delivery_attempts = 1;

        let mut rng = rand::thread_rng();
        let (pkts, evts) = router.process_outbound(&mut core, &mut rng, 1500);
        assert!(pkts.is_empty());
        assert!(evts.is_empty());
        // Attempts unchanged
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
    }

    #[test]
    fn test_process_outbound_increments_attempts() {
        let mut core = make_core(b"outbound-attempts");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x11; 16]));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(router.pending_outbound[0].delivery_attempts, 0);

        let mut rng = rand::thread_rng();
        let _ = router.process_outbound(&mut core, &mut rng, 1000);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
    }

    #[test]
    fn receipt_backpressure_does_not_consume_lxmf_delivery_attempt() {
        let mut core = make_small_receipt_core(b"outbound-receipt-pressure");
        let peer_seed = b"outbound-receipt-pressure-peer";
        let peer = make_small_receipt_core(peer_seed);
        let peer_identity = Identity::from_seed(peer_seed).unwrap();
        core.register_peer(&peer_identity, "testapp", &["aspect1"], 1000)
            .unwrap();

        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let mut rng = rand::thread_rng();
        for index in 0..5 {
            router.handle_outbound(
                make_test_msg_at(*peer.dest_hash(), 1700000000.0 + index as f64),
                1000,
                &mut rng,
            );
        }
        assert_eq!(router.pending_outbound.len(), 5);

        let (packets, events) = router.process_outbound(&mut core, &mut rng, 1000);

        assert_eq!(packets.len(), 4);
        assert!(events.is_empty());
        assert_eq!(core.transport.receipt_count(), 4);
        assert_eq!(
            router
                .pending_outbound
                .iter()
                .filter(|entry| entry.delivery_attempts == 1)
                .count(),
            4
        );
        let blocked = router
            .pending_outbound
            .iter()
            .find(|entry| entry.delivery_attempts == 0)
            .expect("one message must remain blocked by receipt capacity");
        assert!(blocked.receipt_hashes.is_empty());
        assert_eq!(blocked.next_delivery_attempt, 1000 + DELIVERY_RETRY_WAIT);

        let attempts_before: Vec<u32> = router
            .pending_outbound
            .iter()
            .map(|entry| entry.delivery_attempts)
            .collect();
        let (packets, events) = router.process_outbound(&mut core, &mut rng, 1010);
        assert!(packets.is_empty());
        assert!(events.is_empty());
        assert_eq!(
            router
                .pending_outbound
                .iter()
                .map(|entry| entry.delivery_attempts)
                .collect::<Vec<_>>(),
            attempts_before
        );
    }

    #[test]
    fn receipt_hash_collision_backpressure_preserves_attempt_budget() {
        let mut core = make_core(b"outbound-receipt-collision");
        let peer_seed = b"outbound-receipt-collision-peer";
        let peer = make_core(peer_seed);
        let peer_identity = Identity::from_seed(peer_seed).unwrap();
        core.register_peer(&peer_identity, "testapp", &["aspect1"], 1000)
            .unwrap();

        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router.handle_outbound(
            make_test_msg(*peer.dest_hash()),
            1000,
            &mut rand::thread_rng(),
        );
        let mut rng = FixedRng;

        let (first_packets, first_events) = router.process_outbound(&mut core, &mut rng, 1000);
        assert_eq!(first_packets.len(), 1);
        assert!(first_events.is_empty());
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
        let first_hashes = router.pending_outbound[0].receipt_hashes.clone();
        assert_eq!(first_hashes.len(), 1);

        let (retry_packets, retry_events) = router.process_outbound(&mut core, &mut rng, 1010);
        assert!(retry_packets.is_empty());
        assert!(retry_events.is_empty());
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
        assert_eq!(router.pending_outbound[0].receipt_hashes, first_hashes);
        assert_eq!(
            router.pending_outbound[0].next_delivery_attempt,
            1010 + DELIVERY_RETRY_WAIT
        );
    }

    #[test]
    fn delayed_proof_for_any_attempt_delivers_once() {
        let mut core = make_core(b"outbound-delayed-proof");
        let peer_seed = b"outbound-delayed-proof-peer";
        let peer = make_core(peer_seed);
        let peer_identity = Identity::from_seed(peer_seed).unwrap();
        core.register_peer(&peer_identity, "testapp", &["aspect1"], 1000)
            .unwrap();

        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router.handle_outbound(
            make_test_msg(*peer.dest_hash()),
            1000,
            &mut rand::thread_rng(),
        );
        let mut rng = rand::thread_rng();

        for attempt in 0..4 {
            let now = 1000 + attempt as u64 * DELIVERY_RETRY_WAIT;
            let (packets, events) = router.process_outbound(&mut core, &mut rng, now);
            assert_eq!(packets.len(), 1);
            assert!(events.is_empty());
        }

        let hashes = router.pending_outbound[0].receipt_hashes.clone();
        assert_eq!(hashes.len(), 4);

        // A real tick expires only the first attempt; the third remains live.
        let mut terminals = rete_stack::FixedReceiptTerminalSink::<4>::new();
        let tick = core.handle_tick_with_receipt_sink(1031, &mut rng, &mut terminals);
        assert_eq!(tick.failed_receipts, 1);
        assert!(!tick.receipt_notifications_deferred);
        let failed = terminals.pop().unwrap();
        assert_eq!(failed, ReceiptTerminal::Failed(hashes[0]));
        assert!(router
            .handle_receipt_terminal(failed, &mut core)
            .is_none());
        assert!(
            !router.pending_outbound[0]
                .receipt_hashes
                .contains(&hashes[0])
        );

        // A delayed proof for the still-live third attempt is delivered through
        // the allocation-safe sink and cancels every sibling receipt.
        let proof = rete_transport::Transport::<
            rete_transport::HeaplessStorage<64, 16, 128, 4>,
        >::build_proof_packet(&peer_identity, &hashes[2])
        .unwrap();
        let proof_outcome = core
            .handle_ingest_with_receipt_sink(&proof, 1032, 0, &mut rng, &mut terminals)
            .unwrap();
        assert!(proof_outcome.events.is_empty());
        let delivered = router
            .handle_receipt_terminal(terminals.pop().unwrap(), &mut core)
            .unwrap();
        assert!(matches!(delivered, LxmfEvent::MessageDelivered { .. }));
        assert!(router.pending_outbound.is_empty());
        assert_eq!(core.transport.receipt_count(), 0);

        // The proof path removed the entry atomically; processing cannot emit
        // a duplicate MessageDelivered event.
        let (packets, events) = router.process_outbound(&mut core, &mut rng, 1032);
        assert!(packets.is_empty());
        assert!(events.is_empty());
    }

    #[test]
    fn opportunistic_retry_deadline_saturates_after_committed_send() {
        let mut core = make_core(b"outbound-max-time");
        let peer_seed = b"outbound-max-time-peer";
        let peer = make_core(peer_seed);
        let peer_identity = Identity::from_seed(peer_seed).unwrap();
        core.register_peer(&peer_identity, "testapp", &["aspect1"], u64::MAX)
            .unwrap();
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router.handle_outbound(
            make_test_msg(*peer.dest_hash()),
            u64::MAX,
            &mut rand::thread_rng(),
        );
        let mut rng = rand::thread_rng();

        let (packets, events) = router.process_outbound(&mut core, &mut rng, u64::MAX);
        assert_eq!(packets.len(), 1);
        assert!(events.is_empty());
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
        assert_eq!(router.pending_outbound[0].next_delivery_attempt, u64::MAX);
        assert_eq!(core.transport.receipt_count(), 1);
    }

    #[test]
    fn final_failed_receipt_marks_maxed_message_failed_once() {
        let mut core = make_core(b"outbound-all-receipts-failed");
        let peer_seed = b"outbound-all-receipts-failed-peer";
        let peer = make_core(peer_seed);
        let peer_identity = Identity::from_seed(peer_seed).unwrap();
        core.register_peer(&peer_identity, "testapp", &["aspect1"], 1000)
            .unwrap();

        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router.handle_outbound(
            make_test_msg(*peer.dest_hash()),
            1000,
            &mut rand::thread_rng(),
        );
        let mut rng = rand::thread_rng();

        for attempt in 0..MAX_DELIVERY_ATTEMPTS {
            let now = 1000 + attempt as u64 * DELIVERY_RETRY_WAIT;
            let (packets, events) = router.process_outbound(&mut core, &mut rng, now);
            assert_eq!(packets.len(), 1);
            assert!(events.is_empty());
        }

        let hashes = router.pending_outbound[0].receipt_hashes.clone();
        assert_eq!(hashes.len(), MAX_DELIVERY_ATTEMPTS as usize);

        for hash in &hashes[..hashes.len() - 1] {
            assert!(router.check_delivery_failure(hash));
            assert_eq!(router.pending_outbound[0].state, OutboundState::Queued);
        }

        let failure = router.handle_event_mut(
            rete_stack::NodeEvent::ReceiptFailed {
                packet_hash: *hashes.last().unwrap(),
            },
            1050,
        );
        assert!(matches!(failure, LxmfEvent::MessageFailed { .. }));
        assert!(router.pending_outbound.is_empty());

        let (packets, events) = router.process_outbound(&mut core, &mut rng, 1050);
        assert!(packets.is_empty());
        assert!(events.is_empty());
    }

    #[test]
    fn test_process_outbound_fails_after_max_attempts() {
        let mut core = make_core(b"outbound-maxfail");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x22; 16]));

        router.handle_outbound(msg, 0, &mut rand::thread_rng());
        router.pending_outbound[0].delivery_attempts = MAX_DELIVERY_ATTEMPTS;

        let mut rng = rand::thread_rng();
        let _ = router.process_outbound(&mut core, &mut rng, 100);
        // Entry should be marked failed
        assert_eq!(router.pending_outbound[0].state, OutboundState::Failed);
        // Next process call should emit MessageFailed and remove
        let (_, evts) = router.process_outbound(&mut core, &mut rng, 100);
        assert_eq!(evts.len(), 1);
        assert!(matches!(evts[0], LxmfEvent::MessageFailed { .. }));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_check_delivery_receipt_matches() {
        let mut core = make_core(b"receipt-match");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x33; 16]));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let pkt_hash = [0x99; 32];
        router.pending_outbound[0].receipt_hashes.push(pkt_hash);

        let event = router.check_delivery_receipt(&pkt_hash);
        assert!(event.is_some());
        assert!(matches!(event.unwrap(), LxmfEvent::MessageDelivered { .. }));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_check_delivery_receipt_unknown_hash() {
        let mut core = make_core(b"receipt-unknown");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x44; 16]));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let event = router.check_delivery_receipt(&[0xFF; 32]);
        assert!(event.is_none());
    }

    #[test]
    fn test_delivered_entry_removed_on_next_process() {
        let mut core = make_core(b"receipt-cleanup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x55; 16]));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        router.pending_outbound[0].state = OutboundState::Delivered;

        let mut rng = rand::thread_rng();
        let (_, evts) = router.process_outbound(&mut core, &mut rng, 2000);
        assert_eq!(evts.len(), 1);
        assert!(matches!(evts[0], LxmfEvent::MessageDelivered { .. }));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_cleanup_outbound_jobs_for_link() {
        let mut core = make_core(b"outbound-cleanup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x66; 16]));

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let link_id = LinkId::from([0x77; 16]);

        router
            .outbound_direct_jobs
            .push(OutboundDirectJob::Linking {
                dest_hash: DestHash::from([0x66; 16]),
                link_id,
                message_hash: hash,
            });
        router.pending_outbound[0].state = OutboundState::Sending;

        router.cleanup_outbound_jobs_for_link(&link_id);
        assert!(router.outbound_direct_jobs.is_empty());
        assert_eq!(router.pending_outbound[0].state, OutboundState::Queued);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_DELIVERY_ATTEMPTS, 5);
        assert_eq!(DELIVERY_RETRY_WAIT, 10);
    }

    #[test]
    fn test_outbound_message_includes_ticket() {
        let mut core = make_core(b"outbound-ticket-issue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg(DestHash::from([0x77; 16]));
        assert!(!msg.fields.contains_key(&crate::FIELD_TICKET));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        // Message should now have a ticket field
        assert!(
            router.pending_outbound[0]
                .message
                .fields
                .contains_key(&crate::FIELD_TICKET)
        );

        // Ticket should be stored in inbound cache for validation
        let tickets = router
            .tickets
            .get_inbound_tickets(&DestHash::from([0x77; 16]), 1000);
        assert_eq!(tickets.len(), 1);
    }

    #[test]
    fn test_export_import_stamp_costs_roundtrip() {
        let mut core = make_core(b"export-stamp-costs");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        router
            .outbound_stamp_costs
            .insert(DestHash::from([0x11; 16]), (1000, 4));
        router
            .outbound_stamp_costs
            .insert(DestHash::from([0x22; 16]), (2000, 8));

        let exported = router.export_stamp_costs();

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_stamp_costs(&exported);

        assert_eq!(
            router2.get_outbound_stamp_cost(&DestHash::from([0x11; 16])),
            Some(4)
        );
        assert_eq!(
            router2.get_outbound_stamp_cost(&DestHash::from([0x22; 16])),
            Some(8)
        );
    }

    #[test]
    fn test_export_import_tickets_roundtrip() {
        let mut core = make_core(b"export-tickets");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        router
            .tickets
            .store_inbound(DestHash::from([0xAA; 16]), [0x12, 0x34], 5000);
        router
            .tickets
            .store_outbound(DestHash::from([0xBB; 16]), [0x56, 0x78], 6000);

        let exported = router.export_tickets();

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_tickets(&exported);

        assert_eq!(
            router2
                .tickets
                .get_inbound_tickets(&DestHash::from([0xAA; 16]), 1000),
            vec![[0x12, 0x34]]
        );
        assert_eq!(
            router2
                .tickets
                .get_outbound_ticket(&DestHash::from([0xBB; 16]), 1000),
            Some([0x56, 0x78])
        );
    }

    #[test]
    fn test_export_import_outbound_queue_roundtrip() {
        let mut core = make_core(b"export-queue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let msg = make_test_msg(DestHash::from([0xCC; 16]));
        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        let exported = router.export_outbound_queue();
        assert_eq!(exported.len(), 1);

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_outbound_queue(&exported, 2000);
        assert_eq!(router2.pending_outbound.len(), 1);
        assert_eq!(
            router2.pending_outbound[0].message.destination_hash,
            DestHash::from([0xCC; 16])
        );
    }

    #[test]
    fn test_announce_includes_stamp_cost() {
        let mut core = make_core(b"announce-stamp");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        // Default: no cost
        let data = router.build_announce_app_data();
        let parsed = parse_lxmf_announce_data(&data).unwrap();
        assert_eq!(parsed.stamp_cost, None); // 0 = no cost

        // Set cost
        router.set_inbound_stamp_cost(Some(8));
        let data = router.build_announce_app_data();
        let parsed = parse_lxmf_announce_data(&data).unwrap();
        assert_eq!(parsed.stamp_cost, Some(8));
    }
}
