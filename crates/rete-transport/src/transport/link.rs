//! Link lifecycle, handshake, keepalives, close.

use crate::channel::{ChannelMaintenance, PreparedChannelRetry};
use crate::link::{compute_link_id, Link, LinkRole, LinkState, LINK_MDU};
use crate::storage::StorageMap;
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestHash, DestType, Identity, LinkId, MonotonicInstant, PacketBuilder, PacketType, CONTEXT_CHANNEL,
    CONTEXT_KEEPALIVE, CONTEXT_LINKCLOSE, CONTEXT_LRPROOF, CONTEXT_LRRTT, CONTEXT_NONE,
    CONTEXT_REQUEST, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU,
    CONTEXT_RESOURCE_ICL, CONTEXT_RESOURCE_PRF, CONTEXT_RESOURCE_RCL, CONTEXT_RESOURCE_REQ,
    CONTEXT_RESPONSE, Packet, TRUNCATED_HASH_LEN,
};

use super::{
    ChannelReceipt, IngestResult, LinkTableKind, SendError, Transport, PATHFINDER_M,
};

enum OwnedLinkAdmission {
    Inserted,
    Existing,
    Full,
}

pub(super) struct LinkRequestIngress {
    pub(super) now: MonotonicInstant,
    pub(super) hops: u8,
    pub(super) interface: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkSessionFingerprint {
    local_ephemeral: [u8; 32],
    peer_ephemeral: [u8; 32],
}

impl LinkSessionFingerprint {
    fn of(link: &Link) -> Self {
        Self {
            local_ephemeral: link.our_x25519_pub,
            peer_ephemeral: link.peer_x25519_pub,
        }
    }
}

/// One immutable channel retry discovered by periodic maintenance.
///
/// The token is intentionally non-cloneable and can only be committed by
/// [`Transport::retry_channel_message`].
#[derive(Debug)]
pub struct PendingChannelRetry {
    link_id: LinkId,
    link_session: LinkSessionFingerprint,
    retry: PreparedChannelRetry,
}

impl PendingChannelRetry {
    /// Link whose channel owns this retry.
    pub fn link_id(&self) -> &LinkId {
        &self.link_id
    }
}

/// Immutable terminal channel maintenance discovered for one Link.
#[derive(Debug)]
pub struct PendingChannelTeardown {
    link_id: LinkId,
    link_session: LinkSessionFingerprint,
    discovered_at: u64,
}

impl PendingChannelTeardown {
    /// Link whose channel exhausted its retry budget.
    pub fn link_id(&self) -> &LinkId {
        &self.link_id
    }
}

/// Read-only channel work returned by periodic maintenance discovery.
#[derive(Debug)]
pub enum ChannelMaintenanceAction {
    /// Build a fresh encrypted packet and replace the previous proof receipt.
    Retransmit(PendingChannelRetry),
    /// Remove a Link whose channel exhausted its retry budget.
    Teardown(PendingChannelTeardown),
}

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Look up an active link by link_id.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Look up an active link mutably by link_id.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Runtime interface bound to a locally owned Link, if routing has
    /// established one.
    pub fn link_interface(&self, link_id: &LinkId) -> Option<u8> {
        self.links.get(link_id).and_then(Link::bound_interface)
    }

    /// Correlate a bounded Link with an opaque runtime dispatch token.
    pub fn assign_link_protocol_token(
        &mut self,
        link_id: &LinkId,
        role: LinkRole,
        token: core::num::NonZeroU64,
    ) -> bool {
        if self
            .links
            .iter()
            .any(|(_, link)| link.outbound_protocol_token() == Some(token))
        {
            return false;
        }
        self.links.get_mut(link_id).is_some_and(|link| {
            link.role == role && link.assign_outbound_protocol_token(token)
        })
    }

    /// Confirm one Link request timestamp from a completed interface dispatch.
    ///
    /// Initiators select `started_at`; responders select `completed_at`, matching
    /// Python's pre-LINKREQUEST and post-LRPROOF timing edges. Responders also
    /// require the interface retained from LINKREQUEST ingress.
    pub fn confirm_link_protocol_dispatch(
        &mut self,
        token: core::num::NonZeroU64,
        interface: u8,
        started_at: MonotonicInstant,
        completed_at: MonotonicInstant,
    ) -> bool {
        if started_at > completed_at {
            return false;
        }
        self.links.iter_mut().any(|(_, link)| {
            if link.outbound_protocol_token() != Some(token) {
                return false;
            }
            let selected = if link.role == LinkRole::Initiator {
                started_at
            } else {
                completed_at
            };
            link.confirm_request_started_at(token, interface, selected)
        })
    }

    /// Number of tracked channel receipts (pending channel ACKs).
    pub fn channel_receipt_count(&self) -> usize {
        self.channel_receipts.len()
    }

    /// Remove a locally owned Link and its internal channel proof receipts.
    ///
    /// Application-visible ordinary Link DATA receipts remain until receipt
    /// maintenance can reserve and commit their deterministic failure events.
    fn remove_owned_link(&mut self, link_id: &LinkId) -> Option<Link> {
        let removed = self.links.remove(link_id);
        if removed.is_some() {
            self.channel_receipts
                .retain(|_, receipt| receipt.link_id != *link_id);
        }
        removed
    }

    /// Discard a locally owned Link that has not reached an established state.
    ///
    /// NodeCore uses this to roll back responder admission when its unique
    /// outbound LRPROOF timing-token namespace is exhausted.
    pub fn discard_unestablished_link(&mut self, link_id: &LinkId) -> bool {
        let removable = self.links.get(link_id).is_some_and(|link| {
            !matches!(link.state, LinkState::Active | LinkState::Stale)
        });
        removable && self.remove_owned_link(link_id).is_some()
    }

    // -----------------------------------------------------------------------
    // Link management
    // -----------------------------------------------------------------------

    fn admit_owned_link(&mut self, link_id: LinkId, link: Link) -> OwnedLinkAdmission {
        if self.links.contains_key(&link_id) {
            return OwnedLinkAdmission::Existing;
        }

        match self.links.insert(link_id, link) {
            Ok(None) => OwnedLinkAdmission::Inserted,
            Ok(Some(previous)) => {
                // A conforming StorageMap cannot reach this branch after the
                // contains check above. Restore the previous value defensively
                // so an unusual backend cannot reset an existing Link.
                let restored = self.links.insert(link_id, previous);
                debug_assert!(matches!(restored, Ok(Some(_))));
                OwnedLinkAdmission::Existing
            }
            Err(_) => OwnedLinkAdmission::Full,
        }
    }

    /// Initiate a link to a destination.
    ///
    /// Returns the raw LINKREQUEST packet and the link_id only after the
    /// corresponding Link state has been retained. A generated ID collision
    /// returns [`SendError::LinkAlreadyExists`]; bounded storage exhaustion
    /// returns [`SendError::LinkTableFull`] without releasing the request. The
    /// pending Link snapshots the current path height for LRPROOF admission;
    /// an unknown path uses [`PATHFINDER_M`] as the compatibility wildcard.
    pub fn initiate_link<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: DestHash,
        identity: &Identity,
        rng: &mut R,
        now: u64,
    ) -> Result<(alloc::vec::Vec<u8>, LinkId), SendError> {
        self.initiate_link_at(
            dest_hash,
            identity,
            rng,
            now,
            MonotonicInstant::from_secs(now),
        )
    }

    /// Initiate a Link with an explicit high-resolution monotonic clock.
    pub fn initiate_link_at<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: DestHash,
        identity: &Identity,
        rng: &mut R,
        now: u64,
        link_now: MonotonicInstant,
    ) -> Result<(alloc::vec::Vec<u8>, LinkId), SendError> {
        // Python Link snapshots hops_to(destination) at construction. Retain
        // that value atomically with the pending Link so later path changes do
        // not alter which LRPROOF height can establish this handshake.
        let expected_hops = self
            .paths
            .get(&dest_hash)
            .map(|path| path.hops)
            .unwrap_or(PATHFINDER_M);
        let (mut link, request_payload) = Link::new_initiator_with_expected_hops_at(
            dest_hash,
            identity.ed25519_pub(),
            expected_hops,
            rng,
            link_now,
        );

        // Build LINKREQUEST packet.
        // dest_type must be Single (matching the target destination type), not Link.
        // Python RNS uses `self.destination.type` for LINKREQUEST flags (Packet.py:172),
        // and the receiving node checks `destination.type == packet.destination_type`.
        //
        // If we have a transport path (via relay), build HEADER_2 so the relay
        // creates a link_table entry and can route the LRPROOF back.
        let via = self.paths.get(&dest_hash).and_then(|p| p.via);
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&request_payload)
            .via(via.as_ref().map(|v| v.as_bytes()))
            .build()
            .map_err(SendError::PacketBuild)?;

        // Compute link_id from the HEADER_1 form of the packet (strip transport
        // header if present). Python computes link_id from the hashable part which
        // masks header_type/transport bits, but uses get_hashable_part() which for
        // HEADER_2 starts at raw[18:] (skipping transport_id). Our compute_link_id
        // handles both HEADER_1 and HEADER_2.
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).map_err(SendError::PacketBuild)?;
        link.set_link_id(link_id);

        match self.admit_owned_link(link_id, link) {
            OwnedLinkAdmission::Inserted => {}
            OwnedLinkAdmission::Existing => return Err(SendError::LinkAlreadyExists),
            OwnedLinkAdmission::Full => return Err(SendError::LinkTableFull),
        }
        self.touch_path(&dest_hash, now);
        Ok((pkt_buf[..pkt_len].to_vec(), link_id))
    }

    /// Build an encrypted DATA packet for a link.
    pub fn build_link_data_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        Self::build_link_packet(link, link_id, plaintext, context, rng)
    }

    /// Prepare ordinary context-NONE Link DATA into caller-owned storage and
    /// transactionally register its explicit delivery-proof receipt.
    ///
    /// Output size, Link state and binding, negotiated MDU, and bounded receipt
    /// capacity are all checked before encryption consumes entropy. On success,
    /// the returned complete packet hash identifies the registered receipt.
    /// A registration collision can only be known after encryption; it leaves
    /// all transport tables unchanged and the caller must discard the output.
    pub fn prepare_link_data_packet_into<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        plaintext: &[u8],
        rng: &mut R,
        now: u64,
        timeout: u64,
        output: &mut [u8],
    ) -> Result<(usize, [u8; 32]), SendError> {
        if output.len() < rete_core::MTU {
            return Err(SendError::PacketBuild(
                rete_core::Error::BufferTooSmall,
            ));
        }
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        if link.bound_interface().is_none() {
            return Err(SendError::LinkInterfaceUnknown);
        }
        if plaintext.len() > link.mdu() {
            return Err(SendError::PacketBuild(
                rete_core::Error::PayloadTooLarge,
            ));
        }
        if self.link_data_receipts.is_full() {
            return Err(SendError::ReceiptTableFull);
        }
        let peer_ed25519_pub = link.peer_ed25519_pub;
        let packet_len = Self::build_link_packet_into(
            link,
            link_id,
            plaintext,
            CONTEXT_NONE,
            rng,
            output,
        )?;
        let packet_hash = Packet::parse(&output[..packet_len])
            .map_err(SendError::PacketBuild)?
            .compute_hash();
        self.register_link_data_receipt(
            packet_hash,
            *link_id,
            peer_ed25519_pub,
            now,
            timeout,
        )
        .map_err(|error| match error {
            crate::receipt::ReceiptRegistrationError::TableFull => {
                SendError::ReceiptTableFull
            }
            crate::receipt::ReceiptRegistrationError::HashAlreadyTracked => {
                SendError::ReceiptHashAlreadyTracked
            }
        })?;
        Ok((packet_len, packet_hash))
    }

    /// Build an LRRTT packet from an already encoded payload.
    ///
    /// This low-level compatibility surface is useful for protocol tests and
    /// peers that already own a MessagePack encoder. Normal initiators should
    /// call [`Self::build_lrrtt_packet_for_rtt`] so the wire payload is the
    /// canonical MessagePack float64 representation emitted by Python RNS.
    pub fn build_lrrtt_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &LinkId,
        rtt_bytes: &[u8],
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        Self::build_link_packet(link, link_id, rtt_bytes, CONTEXT_LRRTT, rng)
    }

    /// Build a canonical Python-compatible LRRTT measurement packet.
    ///
    /// `umsgpack.packb(float)` emits the float64 marker followed by the
    /// big-endian IEEE-754 value. Form it in a fixed stack buffer so encoding
    /// itself performs no allocation.
    pub fn build_lrrtt_packet_for_rtt<R: RngCore + CryptoRng>(
        &self,
        link_id: &LinkId,
        rtt: f64,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let mut payload = [0u8; 9];
        payload[0] = 0xcb;
        payload[1..].copy_from_slice(&rtt.to_be_bytes());
        self.build_lrrtt_packet(link_id, &payload, rng)
    }

    /// Build an unencrypted keepalive request/response packet for a link.
    ///
    /// Python RNS special-cases keepalives in `Packet.pack()`: the wire payload
    /// is exactly one byte (`0xFF` request or `0xFE` response), without a Token.
    /// Successful construction updates Link outbound and keepalive timestamps.
    pub fn build_keepalive_packet(
        &mut self,
        link_id: &LinkId,
        request: bool,
        now: u64,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        self.build_keepalive_packet_at(link_id, request, MonotonicInstant::from_secs(now))
    }

    /// Precise-clock variant of [`Self::build_keepalive_packet`].
    pub fn build_keepalive_packet_at(
        &mut self,
        link_id: &LinkId,
        request: bool,
        now: MonotonicInstant,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        if request != (link.role == LinkRole::Initiator) {
            return Err(SendError::KeepaliveRoleMismatch);
        }
        let payload: &[u8] = if request { &[0xFF] } else { &[0xFE] };
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_KEEPALIVE)
            .payload(payload)
            .build()
            .map_err(SendError::PacketBuild)?;
        let packet = pkt_buf[..pkt_len].to_vec();
        self.links
            .get_mut(link_id)
            .expect("keepalive Link cannot disappear during synchronous construction")
            .note_keepalive_outbound_at(now);
        Ok(packet)
    }

    /// Encrypt plaintext and build a link DATA packet. Shared by all link packet builders.
    pub(super) fn build_link_packet<R: RngCore + CryptoRng>(
        link: &Link,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let mut packet = alloc::vec::Vec::new();
        packet
            .try_reserve_exact(rete_core::MTU)
            .map_err(|_| SendError::OutputAllocationFailed)?;
        packet.resize(rete_core::MTU, 0);
        let packet_len = Self::build_link_packet_into(
            link,
            link_id,
            plaintext,
            context,
            rng,
            &mut packet,
        )?;
        packet.truncate(packet_len);
        Ok(packet)
    }

    /// Encrypt plaintext into caller-owned packet storage.
    fn build_link_packet_into<R: RngCore + CryptoRng>(
        link: &Link,
        link_id: &LinkId,
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
        output: &mut [u8],
    ) -> Result<usize, SendError> {
        if output.len() < rete_core::MTU {
            return Err(SendError::PacketBuild(rete_core::Error::BufferTooSmall));
        }
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link
            .encrypt(plaintext, rng, &mut ct_buf)
            .map_err(SendError::Crypto)?;
        PacketBuilder::new(&mut output[..rete_core::MTU])
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(context)
            .payload(&ct_buf[..ct_len])
            .build()
            .map_err(SendError::PacketBuild)
    }

    /// Build a LINKCLOSE packet and remove the link.
    pub fn build_linkclose_packet<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        let mut close_buf = [0u8; rete_core::MTU];
        let close_len = link
            .build_close(rng, &mut close_buf)
            .map_err(SendError::Crypto)?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LINKCLOSE)
            .payload(&close_buf[..close_len])
            .build()
            .map_err(SendError::PacketBuild)?;

        let packet = pkt_buf[..pkt_len].to_vec();
        self.remove_owned_link(link_id);
        Ok(packet)
    }

    pub(super) fn handle_link_request<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a [u8],
        dest_hash: &DestHash,
        payload: &[u8],
        ingress: LinkRequestIngress,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        let link_id = match compute_link_id(raw) {
            Ok(id) => id,
            Err(_) => return IngestResult::Invalid,
        };

        // Check for duplicate link request
        if self.links.contains_key(&link_id) {
            return IngestResult::Duplicate;
        }

        let mut link = match Link::from_request_at_with_hops(
            link_id,
            payload,
            rng,
            ingress.now,
            ingress.hops,
        ) {
            Ok(l) => l,
            Err(_) => {
                self.stats.links_failed += 1;
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };
        link.destination_hash = *dest_hash;
        link.bound_interface = Some(ingress.interface);

        match self.admit_owned_link(link_id, link) {
            OwnedLinkAdmission::Inserted => {}
            OwnedLinkAdmission::Existing => return IngestResult::Duplicate,
            OwnedLinkAdmission::Full => {
                return IngestResult::LinkTableFull {
                    link_id,
                    table: LinkTableKind::Owned,
                };
            }
        }

        // Build LRPROOF
        let proof_payload = match self.links.get(&link_id) {
            Some(link) => match link.build_proof(identity) {
                Ok(proof) => proof,
                Err(_) => {
                    self.remove_owned_link(&link_id);
                    self.stats.links_failed += 1;
                    self.stats.crypto_failures += 1;
                    return IngestResult::Invalid;
                }
            },
            None => {
                // A backend that reports successful insertion must make the
                // inserted value observable. Fail closed if it violates that
                // contract instead of emitting a proof without retained state.
                self.remove_owned_link(&link_id);
                self.stats.links_failed += 1;
                return IngestResult::Invalid;
            }
        };

        // Build LRPROOF packet: Proof type, Link dest_type, dest=link_id, context=LRPROOF
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = match PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
        {
            Ok(n) => n,
            Err(_) => {
                self.remove_owned_link(&link_id);
                return IngestResult::Invalid;
            }
        };

        self.stats.link_requests_received += 1;
        IngestResult::LinkRequestReceived {
            link_id,
            proof_raw: proof_buf[..proof_len].to_vec(),
        }
    }

    /// Validate an LRPROOF payload at a relay node.
    ///
    /// Matches Python `Transport.py` relay behavior: validates the responder's
    /// signature before forwarding. Identity lookup and reconstruction are
    /// handled by the caller and fail closed before this method is invoked.
    pub(super) fn validate_lrproof_relay(
        &self,
        proof_payload: &[u8],
        link_id: &LinkId,
        dest_identity: &Identity,
    ) -> bool {
        use crate::link::LINK_MTU_SIZE;

        if proof_payload.len() < 96 {
            return false;
        }

        let signature = &proof_payload[..64];
        let responder_x25519_pub = &proof_payload[64..96];
        let signalling = &proof_payload[96..];

        // Reject unexpected trailing data
        if signalling.len() > LINK_MTU_SIZE {
            return false;
        }

        // Reconstruct signed_data: link_id || responder_x25519_pub || ed25519_pub [|| signalling]
        let signed_len = 80 + signalling.len();
        let mut signed_data = [0u8; 83]; // max: 16+32+32+3
        signed_data[..16].copy_from_slice(link_id.as_ref());
        signed_data[16..48].copy_from_slice(responder_x25519_pub);
        signed_data[48..80].copy_from_slice(dest_identity.ed25519_pub());
        signed_data[80..signed_len].copy_from_slice(signalling);

        dest_identity
            .verify(&signed_data[..signed_len], signature)
            .is_ok()
    }

    pub(super) fn handle_lrproof<'a>(
        &mut self,
        link_id: &LinkId,
        proof_payload: &[u8],
        now: MonotonicInstant,
        iface: u8,
    ) -> IngestResult<'a> {
        // Look up the initiator link
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // A proof can establish an initiator Link exactly once. In particular,
        // a replay received after activation must never migrate the retained
        // interface or reset the cryptographic state.
        if link.role != crate::link::LinkRole::Initiator
            || link.state != crate::link::LinkState::Handshake
            || link.bound_interface.is_some()
        {
            return IngestResult::Invalid;
        }

        // Need the destination identity to verify the proof
        let dest_hash = link.destination_hash;
        let pub_key = match self.known_identities.get(&dest_hash) {
            Some(pk) => *pk,
            None => return IngestResult::Invalid,
        };

        let dest_identity = match Identity::from_public_key(&pub_key) {
            Ok(id) => id,
            Err(_) => {
                self.stats.links_failed += 1;
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };

        if link.validate_proof(proof_payload, &dest_identity).is_err() {
            self.stats.links_failed += 1;
            self.stats.crypto_failures += 1;
            return IngestResult::Invalid;
        }

        // A cryptographically valid LRPROOF is authoritative evidence of the
        // interface on which this Link is reachable. This confirms a learned
        // path binding and repairs a stale/missing one without trusting an
        // unauthenticated packet.
        link.bound_interface = Some(iface);

        // The request origin is immutable and may have been refined by a
        // runtime dispatch confirmation. Zero is a valid loopback RTT and
        // still produces Python's five-second keepalive floor.
        let rtt = link.request_elapsed_seconds(now);
        link.update_keepalive(rtt);

        // Initiator activates after proof validation (will send LRRTT next)
        link.activate_at(now);

        self.stats.links_established += 1;
        IngestResult::LinkEstablished { link_id: *link_id }
    }

    /// Tear down a responder handshake whose authenticated LRRTT plaintext is
    /// not a Python-compatible MessagePack number.
    ///
    /// Python calls `Link.teardown()` from the LRRTT exception path. Construct
    /// its encrypted LINKCLOSE while the session key is still retained, then
    /// purge local state regardless of whether packet construction succeeds.
    fn teardown_malformed_lrrtt<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        rng: &mut R,
    ) -> IngestResult<'a> {
        let was_established = self.links.get(link_id).is_some_and(|link| {
            matches!(link.state, crate::link::LinkState::Active | crate::link::LinkState::Stale)
        });
        let interface = self.links.get(link_id).and_then(Link::bound_interface);
        let close_raw = self.build_linkclose_packet(link_id, rng).ok();
        if close_raw.is_none() {
            self.remove_owned_link(link_id);
        }
        self.stats.packets_dropped_invalid += 1;
        if !was_established {
            self.stats.links_failed += 1;
        }
        self.stats.links_closed += 1;
        IngestResult::LinkTeardown {
            link_id: *link_id,
            close_raw,
            interface,
        }
    }

    pub(super) fn handle_link_data<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        packet: &Packet<'_>,
        now: u64,
        link_now: MonotonicInstant,
        pkt_hash: [u8; 32],
        rng: &mut R,
    ) -> IngestResult<'a> {
        let context = packet.context;
        let ciphertext = packet.payload;
        let hops = packet.hops;
        // Python RNS keepalives are the only ordinary Link DATA context that is
        // deliberately not encrypted. Handle the exact role-specific byte before
        // the generic Token path. Invalid bytes never touch Link liveness state.
        if context == CONTEXT_KEEPALIVE {
            let link = match self.links.get_mut(link_id) {
                Some(link) => link,
                None => return IngestResult::Invalid,
            };
            return match link.consume_keepalive_at(ciphertext, link_now) {
                Some(reply) => IngestResult::Keepalive {
                    link_id: *link_id,
                    reply,
                },
                None => {
                    self.stats.packets_dropped_invalid += 1;
                    IngestResult::Invalid
                }
            };
        }

        // For resource contexts, decrypt first in a sub-scope to release the link
        // borrow, then handle resources using self.resources separately.
        if matches!(
            context,
            CONTEXT_RESOURCE
                | CONTEXT_RESOURCE_ADV
                | CONTEXT_RESOURCE_REQ
                | CONTEXT_RESOURCE_HMU
                | CONTEXT_RESOURCE_PRF
                | CONTEXT_RESOURCE_ICL
                | CONTEXT_RESOURCE_RCL
        ) {
            // CONTEXT_RESOURCE data parts are NOT link-encrypted — they travel as raw payload.
            // All other resource contexts (ADV, REQ, HMU, PRF, ICL, RCL) ARE link-encrypted.
            if context == CONTEXT_RESOURCE {
                // Pass raw ciphertext payload directly (no link decryption).
                // Resource parts retain Python's Link-level liveness behavior:
                // an attached-interface packet may revive Stale before the
                // resource layer applies its per-part hash matching.
                {
                    let link = match self.links.get_mut(link_id) {
                        Some(l) => l,
                        None => return IngestResult::Invalid,
                    };
                    if !link.accepts_inbound() {
                        return IngestResult::Invalid;
                    }
                    link.touch_inbound_at(link_now);
                }
                return self.handle_resource_data(link_id, context, ciphertext, now, rng);
            }

            // Use heap buffer for resource contexts — TCP links can carry
            // payloads much larger than the 500-byte radio MTU.
            let mut dec_buf = alloc::vec![0u8; ciphertext.len()];
            let dec_len = {
                let link = match self.links.get_mut(link_id) {
                    Some(l) => l,
                    None => return IngestResult::Invalid,
                };
                if !link.accepts_inbound() {
                    return IngestResult::Invalid;
                }
                match link.decrypt(ciphertext, &mut dec_buf) {
                    Ok(n) => {
                        link.touch_inbound_at(link_now);
                        n
                    }
                    Err(_) => {
                        self.stats.crypto_failures += 1;
                        return IngestResult::Invalid;
                    }
                }
            };
            // self.links borrow is released. Now we can use self.resources.
            return self.handle_resource_data(link_id, context, &dec_buf[..dec_len], now, rng);
        }

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // Decrypt payload — use heap if ciphertext exceeds radio MTU
        let mut dec_buf = alloc::vec![0u8; core::cmp::max(ciphertext.len(), rete_core::MTU)];
        let dec_len = match link.decrypt(ciphertext, &mut dec_buf) {
            Ok(n) => n,
            Err(_) => {
                self.stats.crypto_failures += 1;
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        };

        match context {
            CONTEXT_LRRTT => {
                // Python accepts fresh authenticated LRRTT on responder Links
                // in Handshake, Active and Stale. Decrypt and decode the first
                // MessagePack object before changing lifecycle or liveness;
                // this intentionally retains Rete's pre-auth hardening.
                if link.role != LinkRole::Responder
                    || !matches!(
                        link.state,
                        crate::link::LinkState::Handshake
                            | crate::link::LinkState::Active
                            | crate::link::LinkState::Stale
                    )
                {
                    return IngestResult::Invalid;
                }
                let first_activation = link.state == crate::link::LinkState::Handshake;
                let mut pos = 0;
                let peer_rtt = match rete_core::msgpack::read_float64(
                    &dec_buf[..dec_len],
                    &mut pos,
                ) {
                    Ok(peer_rtt) => peer_rtt,
                    Err(_) => return self.teardown_malformed_lrrtt(link_id, rng),
                };

                // Python computes max(measured_rtt, peer_rtt). Express it as
                // the comparison Python's max() performs so a peer NaN does
                // not replace a finite local measurement.
                let measured_rtt = link.request_elapsed_seconds(link_now);
                let rtt = if peer_rtt > measured_rtt {
                    peer_rtt
                } else {
                    measured_rtt
                };

                // Only authenticated, numeric LRRTT reaches lifecycle mutation.
                link.set_expected_hops(hops);
                link.update_keepalive(rtt);
                link.activate_at(link_now);
                if first_activation {
                    self.stats.links_established += 1;
                    IngestResult::LinkEstablished { link_id: *link_id }
                } else {
                    IngestResult::LinkRttUpdated { link_id: *link_id }
                }
            }
            CONTEXT_LINKCLOSE => {
                let lid = *link_id;
                if link.handle_close(&dec_buf[..dec_len]) {
                    self.remove_owned_link(&lid);
                    self.stats.links_closed += 1;
                    IngestResult::LinkClosed { link_id: lid }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_CHANNEL => {
                if !link.accepts_inbound() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound_at(link_now);
                // Lazy-init channel
                let channel = link
                    .channel
                    .get_or_insert_with(crate::channel::Channel::new);
                channel.receive(&dec_buf[..dec_len]);
                let mut messages = alloc::vec::Vec::new();
                while let Some(env) = channel.next_received() {
                    messages.push(env);
                }
                if messages.is_empty() {
                    IngestResult::Buffered {
                        packet_hash: pkt_hash,
                        link_id: *link_id,
                    }
                } else {
                    IngestResult::ChannelMessages {
                        link_id: *link_id,
                        messages,
                        packet_hash: pkt_hash,
                    }
                }
            }
            CONTEXT_REQUEST => {
                if !link.accepts_inbound() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound_at(link_now);
                match crate::request::parse_request_data(&dec_buf[..dec_len]) {
                    Ok((ts, rq_path_hash, crate::request::RequestData::Bytes(data))) => {
                        // Python RNS uses the packet's truncated hash as request_id
                        // for single-packet requests (Link.py: RequestReceipt uses
                        // packet_receipt.truncated_hash). This is SHA-256(hashable)[..16].
                        IngestResult::RequestReceived {
                            link_id: *link_id,
                            request_id: rete_core::RequestId::from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]),
                            path_hash: rq_path_hash,
                            data: data.to_vec(),
                            requested_at: ts,
                        }
                    }
                    Ok((ts, rq_path_hash, crate::request::RequestData::EncodedValue(value))) => {
                        IngestResult::RequestValueReceived {
                            link_id: *link_id,
                            request_id: rete_core::RequestId::from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]),
                            path_hash: rq_path_hash,
                            value: value.to_vec(),
                            requested_at: ts,
                        }
                    }
                    Err(_) => IngestResult::Invalid,
                }
            }
            CONTEXT_RESPONSE => {
                if !link.accepts_inbound() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound_at(link_now);
                match crate::request::parse_response(&dec_buf[..dec_len]) {
                    Ok((req_id, data)) => IngestResult::ResponseReceived {
                        link_id: *link_id,
                        request_id: req_id,
                        data,
                    },
                    Err(_) => IngestResult::Invalid,
                }
            }
            _ => {
                // Regular link data — only this branch allocates
                if !link.accepts_inbound() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound_at(link_now);
                IngestResult::LinkData {
                    link_id: *link_id,
                    data: dec_buf[..dec_len].to_vec(),
                    context,
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Channel message send
    // -----------------------------------------------------------------------

    fn channel_receipt_key(packet_hash: &[u8; 32]) -> [u8; TRUNCATED_HASH_LEN] {
        packet_hash[..TRUNCATED_HASH_LEN]
            .try_into()
            .expect("truncated packet hash length is fixed")
    }

    fn find_channel_receipt(
        &self,
        link_id: &LinkId,
        sequence: u16,
    ) -> Option<([u8; TRUNCATED_HASH_LEN], ChannelReceipt)> {
        self.channel_receipts
            .iter()
            .find(|(_, receipt)| receipt.link_id == *link_id && receipt.sequence == sequence)
            .map(|(key, receipt)| (*key, receipt.clone()))
    }

    /// Admit a new channel receipt without replacing a colliding entry.
    fn admit_channel_receipt(&mut self, receipt: ChannelReceipt) -> Result<(), SendError> {
        let key = Self::channel_receipt_key(&receipt.packet_hash);
        if self.channel_receipts.contains_key(&key) {
            return Err(SendError::ReceiptHashAlreadyTracked);
        }
        match self.channel_receipts.insert(key, receipt) {
            Ok(None) => Ok(()),
            Ok(Some(previous)) => {
                let restored = self.channel_receipts.insert(key, previous);
                debug_assert!(matches!(restored, Ok(Some(_))));
                Err(SendError::ReceiptHashAlreadyTracked)
            }
            Err(_) => Err(SendError::ReceiptTableFull),
        }
    }

    /// Atomically replace the exact prior attempt for a channel sequence.
    ///
    /// Removing the old entry first makes this capacity-neutral for bounded
    /// maps. Any unexpected insertion failure restores the old proof target.
    fn replace_channel_receipt(
        &mut self,
        link_id: &LinkId,
        sequence: u16,
        receipt: ChannelReceipt,
    ) -> Result<(), SendError> {
        let Some((old_key, old_receipt)) = self.find_channel_receipt(link_id, sequence) else {
            return self.admit_channel_receipt(receipt);
        };
        if old_receipt.packet_hash == receipt.packet_hash {
            return Err(SendError::ReceiptHashAlreadyTracked);
        }

        let new_key = Self::channel_receipt_key(&receipt.packet_hash);
        if new_key == old_key {
            return match self.channel_receipts.insert(new_key, receipt) {
                Ok(Some(_)) => Ok(()),
                Ok(None) => {
                    // The map changed despite exclusive access. Restore the
                    // prior proof target and fail closed.
                    let restored = self.channel_receipts.insert(old_key, old_receipt);
                    debug_assert!(matches!(restored, Ok(Some(_))));
                    Err(SendError::ReceiptHashAlreadyTracked)
                }
                Err(_) => Err(SendError::ReceiptTableFull),
            };
        }
        if self.channel_receipts.contains_key(&new_key) {
            return Err(SendError::ReceiptHashAlreadyTracked);
        }

        let removed = self
            .channel_receipts
            .remove(&old_key)
            .expect("located channel receipt must remain under exclusive access");
        match self.channel_receipts.insert(new_key, receipt) {
            Ok(None) => Ok(()),
            Ok(Some(displaced)) => {
                self.channel_receipts.remove(&new_key);
                let restored_displaced = self.channel_receipts.insert(new_key, displaced);
                debug_assert!(matches!(restored_displaced, Ok(None)));
                let restored_old = self.channel_receipts.insert(old_key, removed);
                debug_assert!(matches!(restored_old, Ok(None)));
                Err(SendError::ReceiptHashAlreadyTracked)
            }
            Err(_) => {
                let restored = self.channel_receipts.insert(old_key, removed);
                debug_assert!(matches!(restored, Ok(None)));
                Err(SendError::ReceiptTableFull)
            }
        }
    }

    /// Send a channel message on a link.
    ///
    /// Packet output and receipt admission are preflighted before encryption.
    /// The channel sequence/window and Link timestamp commit only after the
    /// exact packet receipt has been retained.
    pub fn send_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        message_type: u16,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        if crate::channel::ENVELOPE_HEADER_SIZE
            .checked_add(payload.len())
            .filter(|length| *length <= LINK_MDU)
            .is_none()
        {
            return Err(SendError::PacketBuild(rete_core::Error::PayloadTooLarge));
        }
        if self.channel_receipts.is_full() {
            return Err(SendError::ReceiptTableFull);
        }

        let mut new_channel = None;
        let prepared = match self
            .links
            .get_mut(link_id)
            .expect("validated channel Link must remain under exclusive access")
            .channel
            .as_mut()
        {
            Some(channel) => {
                if !channel.reserve_send_slot() {
                    return Err(SendError::OutputAllocationFailed);
                }
                channel
                    .prepare_send(message_type, payload)
                    .ok_or(SendError::WindowFull)?
            }
            None => {
                let mut channel = crate::channel::Channel::new();
                if !channel.reserve_send_slot() {
                    return Err(SendError::OutputAllocationFailed);
                }
                let prepared = channel
                    .prepare_send(message_type, payload)
                    .ok_or(SendError::WindowFull)?;
                new_channel = Some(channel);
                prepared
            }
        };
        let sequence = prepared.sequence();
        let link = self
            .links
            .get(link_id)
            .expect("prepared channel Link must remain under exclusive access");
        let raw = Self::build_link_packet(link, link_id, prepared.packed(), CONTEXT_CHANNEL, rng)?;
        let packet_hash = Packet::parse(&raw)
            .map_err(SendError::PacketBuild)?
            .compute_hash();

        // No channel state can change while this method exclusively owns the
        // transport, but validate the immutable token at the transaction edge.
        let current = self
            .links
            .get(link_id)
            .and_then(|link| link.channel.as_ref())
            .or(new_channel.as_ref())
            .is_some_and(|channel| channel.send_is_current(&prepared));
        debug_assert!(current);
        self.admit_channel_receipt(ChannelReceipt {
            link_id: *link_id,
            packet_hash,
            sequence,
            sent_at: now,
        })?;

        let link = self
            .links
            .get_mut(link_id)
            .expect("channel Link must remain under exclusive access");
        if let Some(channel) = new_channel {
            debug_assert!(link.channel.is_none());
            link.channel = Some(channel);
        }
        let channel = link.channel.as_mut().expect("prepared channel must be retained");
        debug_assert!(channel.send_is_current(&prepared));
        let _ = channel.commit_send(prepared, Some(now));
        link.note_outbound(now);

        Ok(raw)
    }

    // -----------------------------------------------------------------------
    // Channel retransmission
    // -----------------------------------------------------------------------

    /// Discover channel retries and terminal teardowns without mutating Link,
    /// channel, receipt, timestamp, or entropy state.
    pub fn pending_channel_maintenance(&self, now: u64) -> alloc::vec::Vec<ChannelMaintenanceAction> {
        let mut actions = alloc::vec::Vec::new();
        for (link_id, link) in self.links.iter() {
            if !link.is_active() {
                continue;
            }
            let Some(channel) = link.channel.as_ref() else {
                continue;
            };
            match channel.pending_maintenance(now) {
                Some(ChannelMaintenance::Retransmit(retries)) => {
                    actions.extend(retries.into_iter().map(|retry| {
                        ChannelMaintenanceAction::Retransmit(PendingChannelRetry {
                            link_id: *link_id,
                            link_session: LinkSessionFingerprint::of(link),
                            retry,
                        })
                    }));
                }
                Some(ChannelMaintenance::Teardown) => {
                    actions.push(ChannelMaintenanceAction::Teardown(PendingChannelTeardown {
                        link_id: *link_id,
                        link_session: LinkSessionFingerprint::of(link),
                        discovered_at: now,
                    }));
                }
                None => {}
            }
        }
        actions
    }

    /// Commit one fresh-ciphertext channel retry and atomically move its proof
    /// target from the previous packet hash to the new packet hash.
    pub fn retry_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        pending: PendingChannelRetry,
        now: u64,
        shrink_window: bool,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let PendingChannelRetry {
            link_id,
            link_session,
            retry,
        } = pending;
        let link = self.links.get(&link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        if LinkSessionFingerprint::of(link) != link_session {
            return Err(SendError::PacketBuild(rete_core::Error::InvalidArgument(
                "stale channel retry Link session",
            )));
        }
        let channel = link.channel.as_ref().ok_or(SendError::LinkNotActive)?;
        if !channel.retry_is_current(&retry) {
            return Err(SendError::PacketBuild(rete_core::Error::InvalidArgument(
                "stale channel retry",
            )));
        }
        let sequence = retry.sequence();
        let old_receipt = self.find_channel_receipt(&link_id, sequence);
        if old_receipt.is_none() && self.channel_receipts.is_full() {
            return Err(SendError::ReceiptTableFull);
        }

        let raw = Self::build_link_packet(
            link,
            &link_id,
            retry.packed(),
            CONTEXT_CHANNEL,
            rng,
        )?;
        let packet_hash = Packet::parse(&raw)
            .map_err(SendError::PacketBuild)?
            .compute_hash();
        self.replace_channel_receipt(
            &link_id,
            sequence,
            ChannelReceipt {
                link_id,
                packet_hash,
                sequence,
                sent_at: now,
            },
        )?;

        let link = self
            .links
            .get_mut(&link_id)
            .expect("retry Link must remain under exclusive access");
        let channel = link
            .channel
            .as_mut()
            .expect("retry token must retain its channel");
        debug_assert!(channel.retry_is_current(&retry));
        let _ = channel.commit_retry(retry, now, shrink_window);
        link.note_outbound(now);
        Ok(raw)
    }

    /// Commit a previously discovered terminal channel teardown.
    pub fn commit_channel_teardown(&mut self, pending: PendingChannelTeardown) -> bool {
        let should_teardown = self
            .links
            .get(&pending.link_id)
            .filter(|link| {
                link.is_active() && LinkSessionFingerprint::of(link) == pending.link_session
            })
            .and_then(|link| link.channel.as_ref())
            .and_then(|channel| channel.pending_maintenance(pending.discovered_at))
            .is_some_and(|maintenance| matches!(maintenance, ChannelMaintenance::Teardown));
        should_teardown && self.remove_owned_link(&pending.link_id).is_some()
    }

    /// Compatibility wrapper that discovers and commits all channel work
    /// without an external routing preflight.
    pub fn pending_channel_retransmits<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let actions = self.pending_channel_maintenance(now);
        let mut packets = alloc::vec::Vec::new();
        let mut retried_links = alloc::vec::Vec::<LinkId>::new();
        if packets.try_reserve(actions.len()).is_err()
            || retried_links.try_reserve(actions.len()).is_err()
        {
            return packets;
        }
        for action in actions {
            match action {
                ChannelMaintenanceAction::Retransmit(pending) => {
                    let link_id = *pending.link_id();
                    let shrink_window = !retried_links.contains(&link_id);
                    if let Ok(packet) =
                        self.retry_channel_message(pending, now, shrink_window, rng)
                    {
                        if shrink_window {
                            retried_links.push(link_id);
                        }
                        packets.push(packet);
                    }
                }
                ChannelMaintenanceAction::Teardown(pending) => {
                    self.commit_channel_teardown(pending);
                }
            }
        }
        packets
    }

    // -----------------------------------------------------------------------
    // Keepalive generation
    // -----------------------------------------------------------------------

    /// Return locally owned initiator Links whose next keepalive is due.
    ///
    /// This query does not mutate Link timers. Callers that also own interface
    /// routing can therefore preflight an authoritative route before packet
    /// construction commits the keepalive timestamp.
    pub fn pending_keepalive_link_ids(&self, now: u64) -> alloc::vec::Vec<LinkId> {
        self.pending_keepalive_link_ids_at(MonotonicInstant::from_secs(now))
    }

    /// Precise-clock variant of [`Self::pending_keepalive_link_ids`].
    pub fn pending_keepalive_link_ids_at(
        &self,
        now: MonotonicInstant,
    ) -> alloc::vec::Vec<LinkId> {
        self.links
            .iter()
            .filter_map(|(link_id, link)| link.needs_keepalive_at(now).then_some(*link_id))
            .collect()
    }

    /// Build keepalive request packets for links that need them.
    ///
    /// Iterates active initiator links and generates a keepalive request after
    /// one complete keepalive interval of inbound silence.
    pub fn build_pending_keepalives<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        self.build_pending_keepalives_at(MonotonicInstant::from_secs(now), rng)
    }

    /// Precise-clock variant of [`Self::build_pending_keepalives`].
    pub fn build_pending_keepalives_at<R: RngCore + CryptoRng>(
        &mut self,
        now: MonotonicInstant,
        _rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let need_ka = self.pending_keepalive_link_ids_at(now);
        let mut packets = alloc::vec::Vec::new();
        for lid in need_ka {
            if let Ok(pkt) = self.build_keepalive_packet_at(&lid, true, now) {
                packets.push(pkt);
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaplessStorage;

    type TestTransport = Transport<HeaplessStorage<8, 4, 16, 2>>;

    fn receipt(link_id: LinkId, packet_hash: [u8; 32], sequence: u16) -> ChannelReceipt {
        ChannelReceipt {
            link_id,
            packet_hash,
            sequence,
            sent_at: 100,
        }
    }

    #[test]
    fn retry_receipt_rejects_identical_full_hash_without_mutation() {
        let mut transport = TestTransport::new();
        let link_id = LinkId::from([0x11; TRUNCATED_HASH_LEN]);
        let packet_hash = [0x22; 32];
        transport
            .admit_channel_receipt(receipt(link_id, packet_hash, 7))
            .unwrap();

        assert_eq!(
            transport.replace_channel_receipt(
                &link_id,
                7,
                receipt(link_id, packet_hash, 7),
            ),
            Err(SendError::ReceiptHashAlreadyTracked)
        );
        assert_eq!(transport.channel_receipt_count(), 1);
        assert_eq!(
            transport
                .find_channel_receipt(&link_id, 7)
                .unwrap()
                .1
                .packet_hash,
            packet_hash
        );
    }

    #[test]
    fn retry_receipt_rejects_another_receipts_truncated_hash() {
        let mut transport = TestTransport::new();
        let link_id = LinkId::from([0x31; TRUNCATED_HASH_LEN]);
        let other_link = LinkId::from([0x32; TRUNCATED_HASH_LEN]);
        let old_hash = [0x41; 32];
        let mut other_hash = [0x52; 32];
        other_hash[TRUNCATED_HASH_LEN..].fill(0x53);
        transport
            .admit_channel_receipt(receipt(link_id, old_hash, 1))
            .unwrap();
        transport
            .admit_channel_receipt(receipt(other_link, other_hash, 2))
            .unwrap();
        let mut colliding_hash = other_hash;
        colliding_hash[TRUNCATED_HASH_LEN..].fill(0x54);

        assert_eq!(
            transport.replace_channel_receipt(
                &link_id,
                1,
                receipt(link_id, colliding_hash, 1),
            ),
            Err(SendError::ReceiptHashAlreadyTracked)
        );
        assert_eq!(transport.channel_receipt_count(), 2);
        assert_eq!(
            transport
                .find_channel_receipt(&link_id, 1)
                .unwrap()
                .1
                .packet_hash,
            old_hash
        );
        assert_eq!(
            transport
                .find_channel_receipt(&other_link, 2)
                .unwrap()
                .1
                .packet_hash,
            other_hash
        );
    }

    #[test]
    fn retry_receipt_can_replace_in_place_at_full_capacity() {
        let mut transport = TestTransport::new();
        let link_id = LinkId::from([0x61; TRUNCATED_HASH_LEN]);
        let other_link = LinkId::from([0x62; TRUNCATED_HASH_LEN]);
        let old_hash = [0x71; 32];
        let other_hash = [0x72; 32];
        transport
            .admit_channel_receipt(receipt(link_id, old_hash, 3))
            .unwrap();
        transport
            .admit_channel_receipt(receipt(other_link, other_hash, 4))
            .unwrap();
        let mut new_hash = old_hash;
        new_hash[TRUNCATED_HASH_LEN..].fill(0x73);

        transport
            .replace_channel_receipt(&link_id, 3, receipt(link_id, new_hash, 3))
            .unwrap();
        assert_eq!(transport.channel_receipt_count(), 2);
        assert_eq!(
            transport
                .find_channel_receipt(&link_id, 3)
                .unwrap()
                .1
                .packet_hash,
            new_hash
        );
    }
}
