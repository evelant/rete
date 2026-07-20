//! Link initiation, channel/stream send, close, and identify.

use rand_core::{CryptoRng, RngCore};
use rete_core::{DestHash, LinkId, MTU};
use rete_transport::SendError;

use crate::NodeEvent;

use super::{
    NodeCore, OutboundDispatchInterval, OutboundPacket, OutboundProtocolToken,
};

impl<S: rete_transport::TransportStorage> NodeCore<S> {
    /// Initiate a link to a destination.
    ///
    /// Returns the outbound LINKREQUEST packet and the link_id on success.
    pub fn initiate_link<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: DestHash,
        now: u64,
        rng: &mut R,
    ) -> Result<(OutboundPacket, LinkId), SendError> {
        self.initiate_link_at(
            dest_hash,
            now,
            rete_core::MonotonicInstant::from_secs(now),
            rng,
        )
    }

    /// Precise-clock variant of [`Self::initiate_link`].
    pub fn initiate_link_at<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: DestHash,
        now: u64,
        link_now: rete_core::MonotonicInstant,
        rng: &mut R,
    ) -> Result<(OutboundPacket, LinkId), SendError> {
        // Allocate before mutating Transport so exhaustion cannot strand a
        // request that the runtime has no unique way to confirm.
        let token = self
            .allocate_outbound_protocol_token()
            .ok_or(SendError::ProtocolTokenExhausted)?;
        // A learned path selects only this initial request. The Link itself is
        // deliberately left unbound until a valid LRPROOF arrives.
        let routing = self
            .transport
            .get_path(&dest_hash)
            .and_then(|path| path.received_on)
            .map(super::PacketRouting::ExactInterface)
            .unwrap_or(super::PacketRouting::All);
        let (raw, link_id) = self
            .transport
            .initiate_link_at(dest_hash, &self.identity, rng, now, link_now)?;
        if !self.transport.assign_link_protocol_token(
            &link_id,
            rete_transport::LinkRole::Initiator,
            token.0,
        ) {
            self.transport.discard_unestablished_link(&link_id);
            return Err(SendError::ProtocolTokenAssignmentFailed);
        }
        Ok((OutboundPacket::new(raw, routing).with_protocol_token(token), link_id))
    }

    /// Confirm a protocol packet's bounded runtime dispatch interval.
    ///
    /// LINKREQUEST uses the interval's pre-dispatch edge. LRPROOF uses the
    /// post-dispatch API/egress-handoff edge. The underlying Link accepts one
    /// confirmation only while it has not activated.
    pub fn confirm_outbound_protocol(
        &mut self,
        token: OutboundProtocolToken,
        completed_interface: u8,
        interval: OutboundDispatchInterval,
    ) -> bool {
        self.transport
            .confirm_link_protocol_dispatch(
                token.0,
                completed_interface,
                interval.started_at(),
                interval.completed_at(),
            )
    }

    /// Send a channel message on a link.
    ///
    /// Returns the outbound packet if the message was queued, or `Err` if
    /// the link is not active or the channel window is full.
    pub fn send_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        message_type: u16,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        let routing = self.owned_link_routing(link_id)?;
        let raw = self
            .transport
            .send_channel_message(link_id, message_type, payload, now, rng)?;
        Ok(OutboundPacket::new(raw, routing))
    }

    /// Send stream data on a link via channel.
    ///
    /// Packs a `StreamDataMessage` and sends it as a channel message with
    /// `MSG_TYPE_STREAM`. Uses stack buffer to avoid intermediate heap allocations.
    pub fn send_stream_data<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        stream_id: u16,
        data: &[u8],
        eof: bool,
        now: u64,
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        let mut buf = [0u8; MTU];
        let n = rete_transport::StreamDataMessage::pack_into(stream_id, eof, false, data, &mut buf);
        self.send_channel_message(
            link_id,
            rete_transport::MSG_TYPE_STREAM,
            &buf[..n],
            now,
            rng,
        )
    }

    /// Close a link, sending a LINKCLOSE packet and removing it from the map.
    ///
    /// Returns the outbound LINKCLOSE packet and a [`NodeEvent::LinkClosed`]
    /// event so the caller can emit it locally (the event would otherwise only
    /// fire on *receiving* a LINKCLOSE from the remote side).
    pub fn close_link<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        rng: &mut R,
    ) -> (Option<OutboundPacket>, Option<NodeEvent>) {
        // build_linkclose_packet removes the Link, so retain its routing before
        // asking the transport to construct the close packet.
        let routing = match self.owned_link_routing(link_id) {
            Ok(routing) => routing,
            Err(_) => return (None, None),
        };
        let pkt = self.transport.build_linkclose_packet(link_id, rng).ok();
        let event = if pkt.is_some() {
            Some(NodeEvent::LinkClosed { link_id: *link_id })
        } else {
            None
        };
        (pkt.map(|data| OutboundPacket::new(data, routing)), event)
    }

    /// Send a LINKIDENTIFY packet on an established link.
    ///
    /// This reveals the initiator's identity to the responder by sending the
    /// identity public key signed with Ed25519, encrypted via the link session.
    /// Matches Python `Link.identify()`.
    pub fn link_identify<R: RngCore + CryptoRng>(
        &self,
        link_id: &LinkId,
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        let routing = self.owned_link_routing(link_id)?;
        // Build identify payload: pub_key[64] || Ed25519_sig[64]
        let pub_key = self.identity.public_key();
        let sig = self.identity.sign(&pub_key).map_err(SendError::Crypto)?;
        let mut payload = [0u8; 128];
        payload[..64].copy_from_slice(&pub_key);
        payload[64..128].copy_from_slice(&sig);

        let pkt = self.transport.build_link_data_packet(
            link_id,
            &payload,
            rete_core::CONTEXT_LINKIDENTIFY,
            rng,
        )?;
        Ok(OutboundPacket::new(pkt, routing))
    }
}
