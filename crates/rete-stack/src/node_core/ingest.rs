//! Inbound packet dispatch, request handling, and resource buffering.

use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, Identity, LinkId, MTU, Packet, PacketBuilder, PacketType, PathHash, RequestId,
    TRUNCATED_HASH_LEN,
};
use rete_transport::{
    ForwardTarget, IngestResult, PATH_REQUEST_DEST, ReceiptSinkFull, ReceiptTerminalSink,
};

use crate::destination::DestinationType;
use crate::{NodeEvent, ProofStrategy, RequestFailReason, ResourceStrategy};

use super::{
    IngestOutcome, IngestRejection, NodeCore, OutboundPacket, PacketRouting,
    ReceiptSinkTickOutcome, SplitRecvEntry,
};

impl<S: rete_transport::TransportStorage> NodeCore<S> {
    /// Process an inbound raw packet and return the outcome.
    ///
    /// The runtime loop dispatches packets based on `IngestOutcome.packets`
    /// routing and emits `IngestOutcome.events` to the application callback.
    pub fn handle_ingest<R: RngCore + CryptoRng>(
        &mut self,
        raw: &[u8],
        now: u64,
        iface: u8,
        rng: &mut R,
    ) -> IngestOutcome {
        self.handle_ingest_at(
            raw,
            now,
            rete_core::MonotonicInstant::from_secs(now),
            iface,
            rng,
        )
    }

    /// Process inbound bytes with a precise monotonic Link clock.
    pub fn handle_ingest_at<R: RngCore + CryptoRng>(
        &mut self,
        raw: &[u8],
        now: u64,
        link_now: rete_core::MonotonicInstant,
        iface: u8,
        rng: &mut R,
    ) -> IngestOutcome {
        let len = raw.len();

        // Local shared-instance links negotiate MTUs up to 262 KB.
        // Resource transfers and LXMF messages can produce single packets
        // at the full link MTU. Allow up to 300 KB for hosted nodes.
        const MAX_INGEST_PKT: usize = 300 * 1024;
        if len > MAX_INGEST_PKT {
            return IngestOutcome::empty();
        }

        // Packet log: inbound
        if let Some(hooks) = &self.hooks {
            hooks.log_packet(raw, "IN", iface);
        }

        // Use stack buffer for small packets (common case), heap for large TCP packets.
        if len <= MTU {
            let mut pkt_buf = [0u8; MTU];
            pkt_buf[..len].copy_from_slice(raw);
            self.dispatch_ingest_at(&mut pkt_buf[..len], now, link_now, iface, rng)
        } else {
            let mut pkt_buf = vec![0u8; len];
            pkt_buf[..len].copy_from_slice(raw);
            self.dispatch_ingest_at(&mut pkt_buf[..len], now, link_now, iface, rng)
        }
    }

    /// Process one radio-sized inbound packet with allocation-atomic receipt
    /// terminal notifications.
    ///
    /// A PROOF targeting an outstanding DATA or channel receipt reserves a
    /// terminal sink slot before transport ingestion and commits it after
    /// validation. Other proof traffic does not consume application-terminal
    /// capacity. When reservation fails, no transport or deduplication state is
    /// changed; the caller must retain and retry that packet.
    pub fn handle_ingest_with_receipt_sink<R, T>(
        &mut self,
        raw: &[u8],
        now: u64,
        iface: u8,
        rng: &mut R,
        sink: &mut T,
    ) -> Result<IngestOutcome, ReceiptSinkFull>
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        self.handle_ingest_with_receipt_sink_at(
            raw,
            now,
            rete_core::MonotonicInstant::from_secs(now),
            iface,
            rng,
            sink,
        )
    }

    /// Precise Link-clock variant of [`Self::handle_ingest_with_receipt_sink`].
    pub fn handle_ingest_with_receipt_sink_at<R, T>(
        &mut self,
        raw: &[u8],
        now: u64,
        link_now: rete_core::MonotonicInstant,
        iface: u8,
        rng: &mut R,
        sink: &mut T,
    ) -> Result<IngestOutcome, ReceiptSinkFull>
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        let len = raw.len();
        if len > MTU {
            return Ok(IngestOutcome::empty());
        }

        if let Some(hooks) = &self.hooks {
            hooks.log_packet(raw, "IN", iface);
        }

        let mut pkt_buf = [0u8; MTU];
        pkt_buf[..len].copy_from_slice(raw);
        let inbound_packet_hash =
            Packet::parse(&pkt_buf[..len]).ok().map(|packet| packet.compute_hash());
        let result = self
            .transport
            .ingest_on_with_receipt_sink_at(
                &mut pkt_buf[..len],
                now,
                link_now,
                iface,
                rng,
                &self.identity,
                sink,
            )?;

        match result {
            IngestResult::ProofReceived { .. } => Ok(IngestOutcome::empty()),
            result => Ok(self.dispatch_ingest_result(
                result,
                inbound_packet_hash,
                now,
                link_now,
                rng,
            )),
        }
    }

    fn dispatch_ingest_at<R: RngCore + CryptoRng>(
        &mut self,
        pkt_buf: &mut [u8],
        now: u64,
        link_now: rete_core::MonotonicInstant,
        iface: u8,
        rng: &mut R,
    ) -> IngestOutcome {
        let inbound_packet_hash =
            Packet::parse(pkt_buf).ok().map(|packet| packet.compute_hash());
        let result = self
            .transport
            .ingest_on_at(pkt_buf, now, link_now, iface, rng, &self.identity);
        self.dispatch_ingest_result(result, inbound_packet_hash, now, link_now, rng)
    }

    fn link_closed_outcome(
        &mut self,
        link_id: LinkId,
        packets: Vec<OutboundPacket>,
    ) -> IngestOutcome {
        // Fail any pending requests on this link (single pass).
        let mut events: Vec<NodeEvent> = Vec::new();
        self.pending_requests.retain(|r| {
            if r.link_id == link_id {
                if r.status != super::request_receipt::RequestStatus::Prepared {
                    events.push(NodeEvent::RequestFailed {
                        link_id,
                        request_id: r.request_id,
                        reason: RequestFailReason::LinkClosed,
                    });
                }
                false
            } else {
                true
            }
        });
        events.push(NodeEvent::LinkClosed { link_id });
        IngestOutcome {
            events,
            packets,
            rejection: None,
        }
    }

    fn dispatch_ingest_result<R: RngCore + CryptoRng>(
        &mut self,
        result: IngestResult<'_>,
        inbound_packet_hash: Option<[u8; 32]>,
        now: u64,
        link_now: rete_core::MonotonicInstant,
        rng: &mut R,
    ) -> IngestOutcome {
        match result {
            IngestResult::AnnounceReceived {
                dest_hash,
                identity_hash,
                hops,
                app_data,
                ratchet,
            } => {
                // Store ratchet public key from announcing peer
                if let (Some(store), Some(ratchet_pub)) = (&mut self.ratchet_store, ratchet) {
                    store.store_peer_ratchet(&identity_hash, ratchet_pub);
                }

                let mut packets = Vec::new();

                // Auto-reply to announcing peer
                if let Some(msg) = self.auto_reply.take() {
                    let result = self.build_data_packet(&dest_hash, &msg, rng, now);
                    self.auto_reply = Some(msg);
                    if let Ok(pkt) = result {
                        packets.push(OutboundPacket::new(
                            pkt,
                            PacketRouting::SourceInterface,
                        ));
                    }
                }

                // Flush due pending announces. Transport-mode ingress queued
                // this received announce with retransmit_timeout=now; endpoint
                // ingress did not queue it for forwarding.
                let flushed = self.flush_announces(now, rng);
                packets.extend(flushed);

                IngestOutcome {
                    events: vec![NodeEvent::AnnounceReceived {
                        dest_hash,
                        identity_hash,
                        hops,
                        app_data: app_data.map(|d| d.to_vec()),
                    }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::LocalData {
                dest_hash,
                dest_type,
                payload,
                packet_hash,
            } => {
                let registered_type = match dest_type {
                    DestType::Single => DestinationType::Single,
                    DestType::Group => DestinationType::Group,
                    DestType::Plain => DestinationType::Plain,
                    DestType::Link => DestinationType::Link,
                };
                // Python RNS resolves the registered destination and compares
                // its direction/type after packet_filter has admitted and
                // remembered the full packet hash. Preserve that ordering: a
                // mismatch is a silent local-dispatch miss, not a pre-transport
                // rejection that could be retried outside normal dedup state.
                let dest = match self.get_inbound_destination(&dest_hash, registered_type) {
                    Some(d) => d,
                    None => return IngestOutcome::empty(),
                };
                let proof_strategy = dest.proof_strategy;

                let mut dec_buf = [0u8; MTU];

                // Gather ratchet private keys for Single destinations
                let mut privkeys = Vec::new();
                if dest.dest_type == DestinationType::Single {
                    if let Some(store) = &self.ratchet_store {
                        if let Some(k) = store.local_ratchet_private() {
                            privkeys.push(k);
                        }
                        privkeys.extend_from_slice(store.previous_ratchet_privates());
                    }
                }

                let decrypted = match dest.decrypt_with_identity(
                    payload,
                    Some(&self.identity),
                    &privkeys,
                    &mut dec_buf,
                ) {
                    Ok(n) => dec_buf[..n].to_vec(),
                    Err(_) => return IngestOutcome::empty(),
                };

                let mut packets = Vec::new();

                let should_prove = match proof_strategy {
                    ProofStrategy::ProveAll => true,
                    ProofStrategy::ProveApp => {
                        if let Some(hooks) = &self.hooks {
                            hooks.prove_app(&dest_hash, &packet_hash, &decrypted)
                        } else {
                            false
                        }
                    }
                    ProofStrategy::ProveNone => false,
                };
                if should_prove {
                    packets.extend(self.proof_outbound(&packet_hash));
                }

                IngestOutcome {
                    events: vec![NodeEvent::DataReceived {
                        dest_hash,
                        payload: decrypted,
                    }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::Forward { raw, target, .. } => IngestOutcome {
                events: vec![],
                packets: vec![OutboundPacket::new(
                    raw.to_vec(),
                    match target {
                        ForwardTarget::ExactInterface(interface) => {
                            PacketRouting::ExactInterface(interface)
                        }
                        ForwardTarget::AllExceptSource => PacketRouting::AllExceptSource,
                    },
                )],
                rejection: None,
            },
            IngestResult::LinkRequestReceived { link_id, proof_raw } => {
                let Some(token) = self.allocate_outbound_protocol_token() else {
                    self.transport.discard_unestablished_link(&link_id);
                    return IngestOutcome::rejected(IngestRejection::ProtocolTokenExhausted {
                        link_id,
                    });
                };
                if !self.transport.assign_link_protocol_token(
                    &link_id,
                    rete_transport::LinkRole::Responder,
                    token.0,
                ) {
                    self.transport.discard_unestablished_link(&link_id);
                    return IngestOutcome::rejected(
                        IngestRejection::ProtocolTokenAssignmentFailed { link_id },
                    );
                }
                IngestOutcome {
                    // A responder is not established until authenticated LRRTT.
                    events: vec![],
                    // LRPROOF is a synchronous response to the accepted request.
                    // Preserve SourceInterface provenance for proof telemetry.
                    packets: vec![OutboundPacket::new(
                        proof_raw,
                        PacketRouting::SourceInterface,
                    )
                    .with_protocol_token(token)],
                    rejection: None,
                }
            }
            IngestResult::LinkEstablished { link_id } => {
                let mut packets = Vec::new();
                // Auto-send Python-compatible MessagePack float64 LRRTT if we
                // are the initiator (activates the responder).
                let initiator_rtt = self
                    .transport
                    .get_link(&link_id)
                    .filter(|link| link.role == rete_transport::LinkRole::Initiator)
                    .map(|link| link.rtt);
                if let Some(rtt) = initiator_rtt {
                    if let Ok(pkt) = self
                        .transport
                        .build_lrrtt_packet_for_rtt(&link_id, rtt, rng)
                    {
                        if let Ok(outbound) = self.owned_link_outbound(&link_id, pkt) {
                            packets.push(outbound);
                        }
                    }
                }
                IngestOutcome {
                    events: vec![NodeEvent::LinkEstablished { link_id }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::LinkRttUpdated { link_id } => {
                let rtt = self
                    .transport
                    .get_link(&link_id)
                    .map(|link| link.rtt)
                    .unwrap_or_default();
                IngestOutcome {
                    events: vec![NodeEvent::LinkRttUpdated { link_id, rtt }],
                    packets: Vec::new(),
                    rejection: None,
                }
            }
            IngestResult::Keepalive { link_id, reply } => {
                let mut packets = Vec::new();
                if reply {
                    if let Ok(outbound) =
                        self.build_owned_keepalive_outbound_at(&link_id, false, link_now)
                    {
                        packets.push(outbound);
                    }
                }
                IngestOutcome {
                    // Keepalive traffic is consumed entirely by the Link
                    // lifecycle and never reaches application-facing events.
                    events: Vec::new(),
                    packets,
                    rejection: None,
                }
            }
            IngestResult::LinkData {
                link_id,
                data,
                context,
            } => {
                // Handle LINKIDENTIFY: validate and emit LinkIdentified event
                if context == rete_core::CONTEXT_LINKIDENTIFY && data.len() >= 128 {
                    let mut pub_key = [0u8; 64];
                    pub_key.copy_from_slice(&data[..64]);
                    let sig = &data[64..128];
                    if let Ok(peer_id) = Identity::from_public_key(&pub_key) {
                        if peer_id.verify(&pub_key, sig).is_ok() {
                            let id_hash = peer_id.hash();
                            if let Some(link) = self.transport.get_link_mut(&link_id) {
                                link.set_identified(pub_key);
                            }
                            return IngestOutcome {
                                events: vec![NodeEvent::LinkIdentified {
                                    link_id,
                                    identity_hash: id_hash,
                                    public_key: pub_key,
                                }],
                                packets: Vec::new(),
                                rejection: None,
                            };
                        }
                    }
                }
                // Python applies the receiving destination's proof policy to
                // ordinary Link DATA. Receipt registration is local sender
                // state and is deliberately not visible on wire.
                let packets = if context == rete_core::CONTEXT_NONE {
                    let should_prove = self
                        .transport
                        .get_link(&link_id)
                        .and_then(|link| {
                            self.get_destination(&link.destination_hash)
                                .map(|destination| {
                                    (link.destination_hash, destination.proof_strategy)
                                })
                        })
                        .is_some_and(|(destination_hash, proof_strategy)| {
                            match proof_strategy {
                                ProofStrategy::ProveAll => true,
                                ProofStrategy::ProveApp => {
                                    self.hooks.as_ref().is_some_and(|hooks| {
                                        inbound_packet_hash.is_some_and(|packet_hash| {
                                            hooks.prove_app(&destination_hash, &packet_hash, &data)
                                        })
                                    })
                                }
                                ProofStrategy::ProveNone => false,
                            }
                        });
                    if should_prove {
                        inbound_packet_hash
                            .and_then(|packet_hash| {
                                self.link_proof_outbound(&packet_hash, &link_id)
                            })
                            .into_iter()
                            .collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                IngestOutcome {
                    events: vec![NodeEvent::LinkData {
                        link_id,
                        data,
                        context,
                    }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::ChannelMessages {
                link_id,
                messages,
                packet_hash,
            } => IngestOutcome {
                events: vec![NodeEvent::ChannelMessages {
                    link_id,
                    messages: messages
                        .into_iter()
                        .map(|e| (e.message_type, e.payload))
                        .collect(),
                }],
                // Auto-prove received channel packets (link-destination proof for relay routing)
                packets: self
                    .link_proof_outbound(&packet_hash, &link_id)
                    .into_iter()
                    .collect(),
                rejection: None,
            },
            IngestResult::RequestReceived {
                link_id,
                request_id,
                path_hash,
                data,
                requested_at,
            } => {
                let response_packets = self.dispatch_request_handler(
                    &link_id,
                    &request_id,
                    &path_hash,
                    &data,
                    requested_at,
                    rng,
                );
                IngestOutcome {
                    events: vec![NodeEvent::RequestReceived {
                        link_id,
                        request_id,
                        path_hash,
                        data,
                    }],
                    packets: response_packets,
                    rejection: None,
                }
            }
            IngestResult::RequestValueReceived {
                link_id,
                request_id,
                path_hash,
                value,
                requested_at,
            } => IngestOutcome {
                events: vec![NodeEvent::RequestValueReceived {
                    link_id,
                    request_id,
                    path_hash,
                    requested_at,
                    value,
                }],
                packets: Vec::new(),
                rejection: None,
            },
            IngestResult::ResponseReceived {
                link_id,
                request_id,
                data,
            } => {
                // Clear only a dispatched matching request. A response cannot
                // consume a packet that is still waiting for interface handoff.
                self.pending_requests.retain(|request| {
                    request.link_id != link_id
                        || request.request_id != request_id
                        || request.status == super::request_receipt::RequestStatus::Prepared
                });
                IngestOutcome {
                    events: vec![NodeEvent::ResponseReceived {
                        link_id,
                        request_id,
                        data,
                    }],
                    packets: Vec::new(),
                    rejection: None,
                }
            }
            IngestResult::LinkClosed { link_id } => {
                self.link_closed_outcome(link_id, Vec::new())
            }
            IngestResult::LinkTeardown {
                link_id,
                close_raw,
                interface,
            } => {
                let packets = close_raw
                    .zip(interface)
                    .map(|(data, interface)| {
                        vec![OutboundPacket::new(
                            data,
                            PacketRouting::BoundInterface(interface),
                        )]
                    })
                    .unwrap_or_default();
                self.link_closed_outcome(link_id, packets)
            }
            IngestResult::ProofReceived { packet_hash } => IngestOutcome {
                events: vec![NodeEvent::ProofReceived { packet_hash }],
                packets: Vec::new(),
                rejection: None,
            },
            IngestResult::Buffered {
                packet_hash,
                link_id,
            } => IngestOutcome {
                events: vec![],
                // Auto-prove buffered channel packets too (link-destination proof for relay routing)
                packets: self
                    .link_proof_outbound(&packet_hash, &link_id)
                    .into_iter()
                    .collect(),
                rejection: None,
            },
            IngestResult::ResourceOffered {
                link_id,
                resource_hash,
                total_size,
                is_request_or_response,
                is_response,
                request_id,
            } => {
                let mut packets = Vec::new();

                // Associate response-resource with pending request.
                // Match by request_id from "q" field when available (Python always
                // populates it for response-resources), fall back to FIFO for
                // interop with peers that send nil.
                if is_response {
                    let matched = if let Some(rid) = request_id {
                        self.pending_requests
                            .iter_mut()
                            .find(|r| {
                                r.link_id == link_id
                                    && r.request_id == rid
                                    && matches!(
                                        r.status,
                                        super::request_receipt::RequestStatus::Sent
                                            | super::request_receipt::RequestStatus::Receiving
                                    )
                            })
                    } else {
                        // FIFO fallback: first Sent request without a resource yet
                        self.pending_requests.iter_mut().find(|r| {
                            r.link_id == link_id
                                && r.response_resource_hash.is_none()
                                && matches!(r.status, super::request_receipt::RequestStatus::Sent)
                        })
                    };
                    if let Some(req) = matched {
                        req.response_resource_hash = Some(resource_hash);
                    }
                }

                // Request/Response resources bypass strategy (Python behavior)
                let effective = if is_request_or_response {
                    ResourceStrategy::AcceptAll
                } else {
                    self.resource_strategy
                };

                match effective {
                    ResourceStrategy::AcceptAll => {
                        packets.extend(self.accept_resource(&link_id, &resource_hash, rng));
                        packets.extend(self.drain_resource_outbound());
                    }
                    ResourceStrategy::AcceptNone => {
                        packets.extend(self.reject_resource(&link_id, &resource_hash, rng));
                    }
                    ResourceStrategy::AcceptApp => {
                        // No auto-action — application calls accept/reject
                    }
                }

                IngestOutcome {
                    events: vec![NodeEvent::ResourceOffered {
                        link_id,
                        resource_hash,
                        total_size,
                    }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::ResourceProgress {
                link_id,
                resource_hash,
                current,
                total,
            } => {
                let mut packets = Vec::new();
                // If all parts received, concat → decrypt → decompress → verify → proof
                if current == total && total > 0 {
                    // Step 1: Concatenate encrypted parts, get flags and split metadata
                    let (
                        concat_result,
                        is_compressed,
                        is_response,
                        is_request,
                        split_index,
                        split_total,
                        original_hash,
                    ) = {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            let compressed = res.flags.compressed;
                            let resp = res.flags.is_response;
                            let req = res.flags.is_request;
                            let si = res.split_index;
                            let st = res.split_total;
                            let oh = res.original_hash;
                            match res.concat_parts() {
                                Ok(data) => (Some(data), compressed, resp, req, si, st, oh),
                                Err(_) => (None, compressed, resp, req, si, st, oh),
                            }
                        } else {
                            (None, false, false, false, 1, 1, [0u8; 32])
                        }
                    };

                    // Failure helper: drain outbound, cleanup, clean split buf
                    macro_rules! resource_failed {
                        ($packets:expr) => {{
                            $packets.extend(self.drain_resource_outbound());
                            self.transport.cleanup_resources();
                            if split_total > 1 {
                                if let Some(idx) = self.split_recv_buf.iter().position(|e| {
                                    e.link_id == link_id && e.original_hash == original_hash
                                }) {
                                    self.split_recv_buf.swap_remove(idx);
                                }
                            }
                            return IngestOutcome {
                                events: vec![NodeEvent::ResourceFailed {
                                    link_id,
                                    resource_hash,
                                }],
                                packets: core::mem::take(&mut $packets),
                                rejection: None,
                            };
                        }};
                    }

                    let encrypted_data = match concat_result {
                        Some(data) => data,
                        None => resource_failed!(packets),
                    };

                    // Step 2: Decrypt via link Token, strip 4-byte random prepend — hard fail
                    let decrypted = if let Some(link) = self.transport.get_link(&link_id) {
                        let mut dec_buf = vec![0u8; encrypted_data.len()];
                        match link.decrypt(&encrypted_data, &mut dec_buf) {
                            Ok(dec_len) => {
                                dec_buf.truncate(dec_len);
                                if dec_buf.len() >= 4 {
                                    dec_buf.drain(..4);
                                }
                                dec_buf
                            }
                            Err(_) => resource_failed!(packets),
                        }
                    } else {
                        resource_failed!(packets)
                    };

                    // Step 3: Decompress if compressed flag is set — hard fail
                    let plaintext = if is_compressed {
                        match self.hooks.as_ref().and_then(|h| h.decompress(&decrypted)) {
                            Some(d) => d,
                            None => resource_failed!(packets),
                        }
                    } else {
                        decrypted
                    };

                    // Step 4: Verify hash — stores plaintext in resource on success
                    if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash) {
                        if res.verify_hash(plaintext).is_err() {
                            resource_failed!(packets);
                        }
                    } else {
                        resource_failed!(packets);
                    }

                    // Step 5: Build proof from verified data
                    let (proof, plaintext) = if let Some(res) =
                        self.transport.get_resource_mut(&link_id, &resource_hash)
                    {
                        let proof = res.build_proof();
                        (proof, core::mem::take(&mut res.data))
                    } else {
                        resource_failed!(packets);
                    };

                    // Step 6: Send proof packet
                    if !proof.is_empty() {
                        let mut pkt_buf = [0u8; MTU];
                        if let Ok(pkt_len) = PacketBuilder::new(&mut pkt_buf)
                            .packet_type(PacketType::Proof)
                            .dest_type(DestType::Link)
                            .destination_hash(link_id.as_ref())
                            .context(rete_core::CONTEXT_RESOURCE_PRF)
                            .payload(&proof)
                            .build()
                        {
                            if let Ok(outbound) = self
                                .owned_link_outbound(&link_id, pkt_buf[..pkt_len].to_vec())
                            {
                                packets.push(outbound);
                            }
                        }
                    }

                    // Drain any resource outbound packets
                    packets.extend(self.drain_resource_outbound());
                    // Clean up completed receiver resource
                    self.transport.cleanup_resources();

                    // Step 7: Handle split resources
                    let mut oh_trunc = [0u8; TRUNCATED_HASH_LEN];
                    oh_trunc.copy_from_slice(&original_hash[..TRUNCATED_HASH_LEN]);

                    if split_total > 1 && split_index < split_total {
                        // Non-final split segment: buffer data, wait for next
                        if let Some(entry) = self
                            .split_recv_buf
                            .iter_mut()
                            .find(|e| e.link_id == link_id && e.original_hash == original_hash)
                        {
                            entry.data.extend_from_slice(&plaintext);
                        } else {
                            self.split_recv_buf.push(SplitRecvEntry {
                                link_id,
                                original_hash,
                                data: plaintext,
                            });
                        }
                        return IngestOutcome {
                            events: vec![NodeEvent::ResourceProgress {
                                link_id,
                                resource_hash: oh_trunc,
                                current: split_index,
                                total: split_total,
                            }],
                            packets,
                            rejection: None,
                        };
                    } else if split_total > 1 && split_index == split_total {
                        // Final split segment: concatenate all buffered data
                        let mut full_data = Vec::new();
                        if let Some(idx) = self
                            .split_recv_buf
                            .iter()
                            .position(|e| e.link_id == link_id && e.original_hash == original_hash)
                        {
                            let entry = self.split_recv_buf.swap_remove(idx);
                            full_data = entry.data;
                        }
                        full_data.extend_from_slice(&plaintext);
                        return IngestOutcome {
                            events: vec![NodeEvent::ResourceComplete {
                                link_id,
                                resource_hash: oh_trunc,
                                data: full_data,
                            }],
                            packets,
                            rejection: None,
                        };
                    }

                    // Non-split resource: deliver directly
                    // If this is a response-as-resource, parse and emit ResponseReceived
                    if is_response {
                        if let Ok((req_id, resp_data)) = rete_transport::parse_response(&plaintext)
                        {
                            self.pending_requests.retain(|request| {
                                request.link_id != link_id
                                    || request.request_id != req_id
                                    || request.status
                                        == super::request_receipt::RequestStatus::Prepared
                            });
                            return IngestOutcome {
                                events: vec![NodeEvent::ResponseReceived {
                                    link_id,
                                    request_id: req_id,
                                    data: resp_data,
                                }],
                                packets,
                                rejection: None,
                            };
                        }
                    }
                    // If this is a request-as-resource, parse and dispatch
                    if is_request {
                        if let Ok((requested_at, path_hash, request_data)) =
                            rete_transport::parse_request_data(&plaintext)
                        {
                            let request_id = rete_transport::request_id(&plaintext);
                            return match request_data {
                                rete_transport::RequestData::Bytes(req_data) => {
                                    let req_data = req_data.to_vec();
                                    let mut handler_packets = self.dispatch_request_handler(
                                        &link_id,
                                        &request_id,
                                        &path_hash,
                                        &req_data,
                                        requested_at,
                                        rng,
                                    );
                                    packets.append(&mut handler_packets);
                                    IngestOutcome {
                                        events: vec![NodeEvent::RequestReceived {
                                            link_id,
                                            request_id,
                                            path_hash,
                                            data: req_data,
                                        }],
                                        packets,
                                        rejection: None,
                                    }
                                }
                                rete_transport::RequestData::EncodedValue(value) => IngestOutcome {
                                    // TODO: let the parser return a validated range so this
                                    // can reuse the owned plaintext buffer without a copy.
                                    events: vec![NodeEvent::RequestValueReceived {
                                        link_id,
                                        request_id,
                                        path_hash,
                                        requested_at,
                                        value: value.to_vec(),
                                    }],
                                    packets,
                                    rejection: None,
                                },
                            };
                        } else {
                            // The advertisement identified this payload as a
                            // request. Malformed request data is terminal here
                            // and must not leak into generic resource consumers.
                            // Keep any proof/resource packets already produced.
                            return IngestOutcome {
                                events: Vec::new(),
                                packets,
                                rejection: None,
                            };
                        }
                    }
                    return IngestOutcome {
                        events: vec![NodeEvent::ResourceComplete {
                            link_id,
                            resource_hash,
                            data: plaintext,
                        }],
                        packets,
                        rejection: None,
                    };
                }
                // Not all parts received yet — drain resource outbound
                packets.extend(self.drain_resource_outbound());
                // Only send follow-up REQ when the entire window batch has
                // arrived (outstanding_parts == 0). Python does the same:
                // Resource.py line 886 checks `outstanding_parts == 0`.
                if current < total {
                    let window_complete = self
                        .transport
                        .get_resource(&link_id, &resource_hash)
                        .is_some_and(|r| r.is_window_complete());
                    if window_complete {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            res.grow_window(true); // assume fast link (localhost/TCP)
                        }
                        if let Some(req_pkt) =
                            self.transport
                                .build_followup_request(&link_id, &resource_hash, rng)
                        {
                            if let Ok(outbound) = self.owned_link_outbound(&link_id, req_pkt) {
                                packets.push(outbound);
                            }
                        }
                    }
                }
                let mut events = vec![NodeEvent::ResourceProgress {
                    link_id,
                    resource_hash,
                    current,
                    total,
                }];
                // Map response-resource progress to RequestProgress
                if let Some(req) = self.pending_requests.iter_mut().find(|r| {
                    r.link_id == link_id && r.response_resource_hash == Some(resource_hash)
                }) {
                    req.status = super::request_receipt::RequestStatus::Receiving;
                    events.push(NodeEvent::RequestProgress {
                        link_id,
                        request_id: req.request_id,
                        current,
                        total,
                    });
                }
                IngestOutcome {
                    events,
                    packets,
                    rejection: None,
                }
            }
            IngestResult::ResourceComplete {
                link_id,
                resource_hash,
                data,
            } => {
                // Sender received proof — transfer complete on our end
                self.transport.cleanup_resources();
                let packets = self.drain_resource_outbound();
                IngestOutcome {
                    events: vec![NodeEvent::ResourceComplete {
                        link_id,
                        resource_hash,
                        data,
                    }],
                    packets,
                    rejection: None,
                }
            }
            IngestResult::ResourceFailed {
                link_id,
                resource_hash,
            } => {
                self.transport.cleanup_resources();
                let packets = self.drain_resource_outbound();
                let mut events = vec![NodeEvent::ResourceFailed {
                    link_id,
                    resource_hash,
                }];
                // Map resource failure to RequestFailed (single pass for both response and request resources)
                self.pending_requests.retain(|r| {
                    if r.link_id == link_id
                        && (r.response_resource_hash == Some(resource_hash)
                            || r.request_resource_hash == Some(resource_hash))
                    {
                        events.push(NodeEvent::RequestFailed {
                            link_id,
                            request_id: r.request_id,
                            reason: RequestFailReason::ResourceFailed,
                        });
                        false
                    } else {
                        true
                    }
                });
                IngestOutcome {
                    events,
                    packets,
                    rejection: None,
                }
            }
            IngestResult::ResourceRejected {
                link_id,
                resource_hash,
            } => {
                self.transport.cleanup_resources();
                IngestOutcome {
                    events: vec![NodeEvent::ResourceRejected {
                        link_id,
                        resource_hash,
                    }],
                    packets: Vec::new(),
                    rejection: None,
                }
            }
            IngestResult::PathRequestForward { payload } => {
                // Forward path request to all interfaces as a broadcast
                // Build a path request packet from the payload
                let mut buf = [0u8; MTU];
                let result = PacketBuilder::new(&mut buf)
                    .packet_type(PacketType::Data)
                    .dest_type(DestType::Plain)
                    .destination_hash(PATH_REQUEST_DEST.as_ref())
                    .context(rete_core::CONTEXT_NONE)
                    .payload(&payload)
                    .build();
                match result {
                    Ok(n) => IngestOutcome {
                        events: vec![],
                        packets: vec![OutboundPacket::broadcast(buf[..n].to_vec())],
                        rejection: None,
                    },
                    Err(_) => IngestOutcome::empty(),
                }
            }
            IngestResult::ReverseTableFull { truncated_hash } => IngestOutcome::rejected(
                IngestRejection::ReverseTableFull { truncated_hash },
            ),
            IngestResult::ReverseRouteConflict { truncated_hash } => IngestOutcome::rejected(
                IngestRejection::ReverseRouteConflict { truncated_hash },
            ),
            IngestResult::LinkTableFull { link_id, table } => {
                // Preserve the pre-existing behavior of releasing unrelated
                // resource packets while exposing the Link admission failure.
                IngestOutcome {
                    events: vec![],
                    packets: self.drain_resource_outbound(),
                    rejection: Some(IngestRejection::LinkTableFull { link_id, table }),
                }
            }
            IngestResult::Duplicate | IngestResult::Invalid => {
                // Drain any resource outbound packets that may have been queued
                let resource_pkts = self.drain_resource_outbound();
                if resource_pkts.is_empty() {
                    IngestOutcome::empty()
                } else {
                    IngestOutcome {
                        events: vec![],
                        packets: resource_pkts,
                        rejection: None,
                    }
                }
            }
        }
    }

    /// Dispatch a request through the handler system.
    ///
    /// Reused for both single-packet requests and request-as-resource.
    /// Returns outbound response packets (empty if no handler or no response).
    fn dispatch_request_handler<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &LinkId,
        request_id: &RequestId,
        path_hash: &PathHash,
        data: &[u8],
        requested_at: f64,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let mut response_packets = Vec::new();
        let link_meta = self.transport.get_link(link_id).map(|link| {
            let mtu = rete_transport::link::decode_mtu(&link.signalling) as usize;
            let link_mdu = if mtu == 0 {
                rete_transport::link::LINK_MDU
            } else {
                rete_transport::link::compute_link_mdu(mtu)
            };
            (
                link.destination_hash,
                link.identified_identity_hash().copied(),
                link_mdu,
            )
        });
        if let Some((dest_hash, remote_identity, link_mdu)) = link_meta {
            if let Some(handler) = self.find_request_handler(&dest_hash, path_hash) {
                if handler.policy.allows(remote_identity.as_ref()) {
                    let ctx = super::RequestContext {
                        destination_hash: dest_hash,
                        path: &handler.path,
                        path_hash: *path_hash,
                        link_id: *link_id,
                        request_id: *request_id,
                        requested_at,
                        remote_identity,
                    };
                    if let Some(response_data) = handler.handler.handle(&ctx, data) {
                        let final_data = if handler
                            .compression_policy
                            .should_compress(response_data.len())
                        {
                            self.hooks
                                .as_ref()
                                .and_then(|h| h.compress(&response_data))
                                .filter(|c| c.len() < response_data.len())
                                .unwrap_or(response_data)
                        } else {
                            response_data
                        };
                        // Response framing: fixarray(2) + bin8 header(2) + request_id(16) + bin header(up to 3)
                        const RESPONSE_FRAMING_OVERHEAD: usize = 1 + 2 + TRUNCATED_HASH_LEN + 3;
                        if final_data.len() + RESPONSE_FRAMING_OVERHEAD <= link_mdu {
                            if let Ok(pkt) =
                                self.send_response(link_id, request_id, &final_data, rng)
                            {
                                response_packets.push(pkt);
                            }
                        } else {
                            if let Ok(pkt) =
                                self.start_response_resource(link_id, request_id, &final_data, rng)
                            {
                                response_packets.push(pkt);
                            }
                            response_packets.extend(self.drain_resource_outbound());
                        }
                    }
                }
            }
        }
        response_packets
    }

    fn prepare_tick_at<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        link_now: rete_core::MonotonicInstant,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let mut packets = self.flush_announces(now, rng);

        // Resource maintenance: send HMU for sender resources with unsent hashes
        self.transport.tick_resources(now, rng);

        // Drain any resource outbound packets queued during ingest or tick_resources
        packets.extend(self.drain_resource_outbound());

        // Send keepalives BEFORE tick — tick may mark links Stale, which would
        // prevent build_keepalive_packet from working (it requires Active state).
        // With dynamic keepalive on fast links, keepalive_interval can be as low
        // as 5s, which equals TICK_INTERVAL. Sending keepalives first ensures
        // they go out before the stale check.
        for link_id in self.transport.pending_keepalive_link_ids_at(link_now) {
            if let Ok(outbound) =
                self.build_owned_keepalive_outbound_at(&link_id, true, link_now)
            {
                packets.push(outbound);
            }
        }

        // Channel maintenance is discovered without mutation. Retry packet
        // construction and receipt replacement happen only after the Link's
        // authoritative route is known, and that route is carried directly
        // into the outbound packet.
        let actions = self.transport.pending_channel_maintenance(now);
        let mut retried_links = Vec::<LinkId>::new();
        if packets.try_reserve(actions.len()).is_err()
            || retried_links.try_reserve(actions.len()).is_err()
        {
            return packets;
        }
        for action in actions {
            match action {
                rete_transport::ChannelMaintenanceAction::Retransmit(pending) => {
                    let link_id = *pending.link_id();
                    let Ok(routing) = self.owned_link_routing(&link_id) else {
                        continue;
                    };
                    let shrink_window = !retried_links.contains(&link_id);
                    if let Ok(data) = self.transport.retry_channel_message(
                        pending,
                        now,
                        shrink_window,
                        rng,
                    ) {
                        if shrink_window {
                            retried_links.push(link_id);
                        }
                        packets.push(OutboundPacket::new(data, routing));
                    }
                }
                rete_transport::ChannelMaintenanceAction::Teardown(pending) => {
                    // Teardown emits no packet, so it does not depend on an
                    // interface route and must still reclaim an unbound Link.
                    self.transport.commit_channel_teardown(pending);
                }
            }
        }

        packets
    }

    /// Periodic maintenance with allocation-atomic receipt failures.
    ///
    /// DATA and Link DATA failure terminals are committed to `sink`; they are not
    /// also duplicated as [`NodeEvent::ReceiptFailed`] values. If the sink is
    /// full, affected receipts remain outstanding and
    /// [`ReceiptSinkTickOutcome::receipt_notifications_deferred`] is set.
    /// Channel receipt expiry remains internal and emits no failure terminal.
    pub fn handle_tick_with_receipt_sink<R, T>(
        &mut self,
        now: u64,
        rng: &mut R,
        sink: &mut T,
    ) -> ReceiptSinkTickOutcome
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        self.handle_tick_with_receipt_sink_at(
            now,
            rete_core::MonotonicInstant::from_secs(now),
            rng,
            sink,
        )
    }

    /// Precise Link-clock variant of [`Self::handle_tick_with_receipt_sink`].
    pub fn handle_tick_with_receipt_sink_at<R, T>(
        &mut self,
        now: u64,
        link_now: rete_core::MonotonicInstant,
        rng: &mut R,
        sink: &mut T,
    ) -> ReceiptSinkTickOutcome
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        let packets = self.prepare_tick_at(now, link_now, rng);
        let result = self
            .transport
            .tick_with_receipt_sink_at(now, link_now, sink);
        let mut events = self.check_request_timeouts(now);
        events.push(NodeEvent::Tick {
            expired_paths: result.expired_paths,
            closed_links: result.closed_links,
        });

        ReceiptSinkTickOutcome {
            outcome: IngestOutcome {
                events,
                packets,
                rejection: None,
            },
            failed_receipts: result.failed_receipts,
            failed_link_data_receipts: result.failed_link_data_receipts,
            receipt_notifications_deferred: result.receipt_notifications_deferred,
        }
    }

    /// Periodic maintenance: expire paths, collect pending announces, send keepalives.
    pub fn handle_tick<R: RngCore + CryptoRng>(&mut self, now: u64, rng: &mut R) -> IngestOutcome {
        self.handle_tick_at(now, rete_core::MonotonicInstant::from_secs(now), rng)
    }

    /// Precise Link-clock variant of [`Self::handle_tick`].
    pub fn handle_tick_at<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        link_now: rete_core::MonotonicInstant,
        rng: &mut R,
    ) -> IngestOutcome {
        let packets = self.prepare_tick_at(now, link_now, rng);

        // Now run tick: expire paths, check stale links, etc.
        let result = self.transport.tick_at(now, link_now);

        // Check request timeouts
        let mut events = self.check_request_timeouts(now);

        for packet_hash in result.failed_receipts {
            events.push(NodeEvent::ReceiptFailed { packet_hash });
        }
        for packet_hash in result.failed_link_data_receipts {
            events.push(NodeEvent::ReceiptFailed { packet_hash });
        }

        events.push(NodeEvent::Tick {
            expired_paths: result.expired_paths,
            closed_links: result.closed_links,
        });

        IngestOutcome {
            events,
            packets,
            rejection: None,
        }
    }

    /// Check pending requests for timeout and return timeout events.
    fn check_request_timeouts(&mut self, now: u64) -> Vec<NodeEvent> {
        use super::request_receipt::RequestStatus;

        let mut events = Vec::new();
        self.pending_requests.retain(|req| {
            if matches!(req.status, RequestStatus::Sent | RequestStatus::Receiving)
                && now.saturating_sub(req.sent_at) > req.timeout_secs
            {
                events.push(NodeEvent::RequestFailed {
                    link_id: req.link_id,
                    request_id: req.request_id,
                    reason: RequestFailReason::Timeout,
                });
                false // remove timed-out request
            } else {
                true
            }
        });
        events
    }
}
