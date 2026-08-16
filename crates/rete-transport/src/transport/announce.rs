//! Announce queue, handling, rate limiting, path requests.

use crate::announce::{validate_announce, PendingAnnounce, PendingOutboundAnnounce};
use crate::path::Path;
use crate::storage::{StorageDeque, StorageMap};
use rete_core::{
    CONTEXT_PATH_RESPONSE, DestHash, DestType, HeaderType, Identity, IdentityHash, Packet,
    PacketBuilder, PacketType, NAME_HASH_LEN, TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    AnnounceRateEntry, IngestResult, ANNOUNCE_RATE_GRACE, ANNOUNCE_RATE_PENALTY,
    ANNOUNCE_RATE_TARGET, LOCAL_REBROADCASTS_MAX, PATH_REQUEST_DEST, PATH_REQUEST_GRACE,
    PATHFINDER_G, PATHFINDER_M, PATHFINDER_R, PATHFINDER_RW_MS, Transport,
};

struct ParsedPathRequest<'a> {
    destination: DestHash,
    requester_transport_id: Option<IdentityHash>,
    tag: &'a [u8],
}

enum PathResponseQueueAdmission {
    Queued,
    Replaced,
    Full,
}

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Queue an announce for transmission. Returns `false` if queue is full.
    pub fn queue_announce(&mut self, ann: PendingAnnounce) -> bool {
        self.announces.push_back(ann).is_ok()
    }

    /// Pop the next announce ready for transmission.
    pub fn next_announce(&mut self) -> Option<PendingAnnounce> {
        self.announces.pop_front()
    }

    /// Number of pending announces.
    pub fn announce_count(&self) -> usize {
        self.announces.len()
    }

    /// Clear all pending announces from the queue.
    pub fn clear_announces(&mut self) {
        self.announces.clear();
    }

    pub(super) fn handle_announce<'a>(
        &mut self,
        pkt: &Packet<'a>,
        raw: &'a [u8],
        now: u64,
        iface: u8,
    ) -> IngestResult<'a> {
        // Self-announce filtering
        let dh_check = DestHash::from_slice(pkt.destination_hash);
        if self.is_local_destination(&dh_check) {
            return IngestResult::Duplicate;
        }

        match validate_announce(pkt.destination_hash, pkt.payload, pkt.context_flag) {
            Ok(info) => {
                // Announce replay detection
                let mut replay_key = [0u8; 32];
                replay_key[..TRUNCATED_HASH_LEN].copy_from_slice(pkt.destination_hash);
                replay_key[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN + 10]
                    .copy_from_slice(info.random_hash);
                let replay_hash: [u8; 32] = Sha256::digest(replay_key).into();
                let restores_missing_path = self.paths.get(&dh_check).is_none();
                if self.announce_dedup.check_and_insert(&replay_hash)
                    && !restores_missing_path
                {
                    // Track local rebroadcasts: if we have this announce
                    // pending, note that we heard it echoed back.
                    self.note_local_rebroadcast(&dh_check, pkt.hops);
                    self.stats.packets_dropped_dedup += 1;
                    return IngestResult::Duplicate;
                }
                let dh = dh_check;

                // Announce rate limiting (disabled when ANNOUNCE_RATE_TARGET == 0,
                // matching Python RNS default which only rate-limits when
                // explicitly configured per-interface).
                let rate_blocked = if ANNOUNCE_RATE_TARGET == 0 {
                    false
                } else {
                    let entry = self.announce_rate.get_mut(&dh);
                    match entry {
                        Some(re) => {
                            if now < re.blocked_until {
                                true
                            } else {
                                let interval = now.saturating_sub(re.last);
                                if interval < ANNOUNCE_RATE_TARGET {
                                    re.violations = re.violations.saturating_add(1);
                                } else {
                                    re.violations = re.violations.saturating_sub(1);
                                }
                                if re.violations > ANNOUNCE_RATE_GRACE {
                                    re.blocked_until =
                                        re.last + ANNOUNCE_RATE_TARGET + ANNOUNCE_RATE_PENALTY;
                                    true
                                } else {
                                    re.last = now;
                                    false
                                }
                            }
                        }
                        None => {
                            let _ = self.announce_rate.insert(
                                dh,
                                AnnounceRateEntry {
                                    last: now,
                                    violations: 0,
                                    blocked_until: 0,
                                },
                            );
                            false
                        }
                    }
                };
                if rate_blocked {
                    #[cfg(feature = "relay-debug")]
                    tracing::trace!(
                        "[relay] RATE_LIMITED dest={}",
                        super::hex_short(dh.as_ref()),
                    );
                    self.stats.announces_rate_limited += 1;
                    return IngestResult::Duplicate;
                }

                let should_update = match self.paths.get(&dh) {
                    None => true,
                    Some(existing) => {
                        pkt.hops <= existing.hops
                            || now.saturating_sub(existing.learned_at) > existing.expiry_time()
                    }
                };

                // Build the retransmit version first — in transport mode this
                // is a HEADER_2 with our own identity as transport_id, replacing
                // any upstream transport_id.  We also use it as the cached
                // announce_raw so that path-request responses point back through
                // us (not through an upstream relay the requester can't reach).
                let retransmit_raw = if pkt.hops < PATHFINDER_M {
                    if let Some(local_id) = self.local_identity_hash {
                        let mut rebuild_buf = [0u8; rete_core::MTU];
                        let result = PacketBuilder::new(&mut rebuild_buf)
                            .header_type(HeaderType::Header2)
                            .transport_type(TRANSPORT_TYPE_TRANSPORT)
                            .packet_type(pkt.packet_type)
                            .dest_type(pkt.dest_type)
                            .context_flag(pkt.context_flag)
                            .hops(pkt.hops)
                            .transport_id(local_id.as_ref())
                            .destination_hash(pkt.destination_hash)
                            .context(pkt.context)
                            .payload(pkt.payload)
                            .build();
                        match result {
                            Ok(n) => Some(rebuild_buf[..n].to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if should_update {
                    let mut path = match pkt.transport_id {
                        Some(tid) => {
                            Path::via_repeater(IdentityHash::from_slice(tid), pkt.hops, now)
                        }
                        None => Path {
                            hops: pkt.hops,
                            ..Path::direct(now)
                        },
                    };
                    // Cache the retransmit version (our H2) so path-request
                    // responses identify us as the relay, not the upstream node.
                    // Fall back to the original raw bytes when not in transport
                    // mode or when the rebuild failed.
                    path.announce_raw = crate::path::AnnounceCache::store(
                        retransmit_raw.as_deref().unwrap_or(raw),
                    );
                    path.received_on = Some(iface);
                    let _ = self.insert_path(dh, path);
                    self.stats.paths_learned += 1;
                }

                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                self.insert_identity(dh, pk);

                // Released Python Reticulum only schedules received announces
                // for rebroadcast when transport is enabled (or when bridging
                // a local shared-instance client, which this core does not yet
                // model). Endpoint nodes still learn and cache the path, but
                // must not become announce relays implicitly.
                if self.local_identity_hash.is_some()
                    && pkt.context != CONTEXT_PATH_RESPONSE
                    && pkt.hops < PATHFINDER_M
                {
                    let ann_raw = match retransmit_raw {
                        Some(v) => v,
                        None => raw.to_vec(),
                    };

                    if !ann_raw.is_empty() {
                        let pending = PendingAnnounce {
                            dest_hash: dh,
                            raw: ann_raw,
                            tx_count: 0,
                            retransmit_timeout: now, // Forward immediately; PATHFINDER_G applies to retransmissions
                            local: false,
                            local_rebroadcasts: 0,
                            block_rebroadcasts: false,
                            received_hops: pkt.hops,
                            attached_interface: None,
                        };
                        let _ = self.queue_announce(pending);
                    }
                }

                let ratchet: Option<[u8; 32]> =
                    info.ratchet.and_then(|r| r.try_into().ok());

                self.stats.announces_received += 1;
                IngestResult::AnnounceReceived {
                    dest_hash: dh,
                    identity_hash: info.identity_hash,
                    hops: pkt.hops,
                    app_data: info.app_data,
                    ratchet,
                }
            }
            Err(_) => {
                self.stats.packets_dropped_invalid += 1;
                self.stats.crypto_failures += 1;
                IngestResult::Invalid
            }
        }
    }

    pub(super) fn handle_path_request<'a>(
        &mut self,
        payload: &[u8],
        now: u64,
        received_on: u8,
    ) -> IngestResult<'a> {
        let Some(request) = parse_path_request(payload) else {
            // Python ignores tagless path requests. They are structurally
            // parseable DATA, but cannot participate in discovery deduplication.
            return IngestResult::Duplicate;
        };
        let requested = request.destination;

        // Python deduplicates exactly destination+tag before local, cached or
        // recursive handling. Requester transport identity is deliberately not
        // part of the key.
        let mut hasher = Sha256::new();
        hasher.update(requested.as_ref());
        hasher.update(request.tag);
        let request_hash: [u8; 32] = hasher.finalize().into();
        if self.path_request_dedup.check_and_insert(&request_hash) {
            self.stats.packets_dropped_dedup += 1;
            return IngestResult::Duplicate;
        }

        // Check if we have a local destination for this hash
        if self.is_local_destination(&requested) {
            // Local destination — handled by NodeCore (it will announce in response)
            return IngestResult::PathRequestForward {
                payload: self.rebuild_recursive_path_request(&request),
            };
        }

        // Check if we know a path (have a cached announce)
        let known_response = self.paths.get(&requested).and_then(|path| {
            let requester_is_next_hop = request
                .requester_transport_id
                .is_some_and(|requester| path.via == Some(requester));
            (!requester_is_next_hop)
                .then(|| path.announce_raw.as_ref().map(|raw| raw.to_vec()))
                .flatten()
        });
        if let Some(cached) = known_response {
            let pending = PendingAnnounce {
                dest_hash: requested,
                raw: cached,
                tx_count: 0,
                retransmit_timeout: now + PATH_REQUEST_GRACE,
                local: false,
                local_rebroadcasts: 0,
                block_rebroadcasts: true,
                received_hops: 0,
                attached_interface: Some(received_on),
            };
            return match self.queue_path_response(pending) {
                PathResponseQueueAdmission::Queued | PathResponseQueueAdmission::Replaced => {
                    IngestResult::Duplicate
                }
                PathResponseQueueAdmission::Full => {
                    IngestResult::PathResponseQueueFull { dest_hash: requested }
                }
            };
        }
        // A retained path that cannot answer (requester is our next hop or no
        // cached signed announce remains) is still known. Python consumes the
        // request instead of recursively searching behind that path.
        if self.paths.get(&requested).is_some() {
            return IngestResult::Duplicate;
        }

        // Unknown path — forward to all interfaces if transport is enabled
        if self.local_identity_hash.is_some() {
            IngestResult::PathRequestForward {
                payload: self.rebuild_recursive_path_request(&request),
            }
        } else {
            IngestResult::Duplicate
        }
    }

    fn rebuild_recursive_path_request(
        &self,
        request: &ParsedPathRequest<'_>,
    ) -> alloc::vec::Vec<u8> {
        let mut payload = alloc::vec::Vec::with_capacity(TRUNCATED_HASH_LEN * 3);
        payload.extend_from_slice(request.destination.as_ref());
        if let Some(local_identity) = self.local_identity_hash {
            payload.extend_from_slice(local_identity.as_ref());
        }
        payload.extend_from_slice(request.tag);
        payload
    }

    fn queue_path_response(&mut self, response: PendingAnnounce) -> PathResponseQueueAdmission {
        if let Some(existing) = self
            .announces
            .iter_mut()
            .find(|pending| pending.dest_hash == response.dest_hash && pending.block_rebroadcasts)
        {
            *existing = response;
            return PathResponseQueueAdmission::Replaced;
        }
        if self.announces.push_back(response).is_ok() {
            PathResponseQueueAdmission::Queued
        } else {
            PathResponseQueueAdmission::Full
        }
    }

    // -----------------------------------------------------------------------
    // Path request origination
    // -----------------------------------------------------------------------

    /// Build a tagged path request packet for a destination.
    ///
    /// Transport nodes supply their identity so the payload is destination,
    /// requester transport identity and a fresh 16-byte tag. Endpoints pass
    /// `None` and emit destination plus tag.
    pub fn build_path_request<R: RngCore>(
        dest_hash: &DestHash,
        requester_transport_id: Option<IdentityHash>,
        rng: &mut R,
    ) -> alloc::vec::Vec<u8> {
        let mut payload = [0_u8; TRUNCATED_HASH_LEN * 3];
        payload[..TRUNCATED_HASH_LEN].copy_from_slice(dest_hash.as_ref());
        let tag_start = if let Some(requester) = requester_transport_id {
            payload[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN * 2]
                .copy_from_slice(requester.as_ref());
            TRUNCATED_HASH_LEN * 2
        } else {
            TRUNCATED_HASH_LEN
        };
        rng.fill_bytes(&mut payload[tag_start..tag_start + TRUNCATED_HASH_LEN]);
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Plain)
            .destination_hash(PATH_REQUEST_DEST.as_ref())
            .context(0x00)
            .payload(&payload[..tag_start + TRUNCATED_HASH_LEN])
            .build()
            .expect("path request packet should always build");
        buf[..n].to_vec()
    }

    // -----------------------------------------------------------------------
    // Announce creation
    // -----------------------------------------------------------------------

    /// Create an announce packet for a local identity.
    ///
    /// When `ratchet_pub` is `Some`, the 32-byte ratchet public key is included
    /// in the announce payload and `context_flag` is set to 1.
    pub fn create_announce<R: RngCore + CryptoRng>(
        identity: &Identity,
        app_name: &str,
        aspects: &[&str],
        app_data: Option<&[u8]>,
        ratchet_pub: Option<&[u8; 32]>,
        rng: &mut R,
        now: u64,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;

        let identity_hash = identity.hash();
        let (dest_hash, name_hash) =
            rete_core::destination_hashes(expanded, Some(&identity_hash));

        let mut random_hash = [0u8; 10];
        rng.fill_bytes(&mut random_hash[..5]);
        random_hash[5..10].copy_from_slice(&now.to_be_bytes()[3..8]);

        let pub_key = identity.public_key();
        let mut signed_data = [0u8; rete_core::MTU];
        let mut pos = 0;
        signed_data[pos..pos + TRUNCATED_HASH_LEN].copy_from_slice(dest_hash.as_ref());
        pos += TRUNCATED_HASH_LEN;
        signed_data[pos..pos + 64].copy_from_slice(&pub_key);
        pos += 64;
        signed_data[pos..pos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        pos += NAME_HASH_LEN;
        signed_data[pos..pos + 10].copy_from_slice(&random_hash);
        pos += 10;
        if let Some(rp) = ratchet_pub {
            signed_data[pos..pos + 32].copy_from_slice(rp);
            pos += 32;
        }
        if let Some(ad) = app_data {
            signed_data[pos..pos + ad.len()].copy_from_slice(ad);
            pos += ad.len();
        }

        let signature = identity.sign(&signed_data[..pos])?;

        // Payload layout:
        //   pub_key[64] + name_hash[10] + random_hash[10]
        //   [+ ratchet[32] if context_flag]
        //   + signature[64] + [app_data]
        let mut payload = [0u8; rete_core::MTU];
        let mut ppos = 0;
        payload[ppos..ppos + 64].copy_from_slice(&pub_key);
        ppos += 64;
        payload[ppos..ppos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        ppos += NAME_HASH_LEN;
        payload[ppos..ppos + 10].copy_from_slice(&random_hash);
        ppos += 10;
        if let Some(rp) = ratchet_pub {
            payload[ppos..ppos + 32].copy_from_slice(rp);
            ppos += 32;
        }
        payload[ppos..ppos + 64].copy_from_slice(&signature);
        ppos += 64;
        if let Some(ad) = app_data {
            payload[ppos..ppos + ad.len()].copy_from_slice(ad);
            ppos += ad.len();
        }

        let n = PacketBuilder::new(out)
            .packet_type(PacketType::Announce)
            .dest_type(DestType::Single)
            .context_flag(ratchet_pub.is_some())
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&payload[..ppos])
            .build()?;

        Ok(n)
    }

    /// Returns announces that are due for retransmission.
    ///
    /// Python adds `random.random() * PATHFINDER_RW` (0-0.5s) of jitter to
    /// each retransmit timeout to prevent synchronized retransmissions on
    /// shared radio channels.
    pub fn pending_outbound<R: RngCore>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<PendingOutboundAnnounce> {
        let mut to_send: alloc::vec::Vec<PendingOutboundAnnounce> = alloc::vec::Vec::new();
        let mut old = core::mem::take(&mut self.announces);

        while let Some(mut ann) = old.pop_front() {
            // Skip if blocked by local rebroadcast detection
            if ann.block_rebroadcasts && !ann.local && ann.tx_count > 0 {
                continue;
            }
            if ann.local || now >= ann.retransmit_timeout {
                let raw = if ann.block_rebroadcasts {
                    let Some(response) = mark_path_response(&ann.raw) else {
                        // A malformed retained announce must fail closed rather
                        // than escaping as an ordinary rebroadcast.
                        continue;
                    };
                    response
                } else {
                    ann.raw.clone()
                };
                to_send.push(PendingOutboundAnnounce {
                    raw,
                    attached_interface: ann.attached_interface,
                });
                if ann.tx_count == 0 {
                    self.stats.announces_sent += 1;
                } else {
                    self.stats.announces_retransmitted += 1;
                }
                self.stats.packets_sent += 1;
                ann.tx_count += 1;
                let jitter_ms = (rng.next_u32() % PATHFINDER_RW_MS as u32) as u64;
                let jitter_secs = if jitter_ms >= 500 { 1 } else { 0 };
                ann.retransmit_timeout = now + PATHFINDER_G + jitter_secs;
                debug_assert!(ann.retransmit_timeout > now);
                ann.local = false;
                if ann.tx_count <= PATHFINDER_R && !ann.block_rebroadcasts {
                    let _ = self.announces.push_back(ann);
                }
            } else {
                let _ = self.announces.push_back(ann);
            }
        }

        to_send
    }

    /// Called when we hear a duplicate announce — tracks local rebroadcasts
    /// and suppresses retransmission if the announce has been locally rebroadcast
    /// enough times (LOCAL_REBROADCASTS_MAX).
    pub fn note_local_rebroadcast(&mut self, dest_hash: &DestHash, heard_hops: u8) {
        for ann in self.announces.iter_mut() {
            if ann.dest_hash == *dest_hash {
                // Same hop count means a peer rebroadcast at our level
                if heard_hops.saturating_sub(1) == ann.received_hops {
                    ann.local_rebroadcasts += 1;
                    if ann.tx_count > 0 && ann.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        ann.block_rebroadcasts = true;
                    }
                }
                // If we hear at one hop further, our rebroadcast was picked up
                if heard_hops.saturating_sub(1) == ann.received_hops + 1 && ann.tx_count > 0 {
                    ann.block_rebroadcasts = true;
                }
                break;
            }
        }
    }
}

/// Mark one validated cached announce as a path response without changing its
/// signed payload, flags, hop count, or HEADER_2 transport identity.
fn mark_path_response(raw: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let packet = Packet::parse(raw).ok()?;
    if packet.packet_type != PacketType::Announce || packet.dest_type != DestType::Single {
        return None;
    }
    let context_offset = match packet.header_type {
        HeaderType::Header1 => 2 + TRUNCATED_HASH_LEN,
        HeaderType::Header2 => 2 + (2 * TRUNCATED_HASH_LEN),
    };
    let mut response = raw.to_vec();
    response[context_offset] = CONTEXT_PATH_RESPONSE;
    Some(response)
}

fn parse_path_request(payload: &[u8]) -> Option<ParsedPathRequest<'_>> {
    let destination_bytes = payload.get(..TRUNCATED_HASH_LEN)?;
    let (requester_transport_id, tag_start) = if payload.len() > TRUNCATED_HASH_LEN * 2 {
        (
            Some(IdentityHash::from_slice(
                payload.get(TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN * 2)?,
            )),
            TRUNCATED_HASH_LEN * 2,
        )
    } else {
        (None, TRUNCATED_HASH_LEN)
    };
    let tag = payload.get(tag_start..)?;
    if tag.is_empty() {
        return None;
    }
    Some(ParsedPathRequest {
        destination: DestHash::from_slice(destination_bytes),
        requester_transport_id,
        tag: &tag[..core::cmp::min(tag.len(), TRUNCATED_HASH_LEN)],
    })
}
