//! Path request handling regressions for the local Rete overlay.

use rete_core::{
    CONTEXT_NONE, CONTEXT_PATH_RESPONSE, DestHash, DestType, HeaderType, Identity, IdentityHash,
    MTU, Packet, PacketBuilder, PacketType, TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use rete_transport::{AnnounceCache, IngestResult, Path, PendingAnnounce, Transport, PATH_REQUEST_DEST};

/// Small transport suitable for tests.
type TestTransport = Transport<rete_transport::HeaplessStorage<64, 16, 128, 4>>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_path_request(requested_dest: &DestHash) -> Vec<u8> {
    TestTransport::build_path_request(requested_dest, None, &mut rand::thread_rng())
}

fn tagged_path_request(
    destination: &DestHash,
    requester: Option<IdentityHash>,
    tag: &[u8],
    hops: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(destination.as_ref());
    if let Some(requester) = requester {
        payload.extend_from_slice(requester.as_ref());
    }
    payload.extend_from_slice(tag);
    let mut raw = [0_u8; MTU];
    let length = PacketBuilder::new(&mut raw)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Plain)
        .hops(hops)
        .destination_hash(PATH_REQUEST_DEST.as_ref())
        .context(CONTEXT_NONE)
        .payload(&payload)
        .build()
        .unwrap();
    raw[..length].to_vec()
}

fn as_h2_path_response(
    announce: &[u8],
    transport_id: IdentityHash,
) -> Vec<u8> {
    let announce = Packet::parse(announce).unwrap();
    let mut raw = [0_u8; MTU];
    let length = PacketBuilder::new(&mut raw)
        .header_type(HeaderType::Header2)
        .transport_type(TRANSPORT_TYPE_TRANSPORT)
        .packet_type(PacketType::Announce)
        .dest_type(DestType::Single)
        .context_flag(announce.context_flag)
        .hops(announce.hops)
        .transport_id(transport_id.as_ref())
        .destination_hash(announce.destination_hash)
        .context(CONTEXT_PATH_RESPONSE)
        .payload(announce.payload)
        .build()
        .unwrap();
    raw[..length].to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn path_request_dest_hash_matches_python() {
    // Precomputed: destination_hash("rnstransport.path.request", None)
    let computed = rete_core::destination_hash("rnstransport.path.request", None);
    assert_eq!(
        computed, PATH_REQUEST_DEST,
        "PATH_REQUEST_DEST must match Python destination_hash('rnstransport.path.request', None)"
    );
}

#[test]
fn path_request_known_dest_queues_announce() {
    let mut t = TestTransport::new();
    let relay_identity = IdentityHash::from([0x11; TRUNCATED_HASH_LEN]);
    t.set_local_identity(relay_identity); // enable transport mode

    // Create an announcer and ingest their announce (to populate path + cached announce)
    let announcer = Identity::from_seed(b"path-req-announcer").unwrap();
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; MTU];
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let ratchet = [0x44; 32];
    let n = TestTransport::create_announce(
        &announcer,
        "testapp",
        &["aspect1"],
        Some(b"cached path response"),
        Some(&ratchet),
        &mut rng,
        1000,
        &mut buf,
    )
    .unwrap();

    let mut ann = buf[..n].to_vec();
    match t.ingest(&mut ann, 1000, &mut rng, &identity) {
        IngestResult::AnnounceReceived { dest_hash, .. } => {
            // Drain the retransmit announce from normal announce processing
            // First call sends (tx_count 0→1) at retransmit_timeout (1000+5=1005)
            let _ = t.pending_outbound(1006, &mut rng);
            // Second call sends (tx_count 1→2) and drops (tx_count > PATHFINDER_R)
            let _ = t.pending_outbound(1012, &mut rng);
            let count_before = t.announce_count();
            assert_eq!(count_before, 0, "queue should be drained");

            // Now send a path request for this dest
            let mut req = build_path_request(&dest_hash);
            match t.ingest_on(&mut req, 1020, 7, &mut rng, &identity) {
                IngestResult::Duplicate => {} // consumed by path request handler
                other => panic!("expected Duplicate (consumed), got {:?}", other),
            }

            assert_eq!(
                t.announce_count(),
                1,
                "path request should queue the cached announce"
            );
            assert!(
                t.pending_outbound(1020, &mut rng).is_empty(),
                "the cached response observes path-request grace"
            );
            let response = t.pending_outbound(1021, &mut rng);
            assert_eq!(response.len(), 1);
            assert_eq!(response[0].attached_interface, Some(7));
            let learned_announce = Packet::parse(&ann).unwrap();
            let response_packet = Packet::parse(&response[0].raw).unwrap();
            assert_eq!(response_packet.header_type, HeaderType::Header2);
            assert_eq!(response_packet.packet_type, PacketType::Announce);
            assert_eq!(response_packet.dest_type, DestType::Single);
            assert_eq!(response_packet.context, CONTEXT_PATH_RESPONSE);
            assert_eq!(response_packet.transport_id, Some(relay_identity.as_ref()));
            assert_eq!(response_packet.destination_hash, dest_hash.as_ref());
            assert_eq!(response_packet.hops, learned_announce.hops);
            assert_eq!(response_packet.context_flag, learned_announce.context_flag);
            assert_eq!(response_packet.payload, learned_announce.payload);
            assert_eq!(t.announce_count(), 0, "a path response transmits once");

            let mut independent_request = build_path_request(&dest_hash);
            match t.ingest_on(&mut independent_request, 1021, 8, &mut rng, &identity) {
                IngestResult::Duplicate => {}
                other => panic!("expected cached request on another interface, got {other:?}"),
            }
            assert_eq!(
                t.announce_count(),
                1,
                "a fresh tagged cached request replaces the source-bound response"
            );
            assert!(t.pending_outbound(1021, &mut rng).is_empty());
            let independent_response = t.pending_outbound(1022, &mut rng);
            assert_eq!(independent_response.len(), 1);
            assert_eq!(independent_response[0].attached_interface, Some(8));
            assert_eq!(
                Packet::parse(&independent_response[0].raw).unwrap().context,
                CONTEXT_PATH_RESPONSE
            );

            let mut second_relay = TestTransport::new();
            second_relay.set_local_identity(IdentityHash::from([0x22; TRUNCATED_HASH_LEN]));
            let mut response_raw = response[0].raw.clone();
            match second_relay.ingest_on(&mut response_raw, 1021, 9, &mut rng, &identity) {
                IngestResult::AnnounceReceived {
                    dest_hash: learned, ..
                } => assert_eq!(learned, dest_hash),
                other => panic!("expected second relay to learn path response, got {other:?}"),
            }
            assert!(second_relay.get_path(&dest_hash).is_some());
            assert_eq!(
                second_relay.announce_count(),
                0,
                "a PATH_RESPONSE must not enter the second relay announce queue"
            );
            assert!(second_relay.pending_outbound(1030, &mut rng).is_empty());
        }
        other => panic!("expected AnnounceReceived, got {:?}", other),
    }
}

#[test]
fn path_request_unknown_dest_no_response() {
    let mut t = TestTransport::new();
    t.set_local_identity(IdentityHash::from([0x11; TRUNCATED_HASH_LEN]));

    let identity = Identity::from_seed(b"test-identity").unwrap();
    let mut rng = rand::thread_rng();
    let unknown = DestHash::from([0xFF; TRUNCATED_HASH_LEN]);
    let mut req = build_path_request(&unknown);
    let _ = t.ingest(&mut req, 1000, &mut rng, &identity);

    assert_eq!(
        t.announce_count(),
        0,
        "unknown dest should not queue any announce"
    );
}

#[test]
fn path_request_ignored_without_transport() {
    let mut t = TestTransport::new();
    // No transport mode — no set_local_identity()
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let mut rng = rand::thread_rng();

    // Path request on a non-transport node is dropped (PATH_REQUEST_DEST
    // is not a local destination and there's no path to forward to).
    let requested = DestHash::from([0xAA; TRUNCATED_HASH_LEN]);
    let mut req = build_path_request(&requested);
    match t.ingest(&mut req, 1000, &mut rng, &identity) {
        IngestResult::Invalid => {} // non-transport nodes drop path requests
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn cached_announce_stored_on_path_learn() {
    let mut t = TestTransport::new();
    let announcer = Identity::from_seed(b"cached-announce-test").unwrap();
    let mut rng = rand::thread_rng();

    let mut buf = [0u8; MTU];
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let n = TestTransport::create_announce(
        &announcer,
        "testapp",
        &["aspect1"],
        None,
        None,
        &mut rng,
        1000,
        &mut buf,
    )
    .unwrap();

    let mut ann = buf[..n].to_vec();
    match t.ingest(&mut ann, 1000, &mut rng, &identity) {
        IngestResult::AnnounceReceived { dest_hash, .. } => {
            let path = t.get_path(&dest_hash).expect("path should exist");
            assert!(
                path.announce_raw.is_some(),
                "path should have cached announce"
            );
        }
        other => panic!("expected AnnounceReceived, got {:?}", other),
    }
}

#[test]
fn path_request_parses_endpoint_and_transport_tags_and_rebuilds_relay_identity() {
    let relay_id = IdentityHash::from([0x31; TRUNCATED_HASH_LEN]);
    let mut transport = TestTransport::new();
    transport.set_local_identity(relay_id);
    let identity = Identity::from_seed(b"path-tag-parser").unwrap();
    let destination = DestHash::from([0x51; TRUNCATED_HASH_LEN]);
    let mut rng = rand::thread_rng();

    let endpoint_tag = [0xa1; 7];
    let mut endpoint = tagged_path_request(&destination, None, &endpoint_tag, 0);
    let IngestResult::PathRequestForward { payload } =
        transport.ingest_on(&mut endpoint, 10, 1, &mut rng, &identity)
    else {
        panic!("fresh endpoint request must recurse")
    };
    assert_eq!(&payload[..TRUNCATED_HASH_LEN], destination.as_ref());
    assert_eq!(
        &payload[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN * 2],
        relay_id.as_ref()
    );
    assert_eq!(&payload[TRUNCATED_HASH_LEN * 2..], &endpoint_tag);

    let requester = IdentityHash::from([0x61; TRUNCATED_HASH_LEN]);
    let first_transport_tag = [0xb1; TRUNCATED_HASH_LEN];
    let mut first = tagged_path_request(
        &destination,
        Some(requester),
        &first_transport_tag,
        0,
    );
    assert!(matches!(
        transport.ingest_on(&mut first, 11, 2, &mut rng, &identity),
        IngestResult::PathRequestForward { .. }
    ));

    let second_transport_tag = [0xb2; TRUNCATED_HASH_LEN];
    let mut second = tagged_path_request(
        &destination,
        Some(requester),
        &second_transport_tag,
        0,
    );
    assert!(matches!(
        transport.ingest_on(&mut second, 12, 2, &mut rng, &identity),
        IngestResult::PathRequestForward { .. }
    ));

    let different_requester = IdentityHash::from([0x62; TRUNCATED_HASH_LEN]);
    let mut duplicate_tag = tagged_path_request(
        &destination,
        Some(different_requester),
        &second_transport_tag,
        0,
    );
    assert!(matches!(
        transport.ingest_on(&mut duplicate_tag, 13, 3, &mut rng, &identity),
        IngestResult::Duplicate
    ));
}

#[test]
fn tagless_and_overheight_path_requests_do_not_poison_fresh_tag_admission() {
    let mut transport = TestTransport::new();
    transport.set_local_identity(IdentityHash::from([0x32; TRUNCATED_HASH_LEN]));
    let identity = Identity::from_seed(b"path-shape-gates").unwrap();
    let destination = DestHash::from([0x52; TRUNCATED_HASH_LEN]);
    let tag = [0xc1; TRUNCATED_HASH_LEN];
    let mut rng = rand::thread_rng();

    let mut tagless = tagged_path_request(&destination, None, &[], 0);
    assert!(matches!(
        transport.ingest_on(&mut tagless, 20, 1, &mut rng, &identity),
        IngestResult::Duplicate
    ));

    let invalid_before = transport.stats().packets_dropped_invalid;
    let mut overheight = tagged_path_request(&destination, None, &tag, 1);
    assert!(matches!(
        transport.ingest_on(&mut overheight, 21, 1, &mut rng, &identity),
        IngestResult::Invalid
    ));
    assert_eq!(
        transport.stats().packets_dropped_invalid,
        invalid_before + 1
    );

    let mut valid = tagged_path_request(&destination, None, &tag, 0);
    assert!(matches!(
        transport.ingest_on(&mut valid, 22, 1, &mut rng, &identity),
        IngestResult::PathRequestForward { .. }
    ));
}

#[test]
fn cached_response_is_suppressed_when_requester_is_the_known_next_hop() {
    let mut transport = TestTransport::new();
    transport.set_local_identity(IdentityHash::from([0x33; TRUNCATED_HASH_LEN]));
    let next_hop = IdentityHash::from([0x63; TRUNCATED_HASH_LEN]);
    let destination = DestHash::from([0x53; TRUNCATED_HASH_LEN]);
    let mut path = Path::via_repeater(next_hop, 2, 30);
    path.announce_raw = AnnounceCache::store(&[0x00]);
    transport.insert_path(destination, path);
    let identity = Identity::from_seed(b"path-next-hop-guard").unwrap();
    let mut rng = rand::thread_rng();
    let mut request = tagged_path_request(
        &destination,
        Some(next_hop),
        &[0xd1; TRUNCATED_HASH_LEN],
        0,
    );

    assert!(matches!(
        transport.ingest_on(&mut request, 31, 4, &mut rng, &identity),
        IngestResult::Duplicate
    ));
    assert_eq!(transport.announce_count(), 0);
}

#[test]
fn repeated_signed_announce_restores_missing_route_for_ordinary_and_path_response() {
    let announcer = Identity::from_seed(b"repeat-announce-restoration").unwrap();
    let local_identity = Identity::from_seed(b"repeat-announce-local").unwrap();
    let relay_id = IdentityHash::from([0x34; TRUNCATED_HASH_LEN]);
    let mut rng = rand::thread_rng();
    let mut buffer = [0_u8; MTU];
    let length = TestTransport::create_announce(
        &announcer,
        "testapp",
        &["restore"],
        None,
        None,
        &mut rng,
        40,
        &mut buffer,
    )
    .unwrap();
    let ordinary = buffer[..length].to_vec();
    let destination = DestHash::from_slice(Packet::parse(&ordinary).unwrap().destination_hash);

    let mut ordinary_transport = TestTransport::new();
    ordinary_transport.set_local_identity(relay_id);
    for cycle in 0..3 {
        let mut candidate = ordinary.clone();
        assert!(matches!(
            ordinary_transport.ingest_on(
                &mut candidate,
                40 + cycle,
                5,
                &mut rng,
                &local_identity,
            ),
            IngestResult::AnnounceReceived { .. }
        ));
        assert!(ordinary_transport.get_path(&destination).is_some());
        ordinary_transport.remove_path(&destination);
    }

    let response = as_h2_path_response(&ordinary, relay_id);
    let mut response_transport = TestTransport::new();
    response_transport.set_local_identity(IdentityHash::from([0x35; TRUNCATED_HASH_LEN]));
    for cycle in 0..3 {
        let mut candidate = response.clone();
        assert!(matches!(
            response_transport.ingest_on(
                &mut candidate,
                50 + cycle,
                6,
                &mut rng,
                &local_identity,
            ),
            IngestResult::AnnounceReceived { .. }
        ));
        assert!(response_transport.get_path(&destination).is_some());
        assert_eq!(response_transport.announce_count(), 0);
        response_transport.remove_path(&destination);
    }
}

#[test]
fn cached_response_flood_coalesces_and_full_queue_rejects_observably() {
    let relay_id = IdentityHash::from([0x36; TRUNCATED_HASH_LEN]);
    let destination = DestHash::from([0x56; TRUNCATED_HASH_LEN]);
    let identity = Identity::from_seed(b"known-response-capacity").unwrap();
    let mut cached_buffer = [0_u8; MTU];
    let mut rng = rand::thread_rng();
    let cached_len = TestTransport::create_announce(
        &identity,
        "testapp",
        &["capacity"],
        None,
        None,
        &mut rng,
        60,
        &mut cached_buffer,
    )
    .unwrap();
    let cached = as_h2_path_response(&cached_buffer[..cached_len], relay_id);

    let mut transport = TestTransport::new();
    transport.set_local_identity(relay_id);
    let mut path = Path::direct(60);
    path.announce_raw = AnnounceCache::store(&cached);
    transport.insert_path(destination, path);
    for tag in 0_u8..32 {
        let mut request = tagged_path_request(&destination, None, &[tag], 0);
        assert!(matches!(
            transport.ingest_on(&mut request, 61, tag, &mut rng, &identity),
            IngestResult::Duplicate
        ));
        assert_eq!(transport.announce_count(), 1);
    }
    assert!(transport.queue_announce(PendingAnnounce {
        dest_hash: DestHash::from([0x77; TRUNCATED_HASH_LEN]),
        raw: cached.clone(),
        tx_count: 0,
        retransmit_timeout: 100,
        local: true,
        local_rebroadcasts: 0,
        block_rebroadcasts: false,
        received_hops: 0,
        attached_interface: None,
    }));
    assert_eq!(transport.announce_count(), 2);

    let mut full = TestTransport::new();
    full.set_local_identity(relay_id);
    let mut path = Path::direct(60);
    path.announce_raw = AnnounceCache::store(&cached);
    full.insert_path(destination, path);
    for tag in 0_u8..16 {
        assert!(full.queue_announce(PendingAnnounce {
            dest_hash: DestHash::from([tag; TRUNCATED_HASH_LEN]),
            raw: cached.clone(),
            tx_count: 0,
            retransmit_timeout: 100,
            local: true,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            received_hops: 0,
            attached_interface: None,
        }));
    }
    let mut request = tagged_path_request(&destination, None, &[0xee], 0);
    assert!(matches!(
        full.ingest_on(&mut request, 61, 4, &mut rng, &identity),
        IngestResult::PathResponseQueueFull { dest_hash } if dest_hash == destination
    ));
    assert_eq!(full.announce_count(), 16);
}
