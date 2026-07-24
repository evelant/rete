//! Link integration tests — validates link lifecycle through Transport.
//!
//! Tests the full link handshake, data exchange, keepalive, close, and
//! edge cases (stale, invalid proof, duplicate request, etc.).

use rand::{rngs::StdRng, RngCore, SeedableRng};
use core::num::NonZeroU64;
use rete_core::{
    DestHash, DestType, HeaderType, Identity, IdentityHash, LinkId, MonotonicDuration,
    MonotonicInstant, Packet, PacketBuilder, PacketType, CONTEXT_KEEPALIVE, CONTEXT_LINKCLOSE,
    CONTEXT_LRPROOF, CONTEXT_LRRTT, CONTEXT_NONE, MTU, TRANSPORT_TYPE_TRANSPORT,
    TRUNCATED_HASH_LEN,
};
use rete_transport::{
    compute_link_id, HeaplessStorage, IngestResult, Link, LinkRole, LinkState, LinkTableKind,
    Path, SendError, Transport,
};

type TestTransport = Transport<rete_transport::HeaplessStorage<64, 16, 128, 4>>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up a responder transport with a local destination and identity.
fn make_responder(seed: &[u8]) -> (TestTransport, Identity, DestHash) {
    let identity = Identity::from_seed(seed).unwrap();
    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["link"], &mut name_buf).unwrap();
    let id_hash = identity.hash();
    let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

    let mut t = TestTransport::new();
    t.add_local_destination(dest_hash);
    (t, identity, dest_hash)
}

/// Build a LINKREQUEST packet for a destination.
fn build_link_request(
    dest_hash: &DestHash,
    identity: &Identity,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<u8> {
    build_link_request_with(dest_hash, identity, DestType::Single, 0x00, 67, rng)
}

fn build_link_request_with(
    dest_hash: &DestHash,
    identity: &Identity,
    dest_type: DestType,
    context: u8,
    payload_len: usize,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<u8> {
    let (_, request_payload) = Link::new_initiator(*dest_hash, identity.ed25519_pub(), rng, 100);
    let mut payload = request_payload.to_vec();
    payload.resize(payload_len, 0);
    payload.truncate(payload_len);

    build_link_request_from_payload_with(dest_hash, dest_type, context, &payload)
}

fn build_link_request_from_payload(dest_hash: &DestHash, request_payload: &[u8]) -> Vec<u8> {
    build_link_request_from_payload_with(
        dest_hash,
        DestType::Single,
        0x00,
        request_payload,
    )
}

fn build_link_request_from_payload_with(
    dest_hash: &DestHash,
    dest_type: DestType,
    context: u8,
    request_payload: &[u8],
) -> Vec<u8> {
    let mut buf = [0u8; MTU];
    let n = PacketBuilder::new(&mut buf)
        .packet_type(PacketType::LinkRequest)
        .dest_type(dest_type)
        .destination_hash(dest_hash.as_ref())
        .context(context)
        .payload(request_payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

fn wrap_header2(raw: &[u8], transport_id: IdentityHash) -> Vec<u8> {
    let packet = Packet::parse(raw).unwrap();
    let mut buf = [0u8; MTU];
    let len = PacketBuilder::new(&mut buf)
        .header_type(HeaderType::Header2)
        .transport_type(TRANSPORT_TYPE_TRANSPORT)
        .packet_type(packet.packet_type)
        .dest_type(packet.dest_type)
        .context_flag(packet.context_flag)
        .hops(packet.hops)
        .transport_id(transport_id.as_ref())
        .destination_hash(packet.destination_hash)
        .context(packet.context)
        .payload(packet.payload)
        .build()
        .unwrap();
    buf[..len].to_vec()
}

fn assert_local_link_request_rejected(dest_type: DestType, context: u8, payload_len: usize) {
    let mut rng = rand::thread_rng();
    let (mut transport, identity, dest_hash) = make_responder(b"responder-invalid-request");
    let initiator = Identity::from_seed(b"initiator-invalid-request").unwrap();
    let mut raw = build_link_request_with(
        &dest_hash,
        &initiator,
        dest_type,
        context,
        payload_len,
        &mut rng,
    );

    assert!(matches!(
        transport.ingest(&mut raw, 100, &mut rng, &identity),
        IngestResult::Invalid
    ));
    assert_eq!(transport.link_count(), 0);
    assert_eq!(transport.stats().packets_dropped_invalid, 1);
    assert_eq!(transport.stats().link_requests_received, 0);
    assert_eq!(transport.stats().links_failed, 0);
    assert_eq!(transport.stats().crypto_failures, 0);
}

fn make_bounded_responder<const L: usize>(
    seed: &[u8],
) -> (
    Transport<HeaplessStorage<64, 16, 128, L>>,
    Identity,
    DestHash,
) {
    let identity = Identity::from_seed(seed).unwrap();
    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["link"], &mut name_buf).unwrap();
    let dest_hash = rete_core::destination_hash(expanded, Some(&identity.hash()));
    let mut transport = Transport::new();
    transport.add_local_destination(dest_hash);
    (transport, identity, dest_hash)
}

struct PanicRng;

impl RngCore for PanicRng {
    fn next_u32(&mut self) -> u32 {
        panic!("preflight rejection consumed entropy")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("preflight rejection consumed entropy")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("preflight rejection consumed entropy")
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("preflight rejection consumed entropy")
    }
}

impl rand_core::CryptoRng for PanicRng {}

fn bounded_handshake<const L: usize>() -> (
    Transport<HeaplessStorage<64, 16, 128, L>>,
    Identity,
    Transport<HeaplessStorage<64, 16, 128, L>>,
    Identity,
    LinkId,
) {
    let mut rng = rand::thread_rng();
    let (mut responder, responder_identity, responder_dest) =
        make_bounded_responder::<L>(b"bounded-responder");
    let initiator_identity = Identity::from_seed(b"bounded-initiator").unwrap();
    let mut initiator = Transport::<HeaplessStorage<64, 16, 128, L>>::new();
    initiator.register_identity(
        responder_dest,
        responder_identity.public_key(),
        100,
    );

    let (mut request, link_id) = initiator
        .initiate_link(responder_dest, &initiator_identity, &mut rng, 100)
        .unwrap();
    let mut proof = match responder.ingest(
        &mut request,
        100,
        &mut rng,
        &responder_identity,
    ) {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected bounded Link request, got {other:?}"),
    };
    assert!(matches!(
        initiator.ingest(&mut proof, 101, &mut rng, &initiator_identity),
        IngestResult::LinkEstablished { .. }
    ));
    (
        initiator,
        initiator_identity,
        responder,
        responder_identity,
        link_id,
    )
}

/// Full handshake between two transports. Returns (initiator, responder, link_id).
fn full_handshake() -> (
    TestTransport,
    Identity,
    TestTransport,
    Identity,
    LinkId,
) {
    let mut rng = rand::thread_rng();
    let (mut resp_t, resp_id, resp_dest) = make_responder(b"responder-hs");
    let init_id = Identity::from_seed(b"initiator-hs").unwrap();
    let mut init_t = TestTransport::new();

    // Register responder identity so initiator can verify proof
    init_t.register_identity(resp_dest, resp_id.public_key(), 100);

    // Initiator builds and sends LINKREQUEST
    let request_pkt = build_link_request(&resp_dest, &init_id, &mut rng);
    let link_id = compute_link_id(&request_pkt).unwrap();

    // Responder ingests LINKREQUEST
    let mut req_buf = request_pkt.clone();
    let resp_result = resp_t.ingest(&mut req_buf, 100, &mut rng, &resp_id);
    let _proof_raw = match resp_result {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator sets up its link (manually, since it needs the raw packet)
    let (mut init_link, _payload) =
        Link::new_initiator(resp_dest, init_id.ed25519_pub(), &mut rng, 100);
    // Recompute from the same raw packet
    init_link.set_link_id(link_id);

    // We need to use initiate_link for the initiator transport to have the link
    let (init_req, init_link_id) = init_t
        .initiate_link(resp_dest, &init_id, &mut rng, 100)
        .unwrap();

    // The link_id from initiate_link may differ from our manually built one
    // because the ephemeral key is different. Use the transport's link.
    // Send LINKREQUEST to responder again with the transport's packet
    let mut req_buf2 = init_req.clone();
    // Clear responder's dedup so we can ingest again
    let (mut resp_t2, resp_id2, resp_dest2) = make_responder(b"responder-hs");
    resp_t2.register_identity(resp_dest2, resp_id2.public_key(), 100);
    let resp_result2 = resp_t2.ingest(&mut req_buf2, 100, &mut rng, &resp_id2);
    let proof_raw2 = match resp_result2 {
        IngestResult::LinkRequestReceived {
            link_id, proof_raw, ..
        } => {
            assert_eq!(link_id, init_link_id);
            proof_raw
        }
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator ingests LRPROOF
    let mut proof_buf = proof_raw2.clone();
    let init_result = init_t.ingest(&mut proof_buf, 101, &mut rng, &init_id);
    match init_result {
        IngestResult::LinkEstablished { link_id } => {
            assert_eq!(link_id, init_link_id);
        }
        other => panic!("expected LinkEstablished, got {:?}", other),
    }

    (init_t, init_id, resp_t2, resp_id2, init_link_id)
}

#[test]
fn precise_lrrtt_lifecycle_uses_confirmed_edges_and_updates_once() {
    let mut rng = rand::thread_rng();
    let (mut responder, responder_id, responder_dest) =
        make_responder(b"precise-lrrtt-responder");
    let initiator_id = Identity::from_seed(b"precise-lrrtt-initiator").unwrap();
    let mut initiator = TestTransport::new();
    initiator.register_identity(responder_dest, responder_id.public_key(), 10);

    let provisional_request = rete_core::MonotonicInstant::from_micros(10_000_000);
    let (mut request, link_id) = initiator
        .initiate_link_at(
            responder_dest,
            &initiator_id,
            &mut rng,
            10,
            provisional_request,
        )
        .unwrap();
    let initiator_token = NonZeroU64::new(1).unwrap();
    assert!(initiator.assign_link_protocol_token(
        &link_id,
        LinkRole::Initiator,
        initiator_token,
    ));
    let request_started = rete_core::MonotonicInstant::from_micros(10_125_000);
    assert!(initiator.confirm_link_protocol_dispatch(
        initiator_token,
        7,
        request_started,
        rete_core::MonotonicInstant::from_micros(10_150_000),
    ));
    let initiator_link = initiator.get_link(&link_id).unwrap();
    assert_eq!(initiator_link.request_started_at(), request_started);
    assert!(initiator_link.request_time_confirmed());
    assert_eq!(initiator_link.request_dispatch_interface(), Some(7));
    assert!(!initiator.confirm_link_protocol_dispatch(
        initiator_token,
        7,
        request_started,
        rete_core::MonotonicInstant::from_micros(10_150_000),
    ));

    let request_received = rete_core::MonotonicInstant::from_micros(10_250_000);
    let mut proof = match responder.ingest_on_at(
        &mut request,
        10,
        request_received,
        7,
        &mut rng,
        &responder_id,
    ) {
        IngestResult::LinkRequestReceived {
            link_id: observed,
            proof_raw,
        } => {
            assert_eq!(observed, link_id);
            proof_raw
        }
        other => panic!("expected responder request admission, got {other:?}"),
    };
    assert_eq!(responder.stats().links_established, 0);

    let responder_token = NonZeroU64::new(2).unwrap();
    assert!(responder.assign_link_protocol_token(
        &link_id,
        LinkRole::Responder,
        responder_token,
    ));
    let proof_started = rete_core::MonotonicInstant::from_micros(10_300_000);
    let proof_completed = rete_core::MonotonicInstant::from_micros(10_375_000);
    assert!(!responder.confirm_link_protocol_dispatch(
        responder_token,
        8,
        proof_started,
        proof_completed,
    ));
    assert!(!responder.get_link(&link_id).unwrap().request_time_confirmed());
    assert!(responder.confirm_link_protocol_dispatch(
        responder_token,
        7,
        proof_started,
        proof_completed,
    ));
    let responder_link = responder.get_link(&link_id).unwrap();
    assert_eq!(responder_link.request_started_at(), proof_completed);
    assert_eq!(responder_link.request_dispatch_interface(), Some(7));

    let proof_received = rete_core::MonotonicInstant::from_micros(10_625_000);
    assert!(matches!(
        initiator.ingest_on_at(
            &mut proof,
            10,
            proof_received,
            7,
            &mut rng,
            &initiator_id,
        ),
        IngestResult::LinkEstablished { link_id: observed } if observed == link_id
    ));
    assert_eq!(initiator.get_link(&link_id).unwrap().rtt.to_bits(), 0.5f64.to_bits());

    let first_lrrtt = initiator
        .build_lrrtt_packet_for_rtt(&link_id, 0.5, &mut rng)
        .unwrap();
    let first_received = rete_core::MonotonicInstant::from_micros(10_875_000);
    let mut first_buf = first_lrrtt.clone();
    assert!(matches!(
        responder.ingest_on_at(
            &mut first_buf,
            10,
            first_received,
            7,
            &mut rng,
            &responder_id,
        ),
        IngestResult::LinkEstablished { link_id: observed } if observed == link_id
    ));
    let immutable_request_origin = responder.get_link(&link_id).unwrap().request_started_at();
    assert_eq!(immutable_request_origin, proof_completed);
    assert_eq!(responder.get_link(&link_id).unwrap().rtt.to_bits(), 0.5f64.to_bits());
    assert_eq!(responder.stats().links_established, 1);

    // Exact ciphertext replay remains a dedup outcome and emits no RTT update.
    let mut exact_replay = first_lrrtt;
    assert!(matches!(
        responder.ingest_on_at(
            &mut exact_replay,
            11,
            rete_core::MonotonicInstant::from_micros(11_000_000),
            7,
            &mut rng,
            &responder_id,
        ),
        IngestResult::Duplicate
    ));
    assert_eq!(responder.stats().links_established, 1);

    // Fresh ciphertext reuses the immutable proof-dispatch origin.
    let mut fresh_repeat = initiator
        .build_lrrtt_packet_for_rtt(&link_id, 0.5, &mut rng)
        .unwrap();
    let repeat_received = rete_core::MonotonicInstant::from_micros(11_625_000);
    assert!(matches!(
        responder.ingest_on_at(
            &mut fresh_repeat,
            11,
            repeat_received,
            7,
            &mut rng,
            &responder_id,
        ),
        IngestResult::LinkRttUpdated { link_id: observed } if observed == link_id
    ));
    let responder_link = responder.get_link(&link_id).unwrap();
    assert_eq!(responder_link.request_started_at(), immutable_request_origin);
    assert_eq!(responder_link.rtt.to_bits(), 1.25f64.to_bits());
    assert_eq!(responder_link.last_inbound, repeat_received);
    assert_eq!(responder.stats().links_established, 1);

    // A fresh LRRTT also revives Stale and still does not establish twice.
    let stale_at = responder_link.last_inbound + responder_link.stale_time;
    assert_eq!(responder.tick_at(stale_at.as_secs(), stale_at).closed_links, 0);
    assert_eq!(responder.get_link(&link_id).unwrap().state, LinkState::Stale);
    let mut stale_repeat = initiator
        .build_lrrtt_packet_for_rtt(&link_id, 0.5, &mut rng)
        .unwrap();
    let revived_at = stale_at + MonotonicDuration::from_micros(250_000);
    assert!(matches!(
        responder.ingest_on_at(
            &mut stale_repeat,
            revived_at.as_secs(),
            revived_at,
            7,
            &mut rng,
            &responder_id,
        ),
        IngestResult::LinkRttUpdated { link_id: observed } if observed == link_id
    ));
    let revived = responder.get_link(&link_id).unwrap();
    assert_eq!(revived.state, LinkState::Active);
    assert_eq!(revived.request_started_at(), immutable_request_origin);
    assert_eq!(responder.stats().links_established, 1);
}

#[test]
fn responder_handshake_timeout_uses_post_ingress_hops_and_confirmed_proof_completion() {
    let mut rng = rand::thread_rng();
    let (mut responder, responder_id, responder_dest) =
        make_responder(b"responder-timeout-confirmed-origin");
    let initiator_id = Identity::from_seed(b"responder-timeout-confirmed-initiator").unwrap();
    let origin = MonotonicInstant::from_micros(100_250_000);
    let mut request = build_link_request(&responder_dest, &initiator_id, &mut rng);
    request[1] = 2;

    let link_id = match responder.ingest_on_at(
        &mut request,
        origin.as_secs(),
        origin,
        7,
        &mut rng,
        &responder_id,
    ) {
        IngestResult::LinkRequestReceived { link_id, .. } => link_id,
        other => panic!("expected responder request admission, got {other:?}"),
    };
    let timeout = MonotonicDuration::from_secs(378);
    let pending = responder.get_link(&link_id).unwrap();
    assert_eq!(pending.request_started_at(), origin);
    assert!(!pending.request_time_confirmed());

    let token = NonZeroU64::new(0x51).unwrap();
    assert!(responder.assign_link_protocol_token(
        &link_id,
        LinkRole::Responder,
        token,
    ));
    let proof_started = origin + MonotonicDuration::from_secs(9);
    let proof_completed = origin + MonotonicDuration::from_secs(10);
    assert!(responder.confirm_link_protocol_dispatch(
        token,
        7,
        proof_started,
        proof_completed,
    ));
    assert_eq!(
        responder.get_link(&link_id).unwrap().request_started_at(),
        proof_completed
    );

    // Confirmation moves the origin: the old provisional deadline must not
    // reclaim a Link whose LRPROOF actually completed later.
    let provisional_deadline = origin + timeout;
    assert_eq!(
        responder
            .tick_at(provisional_deadline.as_secs(), provisional_deadline)
            .closed_links,
        0
    );
    assert!(responder.get_link(&link_id).is_some());

    let confirmed_deadline = proof_completed + timeout;
    assert_eq!(
        responder
            .tick_at(
                confirmed_deadline.as_secs(),
                confirmed_deadline - MonotonicDuration::from_micros(1),
            )
            .closed_links,
        0
    );
    let failed_before = responder.stats().links_failed;
    let closed_before = responder.stats().links_closed;
    assert_eq!(
        responder
            .tick_at(confirmed_deadline.as_secs(), confirmed_deadline)
            .closed_links,
        1
    );
    assert!(responder.get_link(&link_id).is_none());
    assert_eq!(responder.stats().links_failed, failed_before);
    assert_eq!(responder.stats().links_closed, closed_before + 1);

    // Removal is atomic and cannot be counted twice on later maintenance.
    assert_eq!(
        responder
            .tick_at(
                confirmed_deadline.as_secs() + 1,
                confirmed_deadline + MonotonicDuration::from_secs(1),
            )
            .closed_links,
        0
    );
    assert_eq!(responder.stats().links_failed, failed_before);
    assert_eq!(responder.stats().links_closed, closed_before + 1);
}

#[test]
fn unconfirmed_protocol_edges_use_provisional_time_and_cannot_confirm_after_activation() {
    let mut rng = rand::thread_rng();
    let (mut responder, responder_id, responder_dest) =
        make_responder(b"provisional-lrrtt-responder");
    let initiator_id = Identity::from_seed(b"provisional-lrrtt-initiator").unwrap();
    let mut initiator = TestTransport::new();
    initiator.register_identity(responder_dest, responder_id.public_key(), 20);

    let provisional = rete_core::MonotonicInstant::from_micros(20_125_000);
    let (mut request, link_id) = initiator
        .initiate_link_at(
            responder_dest,
            &initiator_id,
            &mut rng,
            20,
            provisional,
        )
        .unwrap();
    let initiator_token = NonZeroU64::new(10).unwrap();
    assert!(initiator.assign_link_protocol_token(
        &link_id,
        LinkRole::Initiator,
        initiator_token,
    ));

    let mut proof = match responder.ingest_on_at(
        &mut request,
        20,
        provisional,
        3,
        &mut rng,
        &responder_id,
    ) {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected responder request admission, got {other:?}"),
    };
    let responder_token = NonZeroU64::new(11).unwrap();
    assert!(responder.assign_link_protocol_token(
        &link_id,
        LinkRole::Responder,
        responder_token,
    ));

    assert!(matches!(
        initiator.ingest_on_at(
            &mut proof,
            20,
            provisional,
            3,
            &mut rng,
            &initiator_id,
        ),
        IngestResult::LinkEstablished { .. }
    ));
    assert_eq!(initiator.get_link(&link_id).unwrap().rtt, 0.0);
    assert!(!initiator.get_link(&link_id).unwrap().request_time_confirmed());
    assert!(!initiator.confirm_link_protocol_dispatch(
        initiator_token,
        3,
        provisional,
        provisional,
    ));
    assert_eq!(initiator.get_link(&link_id).unwrap().request_started_at(), provisional);

    let mut lrrtt = initiator
        .build_lrrtt_packet_for_rtt(&link_id, 0.0, &mut rng)
        .unwrap();
    assert!(matches!(
        responder.ingest_on_at(
            &mut lrrtt,
            20,
            provisional,
            3,
            &mut rng,
            &responder_id,
        ),
        IngestResult::LinkEstablished { .. }
    ));
    let responder_link = responder.get_link(&link_id).unwrap();
    assert_eq!(responder_link.rtt, 0.0);
    assert_eq!(responder_link.keepalive_interval, MonotonicDuration::from_secs(5));
    assert_eq!(responder_link.stale_time, MonotonicDuration::from_secs(10));
    assert!(!responder_link.request_time_confirmed());
    assert!(!responder.confirm_link_protocol_dispatch(
        responder_token,
        3,
        provisional,
        provisional,
    ));
    assert_eq!(responder.get_link(&link_id).unwrap().request_started_at(), provisional);
}

#[test]
fn protocol_tokens_are_unique_within_the_bounded_link_table() {
    let mut rng = rand::thread_rng();
    let identity = Identity::from_seed(b"protocol-token-uniqueness").unwrap();
    let mut transport = TestTransport::new();
    let (_, first) = transport
        .initiate_link(
            DestHash::from([0xA1; TRUNCATED_HASH_LEN]),
            &identity,
            &mut rng,
            1,
        )
        .unwrap();
    let (_, second) = transport
        .initiate_link(
            DestHash::from([0xA2; TRUNCATED_HASH_LEN]),
            &identity,
            &mut rng,
            1,
        )
        .unwrap();
    let token = NonZeroU64::new(42).unwrap();
    assert!(transport.assign_link_protocol_token(&first, LinkRole::Initiator, token));
    assert!(!transport.assign_link_protocol_token(&second, LinkRole::Initiator, token));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn link_request_local_creates_link() {
    let mut rng = rand::thread_rng();
    let (mut t, identity, dest_hash) = make_responder(b"responder-1");

    let initiator = Identity::from_seed(b"initiator-1").unwrap();
    let request_pkt = build_link_request(&dest_hash, &initiator, &mut rng);

    let mut raw = request_pkt;
    match t.ingest(&mut raw, 100, &mut rng, &identity) {
        IngestResult::LinkRequestReceived { link_id, proof_raw } => {
            assert_eq!(link_id.as_ref().len(), 16);
            assert!(!proof_raw.is_empty());
            // Proof should be a parseable packet
            let pkt = Packet::parse(&proof_raw).unwrap();
            assert_eq!(pkt.packet_type, PacketType::Proof);
            assert_eq!(pkt.dest_type, DestType::Link);
            assert_eq!(pkt.context, CONTEXT_LRPROOF);
        }
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);
}

#[test]
fn header2_local_link_request_uses_typed_owned_link_admission() {
    let mut rng = rand::thread_rng();
    let (mut transport, responder, destination) = make_responder(b"h2-local-responder");
    let initiator = Identity::from_seed(b"h2-local-initiator").unwrap();
    let request = build_link_request(&destination, &initiator, &mut rng);
    let expected_id = compute_link_id(&request).unwrap();
    let mut header2 = wrap_header2(&request, responder.hash());

    assert!(matches!(
        transport.ingest_on(&mut header2, 100, 3, &mut rng, &responder),
        IngestResult::LinkRequestReceived { link_id, .. } if link_id == expected_id
    ));
    assert_eq!(transport.link_count(), 1);
    assert_eq!(transport.relay_link_count(), 0);
    assert_eq!(transport.reverse_count(), 0);
}

#[test]
fn header2_owned_link_proof_and_data_reach_typed_dispatch() {
    let mut rng = rand::thread_rng();
    let (mut responder_transport, responder, destination) =
        make_responder(b"h2-owned-link-responder");
    let initiator = Identity::from_seed(b"h2-owned-link-initiator").unwrap();
    let mut initiator_transport = TestTransport::new();
    initiator_transport.register_identity(destination, responder.public_key(), 100);

    let (request, link_id) = initiator_transport
        .initiate_link(destination, &initiator, &mut rng, 100)
        .unwrap();
    let mut request = request;
    let proof = match responder_transport.ingest_on(&mut request, 100, 5, &mut rng, &responder) {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected local LINKREQUEST, got {other:?}"),
    };

    let mut header2_proof = wrap_header2(&proof, initiator.hash());
    assert!(matches!(
        initiator_transport.ingest_on(
            &mut header2_proof,
            101,
            4,
            &mut rng,
            &initiator,
        ),
        IngestResult::LinkEstablished { link_id: id } if id == link_id
    ));
    assert_eq!(initiator_transport.reverse_count(), 0);

    let lrrtt = initiator_transport
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut header2_lrrtt = wrap_header2(&lrrtt, responder.hash());
    assert!(matches!(
        responder_transport.ingest_on(
            &mut header2_lrrtt,
            102,
            5,
            &mut rng,
            &responder,
        ),
        IngestResult::LinkEstablished { link_id: id } if id == link_id
    ));

    let data = initiator_transport
        .build_link_data_packet(&link_id, b"typed h2 link data", 0x00, &mut rng)
        .unwrap();
    let mut header2_data = wrap_header2(&data, responder.hash());
    assert!(matches!(
        responder_transport.ingest_on(
            &mut header2_data,
            103,
            5,
            &mut rng,
            &responder,
        ),
        IngestResult::LinkData { link_id: id, data, .. }
            if id == link_id && data == b"typed h2 link data"
    ));
    assert_eq!(responder_transport.reverse_count(), 0);
}

#[test]
fn local_link_request_accepts_only_canonical_payload_lengths() {
    let mut rng = rand::thread_rng();

    for payload_len in [64, 67] {
        let (mut transport, identity, dest_hash) = make_responder(b"responder-valid-request");
        let initiator = Identity::from_seed(b"initiator-valid-request").unwrap();
        let mut raw = build_link_request_with(
            &dest_hash,
            &initiator,
            DestType::Single,
            0x00,
            payload_len,
            &mut rng,
        );

        assert!(matches!(
            transport.ingest(&mut raw, 100, &mut rng, &identity),
            IngestResult::LinkRequestReceived { .. }
        ));
        assert_eq!(transport.link_count(), 1);
        assert_eq!(transport.stats().link_requests_received, 1);
    }

    for payload_len in [0, 63, 65, 66, 68] {
        assert_local_link_request_rejected(DestType::Single, 0x00, payload_len);
    }
}

#[test]
fn local_link_request_requires_single_destination_type() {
    for dest_type in [DestType::Group, DestType::Plain, DestType::Link] {
        assert_local_link_request_rejected(dest_type, 0x00, 67);
    }
}

#[test]
fn local_link_request_requires_context_zero() {
    for context in [0x01, 0xFF] {
        assert_local_link_request_rejected(DestType::Single, context, 67);
    }
}

#[test]
fn repeated_malformed_local_link_request_is_deduplicated() {
    let mut rng = rand::thread_rng();
    let (mut transport, identity, dest_hash) = make_responder(b"responder-malformed-replay");
    let initiator = Identity::from_seed(b"initiator-malformed-replay").unwrap();
    let request =
        build_link_request_with(&dest_hash, &initiator, DestType::Single, 0x00, 65, &mut rng);

    let mut first = request.clone();
    assert!(matches!(
        transport.ingest(&mut first, 100, &mut rng, &identity),
        IngestResult::Invalid
    ));

    let mut replay = request;
    assert!(matches!(
        transport.ingest(&mut replay, 101, &mut rng, &identity),
        IngestResult::Duplicate
    ));
    assert_eq!(transport.link_count(), 0);
    assert_eq!(transport.stats().packets_dropped_invalid, 1);
    assert_eq!(transport.stats().packets_dropped_dedup, 1);
}

#[test]
fn link_request_non_local_forwards() {
    let mut rng = rand::thread_rng();
    let mut t = TestTransport::new();
    let identity = Identity::from_seed(b"non-local-node").unwrap();

    let remote_dest = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
    let initiator = Identity::from_seed(b"initiator-2").unwrap();
    let request_pkt = build_link_request(&remote_dest, &initiator, &mut rng);

    let mut raw = request_pkt;
    match t.ingest(&mut raw, 100, &mut rng, &identity) {
        IngestResult::Forward { .. } => {}
        other => panic!("expected Forward, got {:?}", other),
    }
    assert_eq!(t.link_count(), 0);
}

#[test]
fn full_handshake_two_transports() {
    let (init_t, _, resp_t, _, link_id) = full_handshake();

    // Initiator should have an active link
    let init_link = init_t.get_link(&link_id).unwrap();
    assert_eq!(init_link.state, LinkState::Active);
    assert_eq!(init_link.expected_hops(), Some(1));

    // Responder should have a handshake link (waiting for LRRTT)
    let resp_link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(resp_link.state, LinkState::Handshake);
    assert_eq!(resp_link.expected_hops(), None);
}

#[test]
fn lrrtt_activates_responder_link() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Initiator sends LRRTT
    let encoded_rtt = init_t.get_link(&link_id).unwrap().rtt as f64;
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, encoded_rtt, &mut rng)
        .unwrap();
    let parsed = Packet::parse(&lrrtt).unwrap();
    assert_eq!(parsed.context, CONTEXT_LRRTT);
    let mut plaintext = [0u8; MTU];
    let plaintext_len = init_t
        .get_link(&link_id)
        .unwrap()
        .decrypt(parsed.payload, &mut plaintext)
        .unwrap();
    let mut expected_plaintext = [0u8; 9];
    expected_plaintext[0] = 0xcb;
    expected_plaintext[1..].copy_from_slice(&encoded_rtt.to_be_bytes());
    assert_eq!(&plaintext[..plaintext_len], &expected_plaintext);

    // A packet that does not authenticate must not teach the responder a
    // route height or activate the Link.
    let invalid_before = resp_t.stats().packets_dropped_invalid;
    let crypto_before = resp_t.stats().crypto_failures;
    let failed_before = resp_t.stats().links_failed;
    let closed_before = resp_t.stats().links_closed;
    let mut invalid_lrrtt = lrrtt.clone();
    *invalid_lrrtt.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        resp_t.ingest(&mut invalid_lrrtt, 101, &mut rng, &resp_id),
        IngestResult::Invalid
    ));
    let pending = resp_t.get_link(&link_id).unwrap();
    assert_eq!(pending.state, LinkState::Handshake);
    assert_eq!(pending.expected_hops(), None);
    assert_eq!(pending.rtt, 0.0);
    assert_eq!(resp_t.stats().packets_dropped_invalid, invalid_before + 1);
    assert_eq!(resp_t.stats().crypto_failures, crypto_before + 1);
    assert_eq!(resp_t.stats().links_failed, failed_before);
    assert_eq!(resp_t.stats().links_closed, closed_before);

    let mut lrrtt_buf = lrrtt;
    match resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id) {
        IngestResult::LinkEstablished { link_id: lid } => {
            assert_eq!(lid, link_id);
        }
        other => panic!("expected LinkEstablished, got {:?}", other),
    }

    // Responder link should now be Active
    let resp_link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(resp_link.state, LinkState::Active);
    assert_eq!(resp_link.expected_hops(), Some(1));
}

#[test]
fn authenticated_lrrtt_hands_lifecycle_to_the_active_stale_watchdog() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // A large authenticated RTT reaches Python's 360-second keepalive ceiling,
    // making the active stale window longer than the old handshake deadline.
    let mut lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 400.0, &mut rng)
        .unwrap();
    assert!(matches!(
        resp_t.ingest(&mut lrrtt, 102, &mut rng, &resp_id),
        IngestResult::LinkEstablished { link_id: observed } if observed == link_id
    ));
    let active = resp_t.get_link(&link_id).unwrap();
    assert_eq!(active.state, LinkState::Active);
    assert_eq!(active.stale_time, MonotonicDuration::from_secs(720));

    let failed_before = resp_t.stats().links_failed;
    let closed_before = resp_t.stats().links_closed;
    let former_handshake_deadline = MonotonicInstant::from_secs(466);
    assert_eq!(
        resp_t
            .tick_at(
                former_handshake_deadline.as_secs(),
                former_handshake_deadline,
            )
            .closed_links,
        0
    );
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Active);
    assert_eq!(resp_t.stats().links_failed, failed_before);
    assert_eq!(resp_t.stats().links_closed, closed_before);
}

#[test]
fn lrrtt_accepts_python_numeric_scalars_and_uses_python_max_ordering() {
    fn float64_payload(value: f64) -> Vec<u8> {
        let mut payload = vec![0xcb];
        payload.extend_from_slice(&value.to_be_bytes());
        payload
    }

    fn float32_payload(value: f32) -> Vec<u8> {
        let mut payload = vec![0xca];
        payload.extend_from_slice(&value.to_be_bytes());
        payload
    }

    let cases = vec![
        (vec![0xff], 2.0f64), // negative fixint
        (vec![0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd], 2.0),
        (vec![0xc3, 0xc1, 0xff], 2.0), // bool, then ignored trailing objects
        (float32_payload(4.5), 4.5),
        (float64_payload(3.5), 3.5),
        (float64_payload(f64::NAN), 2.0),
        (float64_payload(f64::NEG_INFINITY), 2.0),
        (float64_payload(f64::INFINITY), f64::INFINITY),
    ];

    for (payload, expected) in cases {
        let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
        let mut rng = rand::thread_rng();
        let lrrtt = init_t
            .build_lrrtt_packet(&link_id, &payload, &mut rng)
            .unwrap();
        let mut lrrtt_buf = lrrtt;
        assert!(matches!(
            resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id),
            IngestResult::LinkEstablished { link_id: id } if id == link_id
        ));

        let link = resp_t.get_link(&link_id).unwrap();
        assert_eq!(link.rtt, expected, "payload {payload:02x?}");
        if expected == f64::INFINITY {
            assert_eq!(link.keepalive_interval, MonotonicDuration::from_secs(360));
            assert_eq!(link.stale_time, MonotonicDuration::from_secs(720));
        }
        assert_eq!(link.state, LinkState::Active);
        assert_eq!(link.expected_hops(), Some(1));
        assert_eq!(resp_t.stats().links_established, 1);
    }
}

#[test]
fn authenticated_malformed_lrrtt_tears_down_once_and_returns_encrypted_close() {
    for malformed_plaintext in [vec![0xc0], vec![0xcb, 0x00]] {
        let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
        let mut rng = rand::thread_rng();
        let malformed = init_t
            .build_lrrtt_packet(&link_id, &malformed_plaintext, &mut rng)
            .unwrap();
        let replay = malformed.clone();

        let before_invalid = resp_t.stats().packets_dropped_invalid;
        let before_failed = resp_t.stats().links_failed;
        let before_closed = resp_t.stats().links_closed;
        let before_established = resp_t.stats().links_established;
        let before_crypto = resp_t.stats().crypto_failures;
        let pending = resp_t.get_link(&link_id).unwrap();
        assert_eq!(pending.state, LinkState::Handshake);
        assert_eq!(pending.expected_hops(), None);
        assert_eq!(pending.rtt, 0.0);

        let mut malformed_buf = malformed;
        let close = match resp_t.ingest(&mut malformed_buf, 102, &mut rng, &resp_id) {
            IngestResult::LinkTeardown {
                link_id: id,
                close_raw: Some(close),
                interface: Some(0),
            } if id == link_id => close,
            other => panic!("expected LinkTeardown with close, got {other:?}"),
        };
        assert_eq!(resp_t.link_count(), 0);
        assert_eq!(resp_t.channel_receipt_count(), 0);
        assert_eq!(
            resp_t.stats().packets_dropped_invalid,
            before_invalid + 1
        );
        assert_eq!(resp_t.stats().links_failed, before_failed + 1);
        assert_eq!(resp_t.stats().links_closed, before_closed + 1);
        assert_eq!(resp_t.stats().links_established, before_established);
        assert_eq!(resp_t.stats().crypto_failures, before_crypto);

        let parsed_close = Packet::parse(&close).unwrap();
        assert_eq!(parsed_close.context, CONTEXT_LINKCLOSE);
        let mut plaintext = [0u8; MTU];
        let plaintext_len = init_t
            .get_link(&link_id)
            .unwrap()
            .decrypt(parsed_close.payload, &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..plaintext_len], link_id.as_ref());

        let failed_after = resp_t.stats().links_failed;
        let closed_after = resp_t.stats().links_closed;
        let invalid_after = resp_t.stats().packets_dropped_invalid;
        let mut replay_buf = replay;
        assert!(matches!(
            resp_t.ingest(&mut replay_buf, 103, &mut rng, &resp_id),
            IngestResult::Duplicate | IngestResult::Invalid
        ));
        assert_eq!(resp_t.stats().links_failed, failed_after);
        assert_eq!(resp_t.stats().links_closed, closed_after);
        assert_eq!(resp_t.stats().packets_dropped_invalid, invalid_after);

        let mut close_buf = close;
        assert!(matches!(
            init_t.ingest(&mut close_buf, 104, &mut rng, &init_id),
            IngestResult::LinkClosed { link_id: id } if id == link_id
        ));
        assert_eq!(init_t.link_count(), 0);
    }
}

#[test]
fn malformed_lrrtt_tears_down_active_responder_but_not_initiator() {
    let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let malformed_for_initiator = init_t
        .build_lrrtt_packet(&link_id, &[0xc0], &mut rng)
        .unwrap();
    let init_failed = init_t.stats().links_failed;
    let init_closed = init_t.stats().links_closed;
    let mut initiator_buf = malformed_for_initiator;
    assert!(matches!(
        init_t.ingest(&mut initiator_buf, 102, &mut rng, &init_id),
        IngestResult::Invalid
    ));
    assert_eq!(init_t.get_link(&link_id).unwrap().state, LinkState::Active);
    assert_eq!(init_t.stats().links_failed, init_failed);
    assert_eq!(init_t.stats().links_closed, init_closed);

    let valid = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut valid_buf = valid;
    assert!(matches!(
        resp_t.ingest(&mut valid_buf, 102, &mut rng, &resp_id),
        IngestResult::LinkEstablished { .. }
    ));
    let resp_failed = resp_t.stats().links_failed;
    let resp_closed = resp_t.stats().links_closed;

    // Authenticated malformed LRRTT is a protocol error in every responder
    // state that accepts fresh RTT updates.
    let malformed_for_active_responder = init_t
        .build_lrrtt_packet(&link_id, &[0xc0], &mut rng)
        .unwrap();
    let mut responder_buf = malformed_for_active_responder;
    assert!(matches!(
        resp_t.ingest(&mut responder_buf, 103, &mut rng, &resp_id),
        IngestResult::LinkTeardown {
            link_id: id,
            close_raw: Some(_),
            ..
        } if id == link_id
    ));
    assert!(resp_t.get_link(&link_id).is_none());
    assert_eq!(resp_t.stats().links_failed, resp_failed);
    assert_eq!(resp_t.stats().links_closed, resp_closed + 1);
}

#[test]
fn authenticated_malformed_lrrtt_tears_down_stale_responder_without_failure_count() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let mut valid = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    assert!(matches!(
        resp_t.ingest(&mut valid, 102, &mut rng, &resp_id),
        IngestResult::LinkEstablished { .. }
    ));
    let link = resp_t.get_link(&link_id).unwrap();
    let stale_at = link.last_inbound + link.stale_time;
    assert_eq!(resp_t.tick_at(stale_at.as_secs(), stale_at).closed_links, 0);
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Stale);

    let failed_before = resp_t.stats().links_failed;
    let closed_before = resp_t.stats().links_closed;
    let mut malformed = init_t
        .build_lrrtt_packet(&link_id, &[0xc0], &mut rng)
        .unwrap();
    let malformed_at = stale_at + MonotonicDuration::from_micros(1);
    assert!(matches!(
        resp_t.ingest_on_at(
            &mut malformed,
            malformed_at.as_secs(),
            malformed_at,
            0,
            &mut rng,
            &resp_id,
        ),
        IngestResult::LinkTeardown {
            link_id: id,
            close_raw: Some(_),
            ..
        } if id == link_id
    ));
    assert!(resp_t.get_link(&link_id).is_none());
    assert_eq!(resp_t.stats().links_failed, failed_before);
    assert_eq!(resp_t.stats().links_closed, closed_before + 1);
}

#[test]
fn malformed_lrrtt_purges_receipts_for_the_torn_down_link() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let valid = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut valid_buf = valid;
    assert!(matches!(
        resp_t.ingest(&mut valid_buf, 102, &mut rng, &resp_id),
        IngestResult::LinkEstablished { .. }
    ));
    resp_t
        .send_channel_message(&link_id, 0x01, b"pending", 103, &mut rng)
        .unwrap();
    assert_eq!(resp_t.channel_receipt_count(), 1);

    // Simulate a responder still negotiating while a stale receipt exists;
    // teardown must purge all session-owned terminal state atomically.
    resp_t.get_link_mut(&link_id).unwrap().state = LinkState::Handshake;
    let malformed = init_t
        .build_lrrtt_packet(&link_id, &[0xc0], &mut rng)
        .unwrap();
    let mut malformed_buf = malformed;
    assert!(matches!(
        resp_t.ingest(&mut malformed_buf, 104, &mut rng, &resp_id),
        IngestResult::LinkTeardown { .. }
    ));
    assert_eq!(resp_t.link_count(), 0);
    assert_eq!(resp_t.channel_receipt_count(), 0);
}

#[test]
fn link_data_encrypt_decrypt() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends encrypted data
    let data_pkt = init_t
        .build_link_data_packet(&link_id, b"hello link", 0x00, &mut rng)
        .unwrap();
    let mut data_buf = data_pkt;
    match resp_t.ingest(&mut data_buf, 103, &mut rng, &resp_id) {
        IngestResult::LinkData {
            link_id: lid,
            data,
            context,
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(data, b"hello link");
            assert_eq!(context, 0x00);
        }
        other => panic!("expected LinkData, got {:?}", other),
    }
}

#[test]
fn bidirectional_link_data() {
    let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator → Responder
    let pkt1 = init_t
        .build_link_data_packet(&link_id, b"from initiator", 0x00, &mut rng)
        .unwrap();
    let mut buf1 = pkt1;
    match resp_t.ingest(&mut buf1, 103, &mut rng, &resp_id) {
        IngestResult::LinkData { data, .. } => assert_eq!(data, b"from initiator"),
        other => panic!("expected LinkData, got {:?}", other),
    }

    // Responder → Initiator
    let pkt2 = resp_t
        .build_link_data_packet(&link_id, b"from responder", 0x00, &mut rng)
        .unwrap();
    let mut buf2 = pkt2;
    match init_t.ingest(&mut buf2, 104, &mut rng, &init_id) {
        IngestResult::LinkData { data, .. } => assert_eq!(data, b"from responder"),
        other => panic!("expected LinkData, got {:?}", other),
    }
}

#[test]
fn keepalive_request_response() {
    let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends keepalive request
    let ka = init_t.build_keepalive_packet(&link_id, true, 200).unwrap();
    assert_eq!(ka.len(), 20, "keepalives must not carry Token overhead");
    let mut ka_buf = ka.clone();
    assert!(matches!(
        resp_t.ingest(&mut ka_buf, 200, &mut rng, &resp_id),
        IngestResult::Keepalive {
            link_id: id,
            reply: true,
        } if id == link_id
    ));

    let response = resp_t.build_keepalive_packet(&link_id, false, 201).unwrap();
    assert_eq!(response.len(), 20);
    let mut response_buf = response.clone();
    assert!(matches!(
        init_t.ingest(&mut response_buf, 201, &mut rng, &init_id),
        IngestResult::Keepalive {
            link_id: id,
            reply: false,
        } if id == link_id
    ));

    // Identical deterministic requests bypass dedup and continue advancing
    // responder liveness, as required by Python RNS packet_filter().
    let mut repeated = ka;
    assert!(matches!(
        resp_t.ingest(&mut repeated, 202, &mut rng, &resp_id),
        IngestResult::Keepalive { reply: true, .. }
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound.as_secs(), 202);
    assert_eq!(resp_t.stats().packets_dropped_dedup, 0);

    let mut repeated_response = response;
    assert!(matches!(
        init_t.ingest(&mut repeated_response, 203, &mut rng, &init_id),
        IngestResult::Keepalive { reply: false, .. }
    ));
    assert_eq!(init_t.get_link(&link_id).unwrap().last_inbound.as_secs(), 203);
    assert_eq!(init_t.stats().packets_dropped_dedup, 0);
}

#[test]
fn keepalive_wrong_interface_does_not_poison_correct_copy() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest_on(&mut lrrtt_buf, 102, 0, &mut rng, &resp_id);

    let request = init_t.build_keepalive_packet(&link_id, true, 200).unwrap();
    let initial_inbound = resp_t.get_link(&link_id).unwrap().last_inbound;

    let mut wrong = request.clone();
    assert!(matches!(
        resp_t.ingest_on(&mut wrong, 201, 7, &mut rng, &resp_id),
        IngestResult::Invalid
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound, initial_inbound);
    assert_eq!(resp_t.stats().packets_dropped_dedup, 0);

    let mut correct = request;
    assert!(matches!(
        resp_t.ingest_on(&mut correct, 202, 0, &mut rng, &resp_id),
        IngestResult::Keepalive { reply: true, .. }
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound.as_secs(), 202);
    assert_eq!(resp_t.stats().packets_dropped_dedup, 0);
}

#[test]
fn malformed_wrong_role_and_legacy_encrypted_keepalives_do_not_refresh_liveness() {
    let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    let responder_inbound = resp_t.get_link(&link_id).unwrap().last_inbound;
    let mut wrong_role = resp_t.build_keepalive_packet(&link_id, false, 200).unwrap();
    assert!(matches!(
        resp_t.ingest(&mut wrong_role, 201, &mut rng, &resp_id),
        IngestResult::Invalid
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound, responder_inbound);

    let mut malformed_buf = [0u8; MTU];
    let malformed_len = PacketBuilder::new(&mut malformed_buf)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Link)
        .destination_hash(link_id.as_ref())
        .context(CONTEXT_KEEPALIVE)
        .payload(&[0xFF, 0x00])
        .build()
        .unwrap();
    assert!(matches!(
        resp_t.ingest(
            &mut malformed_buf[..malformed_len],
            202,
            &mut rng,
            &resp_id,
        ),
        IngestResult::Invalid
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound, responder_inbound);

    // This reproduces Rete's legacy behavior: context KEEPALIVE sent through
    // the generic Token-encrypted Link packet builder. Python RNS cannot parse
    // it as a keepalive, and the parity path must reject it without decryption.
    let mut encrypted = init_t
        .build_link_data_packet(&link_id, &[0xFF], CONTEXT_KEEPALIVE, &mut rng)
        .unwrap();
    assert!(encrypted.len() > 20);
    let crypto_failures = resp_t.stats().crypto_failures;
    assert!(matches!(
        resp_t.ingest(&mut encrypted, 203, &mut rng, &resp_id),
        IngestResult::Invalid
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().last_inbound, responder_inbound);
    assert_eq!(resp_t.stats().crypto_failures, crypto_failures);

    let initiator_inbound = init_t.get_link(&link_id).unwrap().last_inbound;
    let mut initiator_request = init_t.build_keepalive_packet(&link_id, true, 204).unwrap();
    assert!(matches!(
        init_t.ingest(&mut initiator_request, 205, &mut rng, &init_id),
        IngestResult::Invalid
    ));
    assert_eq!(init_t.get_link(&link_id).unwrap().last_inbound, initiator_inbound);
}

#[test]
fn linkclose_tears_down() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    init_t
        .send_channel_message(&link_id, 0x01, b"local close receipt", 190, &mut rng)
        .unwrap();
    resp_t
        .send_channel_message(&link_id, 0x01, b"remote close receipt", 190, &mut rng)
        .unwrap();
    assert_eq!(init_t.channel_receipt_count(), 1);
    assert_eq!(resp_t.channel_receipt_count(), 1);

    // Initiator closes link
    let close = init_t.build_linkclose_packet(&link_id, &mut rng).unwrap();
    // Initiator's link should be removed
    assert_eq!(init_t.link_count(), 0);
    assert_eq!(init_t.channel_receipt_count(), 0);

    // Responder receives close
    let mut close_buf = close;
    match resp_t.ingest(&mut close_buf, 200, &mut rng, &resp_id) {
        IngestResult::LinkClosed { link_id: lid } => {
            assert_eq!(lid, link_id);
        }
        other => panic!("expected LinkClosed, got {:?}", other),
    }
    assert_eq!(resp_t.link_count(), 0);
    assert_eq!(resp_t.channel_receipt_count(), 0);
}

#[test]
fn link_stale_in_tick() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT first
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Now responder link is Active
    let link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Active);
    let stale_time = link.stale_time;
    let stale_at = link.last_inbound + stale_time;
    let grace = link.stale_grace();
    resp_t
        .send_channel_message(
            &link_id,
            0x01,
            b"stale cleanup receipt",
            stale_at.as_secs(),
            &mut rng,
        )
        .unwrap();
    assert_eq!(resp_t.channel_receipt_count(), 1);

    // Stale begins at two keepalive intervals, with five seconds to revive.
    let result = resp_t.tick_at(stale_at.as_secs(), stale_at);
    assert_eq!(result.closed_links, 0);
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Stale);
    assert_eq!(resp_t.channel_receipt_count(), 1);

    let close_at = stale_at + grace;
    let result = resp_t.tick_at(close_at.as_secs(), close_at);
    assert_eq!(result.closed_links, 1);
    assert_eq!(resp_t.link_count(), 0);
    assert_eq!(resp_t.channel_receipt_count(), 0);
}

#[test]
fn authenticated_link_data_revives_stale_link_during_grace() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    let last_inbound = resp_t.get_link(&link_id).unwrap().last_inbound;
    let stale_at = last_inbound + resp_t.get_link(&link_id).unwrap().stale_time;
    let grace = resp_t.get_link(&link_id).unwrap().stale_grace();
    let result = resp_t.tick_at(stale_at.as_secs(), stale_at);
    assert_eq!(result.closed_links, 0);
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Stale);

    // Authentication failure during grace must not refresh or revive the Link.
    let mut corrupt = init_t
        .build_link_data_packet(&link_id, b"corrupt", CONTEXT_NONE, &mut rng)
        .unwrap();
    *corrupt.last_mut().unwrap() ^= 0x01;
    let corrupt_at = stale_at + MonotonicDuration::from_secs(1);
    assert!(matches!(
        resp_t.ingest_on_at(
            &mut corrupt,
            corrupt_at.as_secs(),
            corrupt_at,
            0,
            &mut rng,
            &resp_id,
        ),
        IngestResult::Invalid
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Stale);
    assert_eq!(
        resp_t.get_link(&link_id).unwrap().last_inbound,
        last_inbound
    );

    let mut valid = init_t
        .build_link_data_packet(&link_id, b"revive", CONTEXT_NONE, &mut rng)
        .unwrap();
    let valid_at = stale_at + MonotonicDuration::from_secs(2);
    assert!(matches!(
        resp_t.ingest_on_at(
            &mut valid,
            valid_at.as_secs(),
            valid_at,
            0,
            &mut rng,
            &resp_id,
        ),
        IngestResult::LinkData {
            link_id: id,
            data,
            context,
        } if id == link_id && data == b"revive" && context == CONTEXT_NONE
    ));
    assert_eq!(resp_t.get_link(&link_id).unwrap().state, LinkState::Active);
    assert_eq!(
        resp_t.get_link(&link_id).unwrap().last_inbound,
        valid_at
    );

    // The old stale-transition deadline no longer applies after revival.
    let old_deadline = stale_at + grace;
    let result = resp_t.tick_at(old_deadline.as_secs(), old_deadline);
    assert_eq!(result.closed_links, 0);
    assert_eq!(resp_t.link_count(), 1);
}

#[test]
fn invalid_lrproof_rejected() {
    let mut rng = rand::thread_rng();
    let init_id = Identity::from_seed(b"initiator-bad-proof").unwrap();
    let resp_id = Identity::from_seed(b"responder-bad-proof").unwrap();

    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["link"], &mut name_buf).unwrap();
    let resp_dest = rete_core::destination_hash(expanded, Some(&resp_id.hash()));

    let mut init_t = TestTransport::new();
    // Register a WRONG identity for the responder dest
    let wrong_id = Identity::from_seed(b"wrong-identity").unwrap();
    init_t.register_identity(resp_dest, wrong_id.public_key(), 100);

    let (init_req, _init_link_id) = init_t
        .initiate_link(resp_dest, &init_id, &mut rng, 100)
        .unwrap();

    // Build a valid proof from the real responder
    let (mut resp_t, _, _) = make_responder(b"responder-bad-proof");
    let mut req_buf = init_req;
    let proof_raw = match resp_t.ingest(&mut req_buf, 100, &mut rng, &resp_id) {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator tries to validate — should fail because wrong identity registered
    let mut proof_buf = proof_raw;
    match init_t.ingest(&mut proof_buf, 101, &mut rng, &init_id) {
        IngestResult::Invalid => {} // expected — signature mismatch
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn link_data_before_active_rejected() {
    let (_, _, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Responder link is in Handshake state (not yet Active, no LRRTT received)
    let link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Handshake);

    // Try to send data on the link — should be able to decrypt but reject
    // because link is not active for regular data
    // Build a data packet directly
    let mut ct_buf = [0u8; MTU];
    let ct_len = link.encrypt(b"too early", &mut rng, &mut ct_buf).unwrap();

    let mut pkt_buf = [0u8; MTU];
    let pkt_len = PacketBuilder::new(&mut pkt_buf)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Link)
        .destination_hash(link_id.as_ref())
        .context(0x00)
        .payload(&ct_buf[..ct_len])
        .build()
        .unwrap();

    let mut raw = pkt_buf[..pkt_len].to_vec();
    match resp_t.ingest(&mut raw, 103, &mut rng, &resp_id) {
        IngestResult::Invalid => {} // expected
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn duplicate_link_request() {
    let mut rng = rand::thread_rng();
    let (mut t, identity, dest_hash) = make_responder(b"responder-dup");

    let initiator = Identity::from_seed(b"initiator-dup").unwrap();
    let request_pkt = build_link_request(&dest_hash, &initiator, &mut rng);

    // First request
    let mut raw1 = request_pkt.clone();
    match t.ingest(&mut raw1, 100, &mut rng, &identity) {
        IngestResult::LinkRequestReceived { .. } => {}
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);

    // Same request again — should be duplicate (same packet hash dedup)
    let mut raw2 = request_pkt.clone();
    match t.ingest(&mut raw2, 101, &mut rng, &identity) {
        IngestResult::Duplicate => {} // packet hash dedup
        other => panic!("expected Duplicate, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);
    assert_eq!(t.stats().packets_received, 2);
    assert_eq!(t.stats().link_requests_received, 1);
    assert_eq!(t.stats().packets_dropped_dedup, 1);
}

#[test]
fn channel_data_over_link() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send a properly-formed channel envelope with CONTEXT_CHANNEL
    let envelope = rete_transport::ChannelEnvelope {
        message_type: 0x01,
        sequence: 0,
        payload: b"channel msg".to_vec(),
    };
    let packed = envelope.pack();
    let pkt = init_t
        .build_link_data_packet(&link_id, &packed, rete_core::CONTEXT_CHANNEL, &mut rng)
        .unwrap();
    let mut buf = pkt;
    match resp_t.ingest(&mut buf, 103, &mut rng, &resp_id) {
        IngestResult::ChannelMessages {
            link_id: lid,
            messages,
            ..
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message_type, 0x01);
            assert_eq!(messages[0].payload, b"channel msg");
        }
        other => panic!("expected ChannelMessages, got {:?}", other),
    }
}

#[test]
fn initiate_link_returns_request() {
    let mut rng = rand::thread_rng();
    let identity = Identity::from_seed(b"initiator-test").unwrap();
    let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

    let mut t = TestTransport::new();
    let (pkt, link_id) = t
        .initiate_link(dest_hash, &identity, &mut rng, 100)
        .unwrap();

    // Should be a parseable LINKREQUEST with dest_type=Single (matching target dest)
    let parsed = Packet::parse(&pkt).unwrap();
    assert_eq!(parsed.packet_type, PacketType::LinkRequest);
    assert_eq!(parsed.dest_type, DestType::Single);

    // Transport should have the link
    assert_eq!(t.link_count(), 1);
    let link = t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Handshake);
}

#[test]
fn outbound_link_table_full_releases_no_request() {
    type TwoLinkTransport = Transport<HeaplessStorage<64, 16, 128, 2>>;

    let identity = Identity::from_seed(b"outbound-capacity").unwrap();
    let destinations = [
        DestHash::from([0x11; TRUNCATED_HASH_LEN]),
        DestHash::from([0x22; TRUNCATED_HASH_LEN]),
        DestHash::from([0x33; TRUNCATED_HASH_LEN]),
    ];
    let mut transport = TwoLinkTransport::new();
    transport.insert_path(destinations[2], Path::direct(10));
    let mut rng = StdRng::seed_from_u64(0xCAFE);

    let (_, first_id) = transport
        .initiate_link(destinations[0], &identity, &mut rng, 100)
        .unwrap();
    let (_, second_id) = transport
        .initiate_link(destinations[1], &identity, &mut rng, 101)
        .unwrap();
    let first_activity = {
        let link = transport.get_link(&first_id).unwrap();
        (link.last_inbound, link.last_outbound)
    };
    let second_activity = {
        let link = transport.get_link(&second_id).unwrap();
        (link.last_inbound, link.last_outbound)
    };

    let mut candidate_rng = rng.clone();
    let (_, candidate_payload) = Link::new_initiator(
        destinations[2],
        identity.ed25519_pub(),
        &mut candidate_rng,
        102,
    );
    let candidate_packet = build_link_request_from_payload(&destinations[2], &candidate_payload);
    let candidate_id = compute_link_id(&candidate_packet).unwrap();
    let packets_sent = transport.stats().packets_sent;
    let links_failed = transport.stats().links_failed;

    assert_eq!(
        transport.initiate_link(destinations[2], &identity, &mut rng, 102),
        Err(SendError::LinkTableFull)
    );
    assert_eq!(transport.link_count(), 2);
    assert!(transport.get_link(&candidate_id).is_none());
    assert_eq!(
        {
            let link = transport.get_link(&first_id).unwrap();
            (link.last_inbound, link.last_outbound)
        },
        first_activity
    );
    assert_eq!(
        {
            let link = transport.get_link(&second_id).unwrap();
            (link.last_inbound, link.last_outbound)
        },
        second_activity
    );
    assert_eq!(
        transport.get_path(&destinations[2]).unwrap().last_accessed,
        10
    );
    assert_eq!(transport.stats().packets_sent, packets_sent);
    assert_eq!(transport.stats().links_failed, links_failed);
}

#[test]
fn outbound_existing_link_id_is_not_replaced_or_reported_full() {
    type TwoLinkTransport = Transport<HeaplessStorage<64, 16, 128, 2>>;

    let identity = Identity::from_seed(b"outbound-existing").unwrap();
    let destination = DestHash::from([0x44; TRUNCATED_HASH_LEN]);
    let other_destination = DestHash::from([0x45; TRUNCATED_HASH_LEN]);
    let mut transport = TwoLinkTransport::new();
    transport.insert_path(destination, Path::direct(10));
    let mut first_rng = StdRng::seed_from_u64(0xFACE);
    let mut repeated_rng = first_rng.clone();

    let (_, link_id) = transport
        .initiate_link(destination, &identity, &mut first_rng, 100)
        .unwrap();
    transport
        .initiate_link(other_destination, &identity, &mut first_rng, 150)
        .unwrap();
    let initial_activity = {
        let link = transport.get_link(&link_id).unwrap();
        (link.last_inbound, link.last_outbound)
    };

    assert_eq!(
        transport.initiate_link(destination, &identity, &mut repeated_rng, 200),
        Err(SendError::LinkAlreadyExists)
    );
    assert_eq!(transport.link_count(), 2);
    assert_eq!(
        {
            let link = transport.get_link(&link_id).unwrap();
            (link.last_inbound, link.last_outbound)
        },
        initial_activity
    );
    assert_eq!(transport.get_path(&destination).unwrap().last_accessed, 100);
}

#[test]
fn inbound_link_table_full_emits_no_proof() {
    let (mut transport, responder, destination) = make_bounded_responder::<2>(b"inbound-capacity");
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let mut retained_ids = Vec::new();

    for index in 0..2 {
        let initiator = Identity::from_seed(&[index + 1; 32]).unwrap();
        let mut request = build_link_request(&destination, &initiator, &mut rng);
        match transport.ingest(&mut request, 100 + u64::from(index), &mut rng, &responder) {
            IngestResult::LinkRequestReceived { link_id, proof_raw } => {
                assert!(!proof_raw.is_empty());
                retained_ids.push(link_id);
            }
            other => panic!("expected retained LINKREQUEST, got {other:?}"),
        }
    }

    let third = Identity::from_seed(&[0x33; 32]).unwrap();
    let mut request = build_link_request(&destination, &third, &mut rng);
    let rejected_id = compute_link_id(&request).unwrap();
    assert!(matches!(
        transport.ingest(&mut request, 102, &mut rng, &responder),
        IngestResult::LinkTableFull {
            link_id,
            table: LinkTableKind::Owned,
        } if link_id == rejected_id
    ));

    assert_eq!(transport.link_count(), 2);
    assert!(retained_ids
        .iter()
        .all(|id| transport.get_link(id).is_some()));
    assert!(transport.get_link(&rejected_id).is_none());
    assert_eq!(transport.stats().packets_received, 3);
    assert_eq!(transport.stats().link_requests_received, 2);
    assert_eq!(transport.stats().packets_dropped_invalid, 0);
    assert_eq!(transport.stats().packets_dropped_dedup, 0);
    assert_eq!(transport.stats().links_failed, 0);
    assert_eq!(transport.stats().crypto_failures, 0);
}

#[test]
fn timed_out_responder_handshakes_recover_bounded_link_capacity() {
    let (mut transport, responder, destination) =
        make_bounded_responder::<4>(b"inbound-timeout-capacity");
    let mut rng = StdRng::seed_from_u64(0xBAD5_EED);
    let origin = MonotonicInstant::from_micros(200_500_000);
    let timeout = MonotonicDuration::from_secs(366);
    let mut retained_ids = Vec::new();

    for index in 0u8..4 {
        let initiator = Identity::from_seed(&[index + 1; 32]).unwrap();
        let mut request = build_link_request(&destination, &initiator, &mut rng);
        match transport.ingest_on_at(
            &mut request,
            origin.as_secs(),
            origin,
            3,
            &mut rng,
            &responder,
        ) {
            IngestResult::LinkRequestReceived { link_id, proof_raw } => {
                assert!(!proof_raw.is_empty());
                retained_ids.push(link_id);
            }
            other => panic!("expected retained LINKREQUEST, got {other:?}"),
        }
    }

    let candidate = Identity::from_seed(b"inbound-timeout-capacity-candidate").unwrap();
    let mut rejected = build_link_request(&destination, &candidate, &mut rng);
    assert!(matches!(
        transport.ingest_on_at(
            &mut rejected,
            origin.as_secs(),
            origin,
            3,
            &mut rng,
            &responder,
        ),
        IngestResult::LinkTableFull {
            table: LinkTableKind::Owned,
            ..
        }
    ));
    assert_eq!(transport.link_count(), 4);
    assert!(retained_ids
        .iter()
        .all(|link_id| transport.get_link(link_id).is_some()));

    let deadline = origin + timeout;
    assert_eq!(
        transport
            .tick_at(
                deadline.as_secs(),
                deadline - MonotonicDuration::from_micros(1),
            )
            .closed_links,
        0
    );
    assert_eq!(transport.link_count(), 4);

    let failed_before = transport.stats().links_failed;
    let closed_before = transport.stats().links_closed;
    assert_eq!(
        transport.tick_at(deadline.as_secs(), deadline).closed_links,
        4
    );
    assert_eq!(transport.link_count(), 0);
    assert_eq!(transport.stats().links_failed, failed_before);
    assert_eq!(transport.stats().links_closed, closed_before + 4);

    // A real retry has fresh ephemeral material and can immediately consume
    // one of the slots reclaimed by responder lifecycle maintenance.
    let mut retry = build_link_request(&destination, &candidate, &mut rng);
    assert!(matches!(
        transport.ingest_on_at(
            &mut retry,
            deadline.as_secs(),
            deadline,
            3,
            &mut rng,
            &responder,
        ),
        IngestResult::LinkRequestReceived { proof_raw, .. } if !proof_raw.is_empty()
    ));
    assert_eq!(transport.link_count(), 1);
}

#[test]
fn inbound_existing_link_id_wins_over_full_capacity() {
    let (mut transport, responder, destination) = make_bounded_responder::<2>(b"inbound-existing");
    let initiator = Identity::from_seed(b"inbound-existing-initiator").unwrap();
    let mut rng = StdRng::seed_from_u64(0xABCD);
    let (_, canonical_payload) =
        Link::new_initiator(destination, initiator.ed25519_pub(), &mut rng, 100);
    let mut legacy_request =
        build_link_request_from_payload(&destination, &canonical_payload[..64]);
    let mut current_request = build_link_request_from_payload(&destination, &canonical_payload);
    let legacy_id = compute_link_id(&legacy_request).unwrap();
    assert_eq!(legacy_id, compute_link_id(&current_request).unwrap());

    assert!(matches!(
        transport.ingest(&mut legacy_request, 100, &mut rng, &responder),
        IngestResult::LinkRequestReceived { .. }
    ));
    let initial_activity = {
        let link = transport.get_link(&legacy_id).unwrap();
        (link.last_inbound, link.last_outbound)
    };

    let filler = Identity::from_seed(b"inbound-existing-filler").unwrap();
    let mut filler_request = build_link_request(&destination, &filler, &mut rng);
    assert!(matches!(
        transport.ingest(&mut filler_request, 150, &mut rng, &responder),
        IngestResult::LinkRequestReceived { .. }
    ));
    assert!(matches!(
        transport.ingest(&mut current_request, 200, &mut rng, &responder),
        IngestResult::Duplicate
    ));

    assert_eq!(transport.link_count(), 2);
    assert_eq!(
        {
            let link = transport.get_link(&legacy_id).unwrap();
            (link.last_inbound, link.last_outbound)
        },
        initial_activity
    );
    assert_eq!(transport.stats().packets_received, 3);
    assert_eq!(transport.stats().link_requests_received, 2);
    assert_eq!(transport.stats().packets_dropped_dedup, 0);
    assert_eq!(transport.stats().packets_dropped_invalid, 0);
    assert_eq!(transport.stats().links_failed, 0);
    assert_eq!(transport.stats().crypto_failures, 0);
}

#[test]
fn capacity_rejection_is_deduplicated_but_a_fresh_request_can_retry() {
    let (mut transport, responder, destination) = make_bounded_responder::<2>(b"inbound-retry");
    let mut rng = StdRng::seed_from_u64(0xD00D);

    let first = Identity::from_seed(b"inbound-retry-first").unwrap();
    let mut first_request = build_link_request(&destination, &first, &mut rng);
    let first_id = compute_link_id(&first_request).unwrap();
    assert!(matches!(
        transport.ingest(&mut first_request, 100, &mut rng, &responder),
        IngestResult::LinkRequestReceived { link_id, .. } if link_id == first_id
    ));

    let second = Identity::from_seed(b"inbound-retry-second").unwrap();
    let mut second_request = build_link_request(&destination, &second, &mut rng);
    assert!(matches!(
        transport.ingest(&mut second_request, 101, &mut rng, &responder),
        IngestResult::LinkRequestReceived { .. }
    ));

    let candidate = Identity::from_seed(b"inbound-retry-candidate").unwrap();
    let rejected_request = build_link_request(&destination, &candidate, &mut rng);
    let rejected_id = compute_link_id(&rejected_request).unwrap();
    let mut first_attempt = rejected_request.clone();
    assert!(matches!(
        transport.ingest(&mut first_attempt, 102, &mut rng, &responder),
        IngestResult::LinkTableFull {
            link_id,
            table: LinkTableKind::Owned,
        } if link_id == rejected_id
    ));

    transport
        .build_linkclose_packet(&first_id, &mut rng)
        .unwrap();
    assert_eq!(transport.link_count(), 1);

    // Reticulum's packet-level deduplication precedes local dispatch. Keep the
    // rejected packet in that window so an exact replay cannot repeatedly
    // force handshake work while a node is saturated.
    let mut exact_replay = rejected_request.clone();
    let mut expected_rng = rng.clone();
    assert!(matches!(
        transport.ingest(&mut exact_replay, 103, &mut rng, &responder),
        IngestResult::Duplicate
    ));
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert_eq!(transport.link_count(), 1);

    // A real retry creates fresh ephemeral Link material and is admitted once
    // capacity is available.
    let mut fresh_request = build_link_request(&destination, &candidate, &mut rng);
    let fresh_id = compute_link_id(&fresh_request).unwrap();
    assert_ne!(fresh_id, rejected_id);
    assert!(matches!(
        transport.ingest(&mut fresh_request, 104, &mut rng, &responder),
        IngestResult::LinkRequestReceived { link_id, proof_raw }
            if link_id == fresh_id && !proof_raw.is_empty()
    ));

    assert_eq!(transport.link_count(), 2);
    assert_eq!(transport.stats().packets_received, 5);
    assert_eq!(transport.stats().link_requests_received, 3);
    assert_eq!(transport.stats().packets_dropped_dedup, 1);
    assert_eq!(transport.stats().packets_dropped_invalid, 0);
    assert_eq!(transport.stats().links_failed, 0);
    assert_eq!(transport.stats().crypto_failures, 0);
}

// ---------------------------------------------------------------------------
// Keepalive timer tests
// ---------------------------------------------------------------------------

#[test]
fn transport_keepalive_sent_when_due() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    let link = init_t.get_link(&link_id).unwrap();
    let ka_interval = link.keepalive_interval;
    let activated_at = link.last_inbound;

    // Not due yet
    let keepalives = init_t.build_pending_keepalives_at(activated_at, &mut rng);
    assert!(keepalives.is_empty(), "no keepalive should be needed yet");

    let keepalives = init_t.build_pending_keepalives_at(
        activated_at + ka_interval - MonotonicDuration::from_micros(1),
        &mut rng,
    );
    assert!(
        keepalives.is_empty(),
        "half-interval probes are not RNS-compatible"
    );

    // Initiator probes after a full interval of inbound silence.
    let keepalives =
        init_t.build_pending_keepalives_at(activated_at + ka_interval, &mut rng);
    assert_eq!(keepalives.len(), 1, "should produce one keepalive");

    // Verify it's a parseable packet
    let parsed = Packet::parse(&keepalives[0]).unwrap();
    assert_eq!(parsed.packet_type, PacketType::Data);
    assert_eq!(parsed.dest_type, DestType::Link);
    assert_eq!(parsed.context, CONTEXT_KEEPALIVE);
    assert_eq!(parsed.payload, &[0xFF]);
    assert_eq!(keepalives[0].len(), 20);

    // The previous probe rate-limits deterministic retries for a full interval.
    assert!(init_t
        .build_pending_keepalives_at(
            activated_at + ka_interval * 2 - MonotonicDuration::from_micros(1),
            &mut rng,
        )
        .is_empty());
    assert_eq!(
        init_t
            .build_pending_keepalives_at(activated_at + ka_interval * 2, &mut rng)
            .len(),
        1
    );

    // Responders never initiate requests, even after long silence.
    assert!(resp_t
        .build_pending_keepalives_at(activated_at + ka_interval * 100, &mut rng)
        .is_empty());
}

// ---------------------------------------------------------------------------
// Channel through Transport tests
// ---------------------------------------------------------------------------

#[test]
fn channel_send_receive_through_transport() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate both sides
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends channel message
    let pkt = init_t
        .send_channel_message(&link_id, 0x42, b"hello channel", 200, &mut rng)
        .expect("should send channel message");

    // Responder ingests
    let mut buf = pkt;
    match resp_t.ingest(&mut buf, 200, &mut rng, &resp_id) {
        IngestResult::ChannelMessages {
            link_id: lid,
            messages,
            ..
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message_type, 0x42);
            assert_eq!(messages[0].payload, b"hello channel");
        }
        other => panic!("expected ChannelMessages, got {:?}", other),
    }
}

#[test]
fn oversized_channel_send_rejects_before_entropy_or_channel_state() {
    let (mut initiator, _initiator_id, _responder, _responder_id, link_id) = full_handshake();
    let last_outbound = initiator.get_link(&link_id).unwrap().last_outbound;
    let oversized = vec![
        0x55;
        rete_transport::LINK_MDU - rete_transport::ENVELOPE_HEADER_SIZE + 1
    ];

    assert_eq!(
        initiator.send_channel_message(
            &link_id,
            0x01,
            &oversized,
            200,
            &mut PanicRng,
        ),
        Err(SendError::PacketBuild(rete_core::Error::PayloadTooLarge))
    );
    assert!(initiator.get_link(&link_id).unwrap().channel().is_none());
    assert_eq!(initiator.get_link(&link_id).unwrap().last_outbound, last_outbound);
    assert_eq!(initiator.channel_receipt_count(), 0);
}

#[test]
fn channel_reorder_through_transport() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send two channel messages
    let pkt0 = init_t
        .send_channel_message(&link_id, 0x01, b"msg0", 200, &mut rng)
        .unwrap();
    let pkt1 = init_t
        .send_channel_message(&link_id, 0x01, b"msg1", 201, &mut rng)
        .unwrap();

    // Deliver seq 1 first (out of order)
    let mut buf1 = pkt1;
    match resp_t.ingest(&mut buf1, 202, &mut rng, &resp_id) {
        IngestResult::Buffered { .. } => {} // out-of-order, held for reordering
        other => panic!("expected Buffered (out-of-order), got {:?}", other),
    }

    // Now deliver seq 0 — should flush both
    let mut buf0 = pkt0;
    match resp_t.ingest(&mut buf0, 203, &mut rng, &resp_id) {
        IngestResult::ChannelMessages { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].sequence, 0);
            assert_eq!(messages[1].sequence, 1);
            assert_eq!(messages[0].payload, b"msg0");
            assert_eq!(messages[1].payload, b"msg1");
        }
        other => panic!("expected ChannelMessages with 2 messages, got {:?}", other),
    }
}

#[test]
fn channel_retransmit_on_timeout() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send channel message from initiator (marks sent_at=200)
    let pkt = init_t
        .send_channel_message(&link_id, 0x01, b"retry me", 200, &mut rng)
        .unwrap();
    let initial_hash = Packet::parse(&pkt).unwrap().compute_hash();
    assert_eq!(init_t.channel_receipt_count(), 1);

    // Before timeout: no retransmits
    let retx = init_t.pending_channel_retransmits(210, &mut rng);
    assert!(retx.is_empty());

    // After timeout (15s default)
    let retx = init_t.pending_channel_retransmits(216, &mut rng);
    assert_eq!(retx.len(), 1, "should retransmit one message");
    let retry_hash = Packet::parse(&retx[0]).unwrap().compute_hash();
    assert_ne!(retry_hash, initial_hash, "retry must use fresh ciphertext");
    assert_eq!(
        init_t.channel_receipt_count(),
        1,
        "retry must replace rather than append its proof receipt"
    );
}

#[test]
fn channel_send_at_monotonic_zero_still_retries() {
    let (mut initiator, _initiator_id, _responder, _responder_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    initiator
        .send_channel_message(&link_id, 0x01, b"boot-time send", 0, &mut rng)
        .unwrap();
    assert!(initiator
        .pending_channel_retransmits(15, &mut rng)
        .is_empty());
    assert_eq!(
        initiator
            .pending_channel_retransmits(16, &mut rng)
            .len(),
        1
    );
    assert_eq!(initiator.channel_receipt_count(), 1);
}

#[test]
fn identical_ciphertext_retry_is_rejected_without_advancing_channel_state() {
    let (mut initiator, _initiator_id, _responder, _responder_id, link_id) = full_handshake();
    let mut initial_rng = StdRng::seed_from_u64(0x5eed);
    let initial = initiator
        .send_channel_message(
            &link_id,
            0x01,
            b"repeat deterministic IV",
            200,
            &mut initial_rng,
        )
        .unwrap();
    let initial_hash = Packet::parse(&initial).unwrap().compute_hash();
    let last_outbound = initiator.get_link(&link_id).unwrap().last_outbound;
    let window = initiator
        .get_link(&link_id)
        .unwrap()
        .channel()
        .unwrap()
        .window();
    let pending = match initiator.pending_channel_maintenance(216).pop().unwrap() {
        rete_transport::ChannelMaintenanceAction::Retransmit(pending) => pending,
        other => panic!("expected retry, got {other:?}"),
    };

    // Replaying the IV stream constructs the exact same encrypted packet. It
    // cannot become a new attempt, and the old receipt must remain authoritative.
    let mut repeated_rng = StdRng::seed_from_u64(0x5eed);
    assert_eq!(
        initiator.retry_channel_message(pending, 216, true, &mut repeated_rng),
        Err(SendError::ReceiptHashAlreadyTracked)
    );
    let channel = initiator.get_link(&link_id).unwrap().channel().unwrap();
    assert_eq!(channel.pending_count(), 1);
    assert_eq!(channel.next_tx_sequence(), 1);
    assert_eq!(channel.window(), window);
    assert_eq!(initiator.get_link(&link_id).unwrap().last_outbound, last_outbound);
    assert_eq!(initiator.channel_receipt_count(), 1);

    let pending = match initiator.pending_channel_maintenance(216).pop().unwrap() {
        rete_transport::ChannelMaintenanceAction::Retransmit(pending) => pending,
        other => panic!("failed retry should remain due, got {other:?}"),
    };
    let mut fresh_rng = StdRng::seed_from_u64(0x5eee);
    let retry = initiator
        .retry_channel_message(pending, 216, true, &mut fresh_rng)
        .unwrap();
    assert_ne!(Packet::parse(&retry).unwrap().compute_hash(), initial_hash);
    assert_eq!(initiator.channel_receipt_count(), 1);
}

#[test]
fn full_receipt_table_rejects_new_send_but_allows_retry_replacement() {
    let (mut initiator, _initiator_identity, _responder, _responder_identity, link_id) =
        bounded_handshake::<2>();
    let mut rng = rand::thread_rng();

    let initial_0 = initiator
        .send_channel_message(&link_id, 0x01, b"occupy sole slot", 200, &mut rng)
        .unwrap();
    let initial_1 = initiator
        .send_channel_message(&link_id, 0x01, b"occupy second slot", 200, &mut rng)
        .unwrap();
    let initial_hashes = [
        Packet::parse(&initial_0).unwrap().compute_hash(),
        Packet::parse(&initial_1).unwrap().compute_hash(),
    ];
    let channel = initiator.get_link(&link_id).unwrap().channel().unwrap();
    assert_eq!(channel.pending_count(), 2);
    assert_eq!(channel.next_tx_sequence(), 2);
    assert_eq!(initiator.channel_receipt_count(), 2);
    let last_outbound = initiator.get_link(&link_id).unwrap().last_outbound;

    assert_eq!(
        initiator.send_channel_message(
            &link_id,
            0x01,
            b"must not mutate",
            201,
            &mut PanicRng,
        ),
        Err(SendError::ReceiptTableFull)
    );
    let channel = initiator.get_link(&link_id).unwrap().channel().unwrap();
    assert_eq!(channel.pending_count(), 2);
    assert_eq!(channel.next_tx_sequence(), 2);
    assert_eq!(initiator.get_link(&link_id).unwrap().last_outbound, last_outbound);
    assert_eq!(initiator.channel_receipt_count(), 2);

    let retries = initiator.pending_channel_retransmits(216, &mut rng);
    assert_eq!(retries.len(), 2);
    for (retry, initial_hash) in retries.iter().zip(initial_hashes) {
        assert_ne!(Packet::parse(retry).unwrap().compute_hash(), initial_hash);
    }
    assert_eq!(initiator.channel_receipt_count(), 2);
}

#[test]
fn channel_window_blocks_at_capacity() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Fill the window (DEFAULT_WINDOW = 4)
    for i in 0..rete_transport::DEFAULT_WINDOW {
        assert!(
            init_t
                .send_channel_message(&link_id, 0x01, &[i as u8], 200, &mut rng)
                .is_ok(),
            "message {} should succeed",
            i
        );
    }

    // Next should be blocked
    assert!(
        init_t
            .send_channel_message(&link_id, 0x01, b"blocked", 201, &mut rng)
            .is_err(),
        "window should be full"
    );
}

#[test]
fn channel_teardown_on_max_retries() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send one message
    let _pkt = init_t
        .send_channel_message(&link_id, 0x01, b"will fail", 100, &mut rng)
        .unwrap();

    // Exhaust retries (MAX_RETRIES = 5, timeout = 15s)
    let mut now = 100u64;
    for _ in 0..=rete_transport::channel::MAX_RETRIES {
        now += 16; // past retry_timeout
        let _ = init_t.pending_channel_retransmits(now, &mut rng);
    }

    // Link should be removed (teardown)
    assert_eq!(
        init_t.link_count(),
        0,
        "link should be removed after max retries"
    );
    assert_eq!(
        init_t.channel_receipt_count(),
        0,
        "channel teardown must reclaim its proof receipt"
    );
}

#[test]
fn proof_after_teardown_discovery_cancels_stale_teardown_token() {
    let (mut initiator, initiator_identity, _responder, responder_identity, link_id) =
        full_handshake();
    let mut rng = rand::thread_rng();

    let mut latest = initiator
        .send_channel_message(&link_id, 0x01, b"late proof", 100, &mut rng)
        .unwrap();
    let mut now = 100u64;
    for _ in 0..rete_transport::channel::MAX_RETRIES {
        now += 16;
        let retries = initiator.pending_channel_retransmits(now, &mut rng);
        assert_eq!(retries.len(), 1);
        latest = retries.into_iter().next().unwrap();
    }

    now += 16;
    let pending = match initiator.pending_channel_maintenance(now).pop().unwrap() {
        rete_transport::ChannelMaintenanceAction::Teardown(pending) => pending,
        other => panic!("expected terminal channel maintenance, got {other:?}"),
    };
    let latest_hash = Packet::parse(&latest).unwrap().compute_hash();
    let mut proof = TestTransport::build_link_proof_packet(
        &responder_identity,
        &latest_hash,
        &link_id,
    )
    .unwrap();
    assert!(matches!(
        initiator.ingest(&mut proof, now, &mut rng, &initiator_identity),
        IngestResult::ProofReceived { packet_hash } if packet_hash == latest_hash
    ));

    assert!(!initiator.commit_channel_teardown(pending));
    assert_eq!(initiator.link_count(), 1);
    assert_eq!(initiator.channel_receipt_count(), 0);
    assert_eq!(
        initiator
            .get_link(&link_id)
            .unwrap()
            .channel()
            .unwrap()
            .pending_count(),
        0
    );
}

// ---------------------------------------------------------------------------
// Dynamic keepalive integration tests
// ---------------------------------------------------------------------------

#[test]
fn link_handshake_sets_dynamic_keepalive() {
    // After full handshake through Transport, verify link's keepalive_interval
    // was updated from the default 360.
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Initiator link should have updated keepalive (RTT = 101 - 100 = 1s)
    let init_link = init_t.get_link(&link_id).unwrap();
    // RTT=1s → keepalive = 1.0 * (360/1.75) ≈ 205.7 → 205
    assert_ne!(
        init_link.keepalive_interval,
        MonotonicDuration::from_secs(360),
        "initiator keepalive should be updated from default 360"
    );
    assert!(init_link.rtt > 0.0, "initiator RTT should be set");

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet_for_rtt(&link_id, 1.0, &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Responder link should also have updated keepalive (RTT = 102 - 100 = 2s)
    let resp_link = resp_t.get_link(&link_id).unwrap();
    assert!(
        resp_link.rtt > 0.0,
        "responder RTT should be set after LRRTT"
    );
    assert_eq!(
        resp_link.state,
        rete_transport::LinkState::Active,
        "responder link should be active"
    );
}
