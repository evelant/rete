use rand::{rngs::StdRng, SeedableRng};
use rete_core::{DestType, Identity, PacketBuilder, PacketType, MTU};
use rete_stack::{IngestRejection, LinkTableKind, NodeCore};
use rete_transport::{HeaplessStorage, Link};

type TwoLinkNodeCore = NodeCore<HeaplessStorage<64, 16, 128, 2>>;

fn build_request(
    destination: rete_core::DestHash,
    initiator: &Identity,
    rng: &mut StdRng,
) -> Vec<u8> {
    let (_, payload) = Link::new_initiator(destination, initiator.ed25519_pub(), rng, 100);
    let mut buffer = [0u8; MTU];
    let length = PacketBuilder::new(&mut buffer)
        .packet_type(PacketType::LinkRequest)
        .dest_type(DestType::Single)
        .destination_hash(destination.as_ref())
        .context(0x00)
        .payload(&payload)
        .build()
        .unwrap();
    buffer[..length].to_vec()
}

#[test]
fn node_core_link_capacity_emits_no_event_or_proof() {
    let identity = Identity::from_seed(b"node-core-link-capacity").unwrap();
    let mut core = TwoLinkNodeCore::new(identity, "testapp", &["aspect1"]).unwrap();
    let destination = *core.dest_hash();
    let mut rng = StdRng::seed_from_u64(0x1234);

    for seed in [
        b"node-core-first-link".as_slice(),
        b"node-core-second-link".as_slice(),
    ] {
        let initiator = Identity::from_seed(seed).unwrap();
        let request = build_request(destination, &initiator, &mut rng);
        let outcome = core.handle_ingest(&request, 100, 0, &mut rng);
        assert!(outcome.events.is_empty());
        assert_eq!(outcome.packets.len(), 1);
    }

    let third_initiator = Identity::from_seed(b"node-core-third-link").unwrap();
    let third = build_request(destination, &third_initiator, &mut rng);
    let outcome = core.handle_ingest(&third, 102, 0, &mut rng);
    assert!(outcome.events.is_empty());
    assert!(outcome.packets.is_empty());
    let third_id = rete_transport::compute_link_id(&third).unwrap();
    assert_eq!(
        outcome.rejection,
        Some(IngestRejection::LinkTableFull {
            link_id: third_id,
            table: LinkTableKind::Owned,
        })
    );
}
