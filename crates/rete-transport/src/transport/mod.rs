//! Core Transport struct — path table, announce queue, packet processing, links.

mod announce;
mod link;
mod path;
mod receipt;
mod resource;
pub use link::{ChannelMaintenanceAction, PendingChannelRetry, PendingChannelTeardown};
pub use resource::ResourceOptions;

use alloc::vec::Vec;
use core::mem::MaybeUninit;

/// Relay debug logging — only available when the `relay-debug` feature is enabled.
macro_rules! relay_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "relay-debug")]
        tracing::trace!($($arg)*);
    };
}

/// Format first 4 bytes of a hash as hex for compact logging.
#[cfg(feature = "relay-debug")]
pub(self) fn hex_short(h: &[u8]) -> alloc::string::String {
    use alloc::format;
    if h.len() >= 4 {
        format!("{:02x}{:02x}{:02x}{:02x}..", h[0], h[1], h[2], h[3])
    } else {
        format!("{:?}", h)
    }
}

use crate::dedup::DedupWindow;
use crate::link::{compute_link_id, is_valid_link_request_payload_len};
use crate::receipt::{
    LinkDataReceiptTable, ReceiptCandidate, ReceiptSinkFull, ReceiptTable, ReceiptTerminal,
    ReceiptTerminalReservation, ReceiptTerminalSink,
};
use crate::resource::Resource;
use crate::storage::{StorageMap, TransportStorage};
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestHash, DestType, HeaderType, Identity, IdentityHash, LinkId, MonotonicInstant, Packet, PacketType,
    CONTEXT_KEEPALIVE, CONTEXT_LRPROOF, CONTEXT_NONE, CONTEXT_RESOURCE_PRF, TRUNCATED_HASH_LEN,
};

// ---------------------------------------------------------------------------
// Protocol constants (from Python Transport.py)
// ---------------------------------------------------------------------------

/// Announce retransmission delay base (seconds).
pub const PATHFINDER_G: u64 = 5;

/// Maximum retransmission count per announce.
pub const PATHFINDER_R: u8 = 1;

/// Announce retransmission random window (milliseconds, 0-500ms).
/// Python: `PATHFINDER_RW = 0.5` — we use millis for integer math.
pub const PATHFINDER_RW_MS: u64 = 500;

/// Maximum hop count for announce retransmission.
pub const PATHFINDER_M: u8 = 128;

/// Maximum local rebroadcasts heard before stopping retransmission.
/// Python: `LOCAL_REBROADCASTS_MAX = 2`
pub const LOCAL_REBROADCASTS_MAX: u8 = 2;

/// Grace period (seconds) before sending a path response.
/// Python: `PATH_REQUEST_GRACE = 0.4` — we use 1s since we work in integer seconds.
pub const PATH_REQUEST_GRACE: u64 = 1;

/// Whether an incoming physical-interface packet has Python Reticulum's
/// accepted path-request envelope.
///
/// Python increments the ingress hop before packet filtering and accepts PLAIN
/// non-announce packets only through post-increment hop one, so the wire hop
/// must be zero. HEADER_2 ownership is validated separately against the local
/// transport identity. Context is intentionally unrestricted by the reference
/// handler.
pub fn is_path_request_ingress(packet: &Packet<'_>) -> bool {
    packet.packet_type == PacketType::Data
        && packet.dest_type == DestType::Plain
        && packet.destination_hash == PATH_REQUEST_DEST.as_ref()
        && packet.hops == 0
}

/// Default announce rate target (seconds between announces per destination).
/// Python: interface-configurable, defaults to None (disabled).
/// Set to 0 to disable rate limiting (matches Python default).
pub const ANNOUNCE_RATE_TARGET: u64 = 0;

/// Number of rate violations allowed before blocking.
/// Python: interface-configurable, typically 10.
pub const ANNOUNCE_RATE_GRACE: u8 = 10;

/// Penalty duration (seconds) added when rate limit is exceeded.
/// Python: interface-configurable, typically 7200s.
pub const ANNOUNCE_RATE_PENALTY: u64 = 7200;

/// Path expiry time in seconds (7 days).
pub const PATH_EXPIRES: u64 = 604800;

/// Reverse table entry timeout in seconds (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 480;

/// Default receipt proof timeout in seconds.
pub const RECEIPT_TIMEOUT: u64 = 30;

/// Minimum seconds between retry REQs for stalled receiver resources.
pub const RESOURCE_RETRY_THRESHOLD_SECS: u64 = 10;

/// Maximum pending outbound resource packets (parts + HMUs) queued per tick.
///
/// `resource_outbound` is drained to the caller after every ingest/tick call,
/// so this bounds a single burst, not steady-state queue depth.
const RESOURCE_OUTBOUND_MAX: usize = 256;

/// Errors from transport-layer send operations.
///
/// Returned by methods that build or encrypt outbound packets, where multiple
/// distinct failure modes were previously collapsed into `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// No known path or cached identity for the destination.
    UnknownDestination,
    /// A Link with the generated ID already exists.
    LinkAlreadyExists,
    /// The bounded owned-Link table has no capacity for another Link.
    LinkTableFull,
    /// Link not found in the link table.
    LinkNotFound,
    /// Link exists but is not in Active state (still Pending/Handshake/Stale/Closed).
    LinkNotActive,
    /// A keepalive request/response was requested by the wrong Link role.
    KeepaliveRoleMismatch,
    /// A locally owned Link packet has no authoritative runtime interface.
    LinkInterfaceUnknown,
    /// Channel send window is full (back-pressure).
    WindowFull,
    /// A bounded DATA, Link DATA, or channel receipt table has no free entry.
    ReceiptTableFull,
    /// Another outstanding receipt already uses this packet's truncated hash.
    ReceiptHashAlreadyTracked,
    /// A compatibility API could not reserve owned packet output before
    /// mutating protocol state.
    OutputAllocationFailed,
    /// Request data was not exactly one complete encoded MessagePack value.
    InvalidRequestValue,
    /// The non-repeating outbound protocol-token namespace is exhausted.
    ProtocolTokenExhausted,
    /// Internal Link state rejected assignment of a freshly allocated token.
    ProtocolTokenAssignmentFailed,
    /// Cryptographic operation failed (encrypt, sign, ECDH).
    Crypto(rete_core::Error),
    /// Packet building failed (buffer too small, invalid fields).
    PacketBuild(rete_core::Error),
    /// Resource limit reached (resource table full).
    ResourceLimit,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::UnknownDestination => write!(f, "unknown destination (no cached identity)"),
            SendError::LinkAlreadyExists => write!(f, "link already exists"),
            SendError::LinkTableFull => write!(f, "owned link table full"),
            SendError::LinkNotFound => write!(f, "link not found"),
            SendError::LinkNotActive => write!(f, "link not active"),
            SendError::KeepaliveRoleMismatch => {
                write!(f, "keepalive packet does not match local link role")
            }
            SendError::LinkInterfaceUnknown => write!(f, "link interface is not bound"),
            SendError::WindowFull => write!(f, "channel window full"),
            SendError::ReceiptTableFull => write!(f, "packet receipt table full"),
            SendError::ReceiptHashAlreadyTracked => {
                write!(f, "packet receipt hash already tracked")
            }
            SendError::OutputAllocationFailed => {
                write!(f, "could not reserve outbound packet storage")
            }
            SendError::InvalidRequestValue => {
                write!(f, "request data is not exactly one MessagePack value")
            }
            SendError::ProtocolTokenExhausted => {
                write!(f, "outbound protocol token namespace exhausted")
            }
            SendError::ProtocolTokenAssignmentFailed => {
                write!(f, "outbound protocol token assignment failed")
            }
            SendError::Crypto(e) => write!(f, "crypto error: {e}"),
            SendError::PacketBuild(e) => write!(f, "packet build error: {e}"),
            SendError::ResourceLimit => write!(f, "resource table full"),
        }
    }
}

/// A receipt for a channel message awaiting proof-of-delivery.
#[derive(Debug, Clone)]
pub struct ChannelReceipt {
    /// Link the channel message was sent on.
    pub link_id: LinkId,
    /// Complete hash of the exact outbound channel packet being proven.
    pub packet_hash: [u8; 32],
    /// Sequence number in the channel.
    pub sequence: u16,
    /// Monotonic timestamp when sent.
    pub sent_at: u64,
}

/// Destination hash for `rnstransport.path.request` (PLAIN, no identity).
///
/// Precomputed: `destination_hash("rnstransport.path.request", None)`.
pub const PATH_REQUEST_DEST: DestHash = DestHash::new([
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61,
]);

// ---------------------------------------------------------------------------
// ReverseEntry — tracks forwarded packets for reply routing
// ---------------------------------------------------------------------------

/// An entry in the reverse table, keyed by truncated packet hash.
///
/// Used to route replies back along the path the original packet traversed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReverseEntry {
    /// Monotonic timestamp when this entry was created.
    pub timestamp: u64,
    /// Interface index the original packet was received on.
    pub received_on: u8,
    /// Interface index the packet was forwarded to.
    pub forwarded_to: u8,
}

/// An entry in the link table, keyed by link_id.
///
/// Used to bidirectionally route link traffic (DATA, PROOF, etc.)
/// through a transport relay for the lifetime of the link.
/// Matches Python RNS `Transport.link_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTableEntry {
    /// Monotonic timestamp when this entry was created.
    pub timestamp: u64,
    /// Interface the LINKREQUEST was received on (toward initiator).
    /// Matches Python `IDX_LT_RCVD_IF`.
    pub received_on: u8,
    /// Interface the LINKREQUEST was forwarded toward (toward responder).
    /// Matches Python `IDX_LT_NH_IF`.
    pub outbound_to: u8,
    /// Hop count from initiator side when LINKREQUEST arrived (post-increment).
    /// Matches Python `IDX_LT_HOPS`.
    pub inbound_hops: u8,
    /// Remaining hops toward responder (from path table).
    /// Matches Python `IDX_LT_REM_HOPS`.
    pub outbound_hops: u8,
    /// Destination hash of the link target.
    pub destination_hash: DestHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayLinkAdmission {
    Inserted,
    Existing,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReverseRouteAdmission {
    Inserted,
    Existing,
    Conflict,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Header2Ownership {
    Header1,
    Announce,
    Own,
    Foreign,
}

fn header2_ownership(packet: &Packet<'_>, local_identity: IdentityHash) -> Header2Ownership {
    if packet.header_type == HeaderType::Header1 {
        Header2Ownership::Header1
    } else if packet.packet_type == PacketType::Announce {
        // Python RNS deliberately excludes ANNOUNCE from transport-id
        // ownership filtering. Its transport header describes the learned
        // path; it does not select a single transport instance as owner.
        Header2Ownership::Announce
    } else if packet
        .transport_id
        .is_some_and(|transport_id| IdentityHash::from_slice(transport_id) == local_identity)
    {
        Header2Ownership::Own
    } else {
        Header2Ownership::Foreign
    }
}

fn normalize_owned_header2(raw: &mut [u8]) -> usize {
    debug_assert!(raw.len() > 2 + 2 * TRUNCATED_HASH_LEN);
    let len = raw.len();
    raw[0] &= 0x0f;
    raw.copy_within(2 + TRUNCATED_HASH_LEN..len, 2);
    len - TRUNCATED_HASH_LEN
}

fn link_forward_interface(entry: &LinkTableEntry, source_iface: u8) -> Option<u8> {
    if entry.received_on == entry.outbound_to {
        (source_iface == entry.received_on).then_some(entry.received_on)
    } else if source_iface == entry.received_on {
        Some(entry.outbound_to)
    } else if source_iface == entry.outbound_to {
        Some(entry.received_on)
    } else {
        None
    }
}

fn link_hops_match(entry: &LinkTableEntry, source_iface: u8, hops: u8) -> bool {
    if entry.received_on == entry.outbound_to {
        source_iface == entry.received_on
            && (hops == entry.inbound_hops || hops == entry.outbound_hops)
    } else if source_iface == entry.received_on {
        hops == entry.inbound_hops
    } else if source_iface == entry.outbound_to {
        hops == entry.outbound_hops
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// IngestResult — what to do after processing an inbound packet
// ---------------------------------------------------------------------------

/// Bounded Link table whose admission rejected an inbound LINKREQUEST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTableKind {
    /// Links owned by this endpoint.
    Owned,
    /// Links forwarded on behalf of other endpoints.
    Relay,
}

/// Interface selection for a packet emitted by transport ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardTarget {
    /// Send only on the interface selected by the learned path or relay table.
    ExactInterface(u8),
    /// Propagate on every interface except the one that supplied the packet.
    AllExceptSource,
}

/// Result of processing an inbound packet via [`Transport::ingest`].
#[derive(Debug)]
#[must_use = "ingest results can contain forwarding actions or terminal receipt notifications"]
pub enum IngestResult<'a> {
    /// Data packet addressed to one of our destinations.
    LocalData {
        /// Destination hash the packet was addressed to.
        dest_hash: DestHash,
        /// Destination type declared by the wire packet.
        dest_type: DestType,
        /// Payload data.
        payload: &'a [u8],
        /// Full 32-byte packet hash (for proof generation).
        packet_hash: [u8; 32],
    },
    /// A valid announce was received and its path has been learned.
    AnnounceReceived {
        /// Destination hash of the announcing identity.
        dest_hash: DestHash,
        /// Identity hash of the announcer.
        identity_hash: IdentityHash,
        /// Hop count at time of receipt.
        hops: u8,
        /// Optional application data from the announce.
        app_data: Option<&'a [u8]>,
        /// Optional ratchet public key (32 bytes, present when context_flag=1).
        ratchet: Option<[u8; 32]>,
    },
    /// Packet should be forwarded according to the transport-selected target.
    Forward {
        /// Raw packet bytes (with hops incremented).
        raw: &'a [u8],
        /// Interface index the packet was received on.
        source_iface: u8,
        /// Exact path-selected interface or genuine propagation behavior.
        target: ForwardTarget,
    },
    /// A LINKREQUEST was received for one of our destinations.
    LinkRequestReceived {
        /// The computed link_id (16 bytes).
        link_id: LinkId,
        /// The LRPROOF response to send back (raw packet bytes, owned).
        proof_raw: alloc::vec::Vec<u8>,
    },
    /// A valid LINKREQUEST could not be retained in a bounded Link table.
    ///
    /// Its packet hash remains in the normal deduplication window. A later
    /// attempt must create a fresh LINKREQUEST with new ephemeral material.
    LinkTableFull {
        /// The computed Link ID that could not be admitted.
        link_id: LinkId,
        /// The bounded table that rejected the Link.
        table: LinkTableKind,
    },
    /// A transported DATA packet could not retain its reverse route because
    /// the bounded reverse table is full.
    ///
    /// Its full packet hash remains in the normal deduplication window. The
    /// packet has not been rewritten and must not be emitted.
    ReverseTableFull {
        /// Truncated packet hash that could not be admitted.
        truncated_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A transported DATA packet's truncated hash is already bound to a
    /// different reverse route.
    ///
    /// The retained route wins: it is not redirected, and the colliding
    /// packet has not been rewritten and must not be emitted.
    ReverseRouteConflict {
        /// Truncated packet hash whose retained route conflicts.
        truncated_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A link handshake completed (LRPROOF validated or LRRTT processed).
    LinkEstablished {
        /// The link_id.
        link_id: LinkId,
    },
    /// An established responder accepted a fresh authenticated LRRTT update.
    ///
    /// This is deliberately distinct from [`Self::LinkEstablished`]: Python
    /// re-runs its destination callback for such packets, but Rete's public
    /// establishment event is a one-shot lifecycle trigger.
    LinkRttUpdated {
        /// The link_id.
        link_id: LinkId,
    },
    /// A valid protocol keepalive was consumed internally.
    ///
    /// Keepalives are Link lifecycle traffic and must never surface as
    /// application data. `reply` is true only when this endpoint is the
    /// responder and must emit the unencrypted `0xFE` response.
    Keepalive {
        /// The Link that consumed the keepalive.
        link_id: LinkId,
        /// Whether a response packet must be emitted.
        reply: bool,
    },
    /// Decrypted data received on an active or successfully revived link.
    LinkData {
        /// The link_id.
        link_id: LinkId,
        /// Decrypted payload data (owned).
        data: alloc::vec::Vec<u8>,
        /// The context byte from the packet.
        context: u8,
    },
    /// Channel messages received on a link (reliable ordered delivery).
    ChannelMessages {
        /// The link_id.
        link_id: LinkId,
        /// Delivered channel envelopes.
        messages: alloc::vec::Vec<crate::channel::ChannelEnvelope>,
        /// The packet hash of the DATA packet carrying these channel messages.
        packet_hash: [u8; 32],
    },
    /// A link was closed (teardown or timeout).
    LinkClosed {
        /// The link_id.
        link_id: LinkId,
    },
    /// A locally owned Link was purged after an authenticated handshake
    /// payload failed protocol decoding.
    ///
    /// `close_raw` carries the best-effort encrypted LINKCLOSE response. Link
    /// removal is unconditional even if construction of that response failed.
    LinkTeardown {
        /// The link_id.
        link_id: LinkId,
        /// Encrypted LINKCLOSE packet, when construction succeeded.
        close_raw: Option<alloc::vec::Vec<u8>>,
        /// Interface retained by the authenticated Link handshake.
        interface: Option<u8>,
    },
    /// A proof was received for a packet we sent.
    ///
    /// The corresponding receipt has already been reclaimed when this result
    /// is returned.
    ProofReceived {
        /// The full 32-byte packet hash the proof covers.
        packet_hash: [u8; 32],
    },
    /// A resource advertisement was received on a link.
    ResourceOffered {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes for keying).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// Total size of the resource data.
        total_size: usize,
        /// True if this resource is a request or response payload (auto-accept regardless of strategy).
        is_request_or_response: bool,
        /// True if this resource carries a response payload.
        is_response: bool,
        /// Request ID from the `"q"` advertisement field (for response-resource correlation).
        request_id: Option<rete_core::RequestId>,
    },
    /// Resource transfer progress.
    ResourceProgress {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// Parts received so far.
        current: usize,
        /// Total parts.
        total: usize,
    },
    /// Resource transfer completed successfully.
    ResourceComplete {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// The assembled resource data.
        data: alloc::vec::Vec<u8>,
    },
    /// Resource transfer failed.
    ResourceFailed {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A resource we sent was rejected by the receiver (RESOURCE_RCL received).
    ResourceRejected {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A link.request() was received on a link.
    RequestReceived {
        /// The link_id.
        link_id: LinkId,
        /// The request_id (truncated packet hash for single-packet requests).
        request_id: rete_core::RequestId,
        /// The path_hash (SHA-256(path)[..16]).
        path_hash: rete_core::PathHash,
        /// The request data payload.
        data: alloc::vec::Vec<u8>,
        /// Timestamp from the wire format (seconds since epoch).
        requested_at: f64,
    },
    /// A link.request() carrying an encoded non-binary/string MessagePack
    /// value was received on a link.
    RequestValueReceived {
        /// The link_id.
        link_id: LinkId,
        /// The request_id (truncated packet hash for single-packet requests).
        request_id: rete_core::RequestId,
        /// The path_hash (SHA-256(path)[..16]).
        path_hash: rete_core::PathHash,
        /// Exact encoded bytes of the validated MessagePack request value.
        value: alloc::vec::Vec<u8>,
        /// Timestamp from the wire format (seconds since epoch).
        requested_at: f64,
    },
    /// A link.response() was received on a link.
    ResponseReceived {
        /// The link_id.
        link_id: LinkId,
        /// The request_id this response is for.
        request_id: rete_core::RequestId,
        /// The response data payload.
        data: alloc::vec::Vec<u8>,
    },
    /// Packet was a duplicate and should be dropped.
    Duplicate,
    /// A channel message was accepted and buffered (out-of-order), not yet deliverable.
    Buffered {
        /// The packet hash of the DATA packet (receiver should prove it).
        packet_hash: [u8; 32],
        /// The link_id (used to build a link-destination proof).
        link_id: LinkId,
    },
    /// A path request for an unknown destination should be forwarded to other interfaces.
    PathRequestForward {
        /// The raw path request payload to forward.
        payload: alloc::vec::Vec<u8>,
    },
    /// A known-path response could not be retained in the bounded announce queue.
    PathResponseQueueFull {
        /// Destination whose source-bound response was not admitted.
        dest_hash: DestHash,
    },
    /// Packet was malformed or invalid.
    Invalid,
}

// ---------------------------------------------------------------------------
// TickResult — output of periodic maintenance
// ---------------------------------------------------------------------------

/// Result of periodic transport maintenance via [`Transport::tick`].
#[must_use = "timed-out receipt hashes must be observed by the application"]
pub struct TickResult {
    /// Number of paths that were expired and removed.
    pub expired_paths: usize,
    /// Number of links closed by establishment or stale-session maintenance.
    pub closed_links: usize,
    /// Full hashes of receipts that newly timed out during this tick.
    pub failed_receipts: Vec<[u8; 32]>,
    /// Full hashes of Link DATA receipts that timed out or lost their Link.
    pub failed_link_data_receipts: Vec<[u8; 32]>,
}

/// Allocation-free result of periodic transport maintenance.
///
/// DATA and Link DATA receipt failures are committed to the caller's reserved
/// sink before their receipt-table entries are removed. Channel-receipt expiry remains
/// internal and does not emit a [`ReceiptTerminal::Failed`] notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "timed-out receipt notifications may have been deferred"]
pub struct TickSummary {
    /// Number of paths that were expired and removed.
    pub expired_paths: usize,
    /// Number of links closed by establishment or stale-session maintenance.
    pub closed_links: usize,
    /// Number of DATA receipt-failure notifications committed to the sink.
    pub failed_receipts: usize,
    /// Number of Link DATA receipt-failure notifications committed to the sink.
    pub failed_link_data_receipts: usize,
    /// At least one failed DATA or Link DATA receipt remains because the sink was full.
    pub receipt_notifications_deferred: bool,
}

// ---------------------------------------------------------------------------
// TransportStats
// ---------------------------------------------------------------------------

/// Cumulative counters for transport-layer activity.
///
/// All counters are monotonically increasing `u64` values. They are never
/// reset — callers can snapshot and diff to compute rates.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TransportStats {
    /// Total packets received and parsed (excludes parse failures).
    pub packets_received: u64,
    /// Total packets sent (announces via pending_outbound).
    pub packets_sent: u64,
    /// Packets forwarded on behalf of other nodes (relay traffic).
    pub packets_forwarded: u64,
    /// Packets dropped because they were seen before (dedup window).
    pub packets_dropped_dedup: u64,
    /// Packets dropped as invalid (parse failure, unknown dest, crypto error, etc.).
    pub packets_dropped_invalid: u64,
    /// Valid announces received and processed.
    pub announces_received: u64,
    /// Announces sent (first transmission of locally-queued announces).
    pub announces_sent: u64,
    /// Announce retransmissions (subsequent sends of the same announce).
    pub announces_retransmitted: u64,
    /// Announces suppressed by the announce rate limiter.
    pub announces_rate_limited: u64,
    /// Links that reached Active state (LRRTT or LRPROOF exchange completed).
    pub links_established: u64,
    /// Links closed (LINKCLOSE received, local protocol-error teardown,
    /// establishment timeout, or keepalive timeout).
    pub links_closed: u64,
    /// Link handshake failures (cryptographic errors or malformed authenticated
    /// negotiation payloads during establishment).
    pub links_failed: u64,
    /// Link requests received (before LRPROOF sent).
    pub link_requests_received: u64,
    /// Paths learned or updated in the path table.
    pub paths_learned: u64,
    /// Paths expired and removed from the path table.
    pub paths_expired: u64,
    /// Cryptographic failures (decrypt/verify errors).
    pub crypto_failures: u64,
    /// Timestamp of first activity (seconds, caller-provided). 0 until first use.
    pub started_at: u64,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The Reticulum transport layer — path table, announce queue, dedup window, links.
///
/// Generic over `S: TransportStorage` — pluggable storage backend.
/// Use [`HeaplessStorage`](crate::HeaplessStorage) for embedded (fixed-size) or
/// [`StdStorage`](crate::storage_std::StdStorage) for hosted (heap-allocated).
pub struct Transport<S: TransportStorage> {
    pub(super) paths: S::PathMap,
    pub(super) announces: S::AnnounceDeque,
    pub(super) dedup: DedupWindow<S::DedupDeque>,
    pub(super) known_identities: S::IdentityMap,
    /// Identity hash of this node (enables HEADER_2 forwarding when set).
    pub(super) local_identity_hash: Option<IdentityHash>,
    /// Reverse table: truncated packet hash → entry (for reply routing).
    pub(super) reverse_table: S::ReverseMap,
    /// Dedup window for announce random_hashes (replay detection).
    pub(super) announce_dedup: DedupWindow<S::DedupDeque>,
    /// Independent destination-plus-tag deduplication for received path requests.
    ///
    /// Python does not apply `PATH_REQUEST_MI` to ingress. Keeping this window
    /// separate prevents path-request churn from evicting signed announce
    /// replay state.
    pub(super) path_request_dedup: DedupWindow<S::DedupDeque>,
    /// Destination hashes registered as local (self-announce filtering, local delivery routing).
    pub(super) local_destinations: alloc::vec::Vec<DestHash>,
    /// Active link sessions, keyed by link_id.
    pub(super) links: S::LinkMap,
    /// Receipts for sent packets, awaiting delivery proofs.
    pub(super) receipts: ReceiptTable<S::ReceiptMap>,
    /// Receipts for ordinary context-NONE DATA sent on owned Links.
    pub(super) link_data_receipts: LinkDataReceiptTable<S::LinkDataReceiptMap>,
    /// Receipts for channel messages: truncated packet hash → ChannelReceipt.
    /// Used to match incoming PROOFs to channel sequences and call mark_delivered().
    pub(super) channel_receipts: S::ChannelReceiptMap,
    /// Active resource transfers.
    pub(super) resources: alloc::vec::Vec<Resource>,
    /// Pending outbound resource packets (parts, HMU, etc.) built during ingest.
    pub(super) resource_outbound: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// Link routing table: link_id → entry (for bidirectional relay of link traffic).
    /// Entries persist for the lifetime of the relayed link.
    pub(super) link_table: S::LinkTableMap,
    /// Announce rate limiting: dest_hash → (last_announce_time, violations, blocked_until).
    pub(super) announce_rate: S::AnnounceRateMap,
    /// Pending split resource segments waiting to be advertised.
    pub(super) split_send_queue: alloc::vec::Vec<SplitSendEntry>,
    /// Cumulative transport-layer counters.
    pub(super) stats: TransportStats,
}

/// Metadata for a split resource segment advertisement.
pub(crate) struct SplitMeta {
    pub(crate) split_index: usize,
    pub(crate) split_total: usize,
    pub(crate) original_hash: [u8; 32],
    pub(crate) full_original_size: usize,
}

pub(super) struct SplitSendEntry {
    pub(super) link_id: LinkId,
    /// Group key: resource_hash of segment 1.
    pub(super) original_hash: [u8; 32],
    /// 1-based index of the next segment to send.
    pub(super) next_segment: usize,
    /// Total split segments.
    pub(super) split_total: usize,
    /// Full original plaintext size (all segments combined).
    pub(super) full_original_size: usize,
    /// Remaining plaintext data (after segment 1). Each segment reads its slice at send time.
    pub(super) data: alloc::vec::Vec<u8>,
}

/// Per-destination announce rate tracking entry.
#[derive(Debug, Clone, Copy)]
pub struct AnnounceRateEntry {
    pub(crate) last: u64,
    pub(crate) violations: u8,
    pub(crate) blocked_until: u64,
}

impl<S: TransportStorage> Default for Transport<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: TransportStorage> Transport<S> {
    /// Create a new, empty transport.
    pub fn new() -> Self {
        Transport {
            paths: Default::default(),
            announces: Default::default(),
            dedup: Default::default(),
            known_identities: Default::default(),
            local_identity_hash: None,
            reverse_table: Default::default(),
            announce_dedup: Default::default(),
            path_request_dedup: Default::default(),
            local_destinations: Default::default(),
            links: Default::default(),
            receipts: Default::default(),
            link_data_receipts: Default::default(),
            channel_receipts: Default::default(),
            resources: alloc::vec::Vec::new(),
            resource_outbound: alloc::vec::Vec::new(),
            link_table: Default::default(),
            announce_rate: Default::default(),
            split_send_queue: alloc::vec::Vec::new(),
            stats: TransportStats::default(),
        }
    }

    /// Create a new, empty transport directly in caller-provided storage.
    ///
    /// Unlike [`Self::new`], this constructor never materialises the complete
    /// transport as a temporary value. This is important for large bounded
    /// storage backends on targets with a small task stack.
    #[inline(never)]
    pub fn new_in(destination: &mut MaybeUninit<Self>) -> &mut Self {
        let ptr = destination.as_mut_ptr();

        // SAFETY: `ptr` is aligned, non-null and uniquely borrowed through the
        // `MaybeUninit<Self>`. Each field below is written exactly once, no
        // reference to the enclosing `Self` is created while it is partially
        // initialised, and the final reference is produced only after every
        // field has been initialised. If a field initializer panics, no `Self`
        // reference escapes; already-written fields are leaked, which is safe.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).paths).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).announces).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).dedup).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).known_identities).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).local_identity_hash).write(None);
            core::ptr::addr_of_mut!((*ptr).reverse_table).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).announce_dedup).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).path_request_dedup).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).local_destinations).write(Vec::new());
            core::ptr::addr_of_mut!((*ptr).links).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).receipts).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).link_data_receipts).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).channel_receipts).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).resources).write(Vec::new());
            core::ptr::addr_of_mut!((*ptr).resource_outbound).write(Vec::new());
            core::ptr::addr_of_mut!((*ptr).link_table).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).announce_rate).write(Default::default());
            core::ptr::addr_of_mut!((*ptr).split_send_queue).write(Vec::new());
            core::ptr::addr_of_mut!((*ptr).stats).write(TransportStats::default());

            &mut *ptr
        }
    }

    /// Return a reference to the cumulative transport counters.
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Register a destination hash as belonging to this node.
    pub fn add_local_destination(&mut self, dest_hash: DestHash) {
        if !self.local_destinations.contains(&dest_hash) {
            self.local_destinations.push(dest_hash);
        }
    }

    /// Check whether a destination hash is registered as local.
    pub fn is_local_destination(&self, dest_hash: &DestHash) -> bool {
        self.local_destinations.contains(dest_hash)
    }

    /// Check a packet hash for duplicates.
    pub fn is_duplicate(&mut self, hash: &[u8; 32]) -> bool {
        self.dedup.check_and_insert(hash)
    }

    /// Set the local identity hash, enabling HEADER_2 forwarding.
    pub fn set_local_identity(&mut self, hash: IdentityHash) {
        self.local_identity_hash = Some(hash);
    }

    /// Get the local identity hash (transport node ID), if set.
    pub fn local_identity_hash(&self) -> Option<IdentityHash> {
        self.local_identity_hash
    }

    /// Look up a reverse table entry by truncated packet hash.
    pub fn get_reverse(&self, hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&ReverseEntry> {
        self.reverse_table.get(hash)
    }

    /// Number of reverse table entries.
    pub fn reverse_count(&self) -> usize {
        self.reverse_table.len()
    }

    /// Look up a Link route retained on behalf of two remote endpoints.
    pub fn get_relay_link(&self, link_id: &LinkId) -> Option<&LinkTableEntry> {
        self.link_table.get(link_id)
    }

    /// Number of Link routes retained on behalf of remote endpoints.
    pub fn relay_link_count(&self) -> usize {
        self.link_table.len()
    }

    fn admit_relay_link(&mut self, link_id: LinkId, entry: LinkTableEntry) -> RelayLinkAdmission {
        if self.link_table.contains_key(&link_id) {
            return RelayLinkAdmission::Existing;
        }

        match self.link_table.insert(link_id, entry) {
            Ok(None) => RelayLinkAdmission::Inserted,
            Ok(Some(previous)) => {
                // A conforming StorageMap cannot replace an entry after the
                // contains check above. Restore it defensively so an unusual
                // backend cannot redirect an established relayed Link.
                let restored = self.link_table.insert(link_id, previous);
                debug_assert!(matches!(restored, Ok(Some(_))));
                RelayLinkAdmission::Existing
            }
            Err(_) => RelayLinkAdmission::Full,
        }
    }

    fn admit_reverse_route(
        &mut self,
        truncated_hash: [u8; TRUNCATED_HASH_LEN],
        entry: ReverseEntry,
    ) -> ReverseRouteAdmission {
        if let Some(existing) = self.reverse_table.get(&truncated_hash).copied() {
            return if existing.received_on == entry.received_on
                && existing.forwarded_to == entry.forwarded_to
            {
                // Admission is idempotent. In particular, do not refresh the
                // timestamp or let a replay redirect an established route.
                ReverseRouteAdmission::Existing
            } else {
                ReverseRouteAdmission::Conflict
            };
        }

        match self.reverse_table.insert(truncated_hash, entry) {
            Ok(None) => ReverseRouteAdmission::Inserted,
            Ok(Some(previous)) => {
                // A conforming StorageMap cannot replace an entry after the
                // lookup above. Restore it defensively so an unusual backend
                // cannot redirect an established reverse route.
                let restored = self.reverse_table.insert(truncated_hash, previous);
                debug_assert!(matches!(restored, Ok(Some(_))));
                if previous.received_on == entry.received_on
                    && previous.forwarded_to == entry.forwarded_to
                {
                    ReverseRouteAdmission::Existing
                } else {
                    ReverseRouteAdmission::Conflict
                }
            }
            Err(_) => ReverseRouteAdmission::Full,
        }
    }

    fn remember_reverse_route_best_effort(
        &mut self,
        packet_hash: &[u8; 32],
        now: u64,
        received_on: u8,
        forwarded_to: u8,
    ) {
        let mut truncated_hash = [0u8; TRUNCATED_HASH_LEN];
        truncated_hash.copy_from_slice(&packet_hash[..TRUNCATED_HASH_LEN]);
        let _ = self.reverse_table.insert(
            truncated_hash,
            ReverseEntry {
                timestamp: now,
                received_on,
                forwarded_to,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Packet ingestion
    // -----------------------------------------------------------------------

    /// Process an inbound raw packet (single-interface convenience wrapper).
    ///
    /// Equivalent to `ingest_on(raw, now, 0, rng, identity)`.
    pub fn ingest<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        self.ingest_on(raw, now, 0, rng, identity)
    }

    fn proof_terminal_candidate(
        &self,
        raw: &[u8],
        local_identity: IdentityHash,
    ) -> Option<ReceiptCandidate> {
        let Ok(packet) = Packet::parse(raw) else {
            return None;
        };
        if packet.packet_type != PacketType::Proof {
            return None;
        }

        // Receipt preflight and normal ingress must agree on HEADER_2
        // ownership. A proof for another transport instance cannot reserve
        // our terminal capacity, while an own-targeted proof must reserve
        // before typed dispatch can consume its receipt.
        if header2_ownership(&packet, local_identity) == Header2Ownership::Foreign {
            return None;
        }

        let raw_destination: [u8; TRUNCATED_HASH_LEN] =
            packet.destination_hash.try_into().unwrap();
        let link_id = LinkId::from(raw_destination);

        // These locally handled proof contexts terminate link or resource
        // state, not application-visible DATA/channel receipts.
        if packet.dest_type == DestType::Link
            && self.links.contains_key(&link_id)
            && matches!(packet.context, CONTEXT_LRPROOF | CONTEXT_RESOURCE_PRF)
        {
            return None;
        }

        // Channel proofs are Link-typed and overload destination_hash with the
        // Link ID. Prefer their explicit packet hash before consulting the
        // ordinary DATA receipt map, whose truncated key can theoretically
        // collide with that Link ID. The normal ingest path uses the same
        // ordering, so a reservation can never be bound to a different kind.
        if packet.dest_type == DestType::Link && packet.payload.len() >= 96 {
            let mut packet_hash = [0u8; 32];
            packet_hash.copy_from_slice(&packet.payload[..32]);
            let receipt_key: [u8; TRUNCATED_HASH_LEN] = packet_hash
                [..TRUNCATED_HASH_LEN]
                .try_into()
                .unwrap();
            if let Some(receipt) = self.channel_receipts.get(&receipt_key) {
                if receipt.link_id == link_id && receipt.packet_hash == packet_hash {
                    return Some(ReceiptCandidate::channel(receipt.packet_hash));
                }
            }
        }

        // Ordinary Link DATA receipts also use explicit Link-destination
        // proofs, but are independent of channel sequencing and retry state.
        // Match the exact Link ID and complete covered hash retained at send
        // time. A removed Link is terminally failed by maintenance instead of
        // accepting a proof after closure.
        if packet.dest_type == DestType::Link
            && packet.context == CONTEXT_NONE
            && self.links.contains_key(&link_id)
        {
            if let Some(receipt) = self
                .link_data_receipts
                .proof_candidate(&link_id, packet.payload)
            {
                return Some(ReceiptCandidate::link_data(receipt.packet_hash));
            }
        }

        if let Some(receipt) = self.receipts.get(&raw_destination) {
            return Some(ReceiptCandidate::data(receipt.packet_hash));
        }

        None
    }

    /// Process an inbound packet while committing DATA/channel receipt proofs
    /// to a caller-reserved terminal sink.
    ///
    /// A sink slot is reserved only when a PROOF addresses a currently
    /// outstanding DATA or channel receipt. Reservation happens before normal
    /// ingestion changes statistics, deduplication, or receipt state. Link,
    /// resource, relayed, and unrelated proofs therefore continue to flow even
    /// when the application terminal sink is full. On [`ReceiptSinkFull`], the
    /// caller must retain and retry the candidate proof packet.
    pub fn ingest_on_with_receipt_sink<'a, R, T>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        iface: u8,
        rng: &mut R,
        identity: &Identity,
        sink: &mut T,
    ) -> Result<IngestResult<'a>, ReceiptSinkFull>
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        self.ingest_on_with_receipt_sink_at(
            raw,
            now,
            MonotonicInstant::from_secs(now),
            iface,
            rng,
            identity,
            sink,
        )
    }

    /// Precise Link-clock variant of [`Self::ingest_on_with_receipt_sink`].
    pub fn ingest_on_with_receipt_sink_at<'a, R, T>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        link_now: MonotonicInstant,
        iface: u8,
        rng: &mut R,
        identity: &Identity,
        sink: &mut T,
    ) -> Result<IngestResult<'a>, ReceiptSinkFull>
    where
        R: RngCore + CryptoRng,
        T: ReceiptTerminalSink,
    {
        let ingress_identity = self.local_identity_hash.unwrap_or_else(|| identity.hash());
        let reservation = match self.proof_terminal_candidate(raw, ingress_identity) {
            Some(candidate) => Some((candidate, sink.try_reserve(candidate)?)),
            None => None,
        };
        let result = self.ingest_on_at(raw, now, link_now, iface, rng, identity);

        match (&result, reservation) {
            (IngestResult::ProofReceived { packet_hash }, Some((candidate, reservation))) => {
                assert_eq!(
                    packet_hash, &candidate.packet_hash,
                    "validated proof must match its reserved receipt candidate"
                );
                reservation.commit(ReceiptTerminal::Delivered(*packet_hash));
            }
            (IngestResult::ProofReceived { .. }, None) => {
                debug_assert!(false, "receipt proof bypassed terminal sink preflight");
            }
            (_, _) => {}
        }

        Ok(result)
    }

    /// Process an inbound raw packet received on interface `iface`.
    ///
    /// Parses the packet, checks for duplicates, and dispatches by type:
    /// - **ANNOUNCE**: validate signature + dest hash, learn path, queue retransmission
    /// - **DATA**: return for local delivery, handle path requests, link data, or forward
    /// - **PROOF**: route via reverse table, validate LRPROOF, or forward
    /// - **LINKREQUEST**: validate and create a canonical local Link, else forward
    ///
    /// `now` is the current monotonic time in seconds.
    pub fn ingest_on<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        iface: u8,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        self.ingest_on_at(
            raw,
            now,
            MonotonicInstant::from_secs(now),
            iface,
            rng,
            identity,
        )
    }

    /// Precise Link-clock variant of [`Self::ingest_on`].
    ///
    /// `now` remains the whole-second logical clock used by path and receipt
    /// tables. `link_now` is a process-local monotonic instant used only for
    /// Link RTT and liveness calculations.
    pub fn ingest_on_at<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        link_now: MonotonicInstant,
        iface: u8,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        let mut len = raw.len();

        // Parse
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                if self.stats.started_at == 0 {
                    self.stats.started_at = now;
                }
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        };

        let ingress_identity = self.local_identity_hash.unwrap_or_else(|| identity.hash());
        let h2_ownership = header2_ownership(&pkt, ingress_identity);

        // Match Python RNS packet_filter(): non-ANNOUNCE HEADER_2 traffic for
        // another transport instance is ignored before packet-hash admission
        // or any other observable transport mutation. IngestResult has no
        // separate Ignored variant, so Invalid is the fail-closed action while
        // statistics deliberately remain unchanged.
        if h2_ownership == Header2Ownership::Foreign {
            return IngestResult::Invalid;
        }

        // Lazy-init started_at on first admitted ingest.
        if self.stats.started_at == 0 {
            self.stats.started_at = now;
        }

        self.stats.packets_received += 1;

        // Python accepts Link DATA only on that Link's attached interface.
        // Rete applies the same route-affinity hardening to Link-owned
        // RESOURCE_PRF traffic as a fail-closed policy. Perform both checks
        // before dedup admission so a packet observed on the wrong interface
        // cannot poison the hash window and suppress a later copy from the
        // authoritative interface. Ordinary delivery proofs remain globally
        // validated; LRPROOF remains exempt until cryptographic validation
        // establishes the initiator binding.
        let is_owned_link_payload = pkt.packet_type == PacketType::Data
            || (pkt.packet_type == PacketType::Proof && pkt.context == CONTEXT_RESOURCE_PRF);
        if is_owned_link_payload && pkt.dest_type == DestType::Link {
            let link_id = LinkId::from_slice(pkt.destination_hash);
            if self
                .links
                .get(&link_id)
                .is_some_and(|link| link.bound_interface != Some(iface))
            {
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        }

        // Python retains hops_to(destination) when an initiator creates its
        // pending Link, then admits LRPROOF only at that height. Apply the
        // local ingress increment here and reject mismatches before packet-hash
        // admission, so an otherwise valid proof observed at the wrong height
        // cannot suppress a later authoritative copy. PATHFINDER_M remains the
        // compatibility wildcard for Links initiated without a known path.
        if pkt.packet_type == PacketType::Proof
            && pkt.dest_type == DestType::Link
            && pkt.context == CONTEXT_LRPROOF
        {
            let link_id = LinkId::from_slice(pkt.destination_hash);
            let inbound_hops = pkt.hops.saturating_add(1);
            if self.links.get(&link_id).is_some_and(|link| {
                link.role == crate::link::LinkRole::Initiator
                    && link.state == crate::link::LinkState::Handshake
                    && link.bound_interface.is_none()
                    && !link.accepts_lrproof_hops(inbound_hops)
            }) {
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        }

        // Python accepts ANNOUNCE only for SINGLE destinations. Destination
        // type is outside the signed announce payload, so reject this before
        // replay or path state can be mutated.
        if pkt.packet_type == PacketType::Announce && pkt.dest_type != DestType::Single {
            self.stats.packets_dropped_invalid += 1;
            return IngestResult::Invalid;
        }

        // Python increments ingress before filtering and rejects non-announce
        // PLAIN packets above post-increment hop one. Physical wire ingress
        // must therefore be at hop zero. Apply this before either packet or
        // path-request dedup state changes.
        if pkt.dest_type == DestType::Plain
            && pkt.packet_type != PacketType::Announce
            && pkt.hops > 0
        {
            self.stats.packets_dropped_invalid += 1;
            return IngestResult::Invalid;
        }
        let is_path_request = is_path_request_ingress(&pkt);

        // Compute packet hash for dedup
        let pkt_hash = pkt.compute_hash();

        // Conforming keepalives are deterministic unencrypted packets, so every
        // request (and every response) for one Link has the same hash. Python RNS
        // exempts them from packet filtering. Classify before dedup but mutate no
        // Link state here; the bound-interface gate above has already run.
        let is_valid_owned_keepalive = pkt.packet_type == PacketType::Data
            && pkt.dest_type == DestType::Link
            && pkt.context == CONTEXT_KEEPALIVE
            && self
                .links
                .get(&LinkId::from_slice(pkt.destination_hash))
                .is_some_and(|link| link.classify_keepalive(pkt.payload).is_some());

        // Dedup check.
        //
        // Skip dedup for link-type traffic on the local Hub interface
        // (iface 0 when local_identity_hash is set, i.e. transport mode).
        // In shared-mode daemons, link keepalives are identical packets
        // that must still be relayed between local clients. Python rnsd
        // relays to other shared clients before the dedup check, achieving
        // the same effect. Without this skip, the daemon deduplicates
        // repeated keepalives, causing remote link endpoints to time out
        // and breaking resource transfers.
        // Skip dedup for link traffic transiting through this relay (foreign
        // links we don't own). Identical keepalives would otherwise be
        // permanently flagged, causing remote link endpoints to time out.
        let is_foreign_link_transit = pkt.dest_type == DestType::Link
            && self.local_identity_hash.is_some()
            && !self
                .links
                .contains_key(&LinkId::from_slice(pkt.destination_hash));
        let is_single_announce =
            pkt.packet_type == PacketType::Announce && pkt.dest_type == DestType::Single;
        if !is_single_announce
            && !is_foreign_link_transit
            && !is_valid_owned_keepalive
            && self.is_duplicate(&pkt_hash)
        {
            relay_log!(
                "[relay] DEDUP pkt_hash={} type={:?} dest_type={:?}",
                hex_short(&pkt_hash),
                pkt.packet_type,
                pkt.dest_type,
            );
            self.stats.packets_dropped_dedup += 1;
            return IngestResult::Duplicate;
        }

        // HEADER_2 has one narrow routing fast path. Local destinations,
        // owned Links and receipts stay out of it by packet family and are
        // normalized below for the same typed validators as HEADER_1.
        if h2_ownership == Header2Ownership::Own {
            let dest = DestHash::from_slice(pkt.destination_hash);
            let is_remote_single_data = pkt.packet_type == PacketType::Data
                && pkt.dest_type == DestType::Single
                && !self.is_local_destination(&dest);
            let is_remote_single_link_request = pkt.packet_type == PacketType::LinkRequest
                && pkt.dest_type == DestType::Single
                && !self.is_local_destination(&dest);

            if self.local_identity_hash.is_some()
                && (is_remote_single_data || is_remote_single_link_request)
            {
                let is_link_request = is_remote_single_link_request;
                let inbound_hops = pkt.hops.saturating_add(1);
                let path_route = self
                    .paths
                    .get(&dest)
                    .map(|path| (path.via, path.received_on, path.hops));

                let Some((next_hop, Some(outbound_iface), remaining)) = path_route else {
                    self.stats.packets_dropped_invalid += 1;
                    return IngestResult::Invalid;
                };

                // A relayed LINKREQUEST may be emitted only after its complete
                // bidirectional route has been retained. The packet hash has
                // already entered the normal dedup window, matching owned-Link
                // capacity rejection.
                if is_link_request {
                    let lid = match compute_link_id(raw) {
                        Ok(lid) => lid,
                        Err(_) => {
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        }
                    };
                    let entry = LinkTableEntry {
                        timestamp: now,
                        received_on: iface,
                        outbound_to: outbound_iface,
                        inbound_hops,
                        outbound_hops: remaining,
                        destination_hash: dest,
                    };
                    match self.admit_relay_link(lid, entry) {
                        RelayLinkAdmission::Inserted => {
                            relay_log!(
                                "[relay] H2 LINKREQUEST link_table INSERT lid={} dest={} in_hops={} out_hops={} rcvd={} out={}",
                                hex_short(lid.as_ref()),
                                hex_short(dest.as_ref()),
                                inbound_hops,
                                remaining,
                                iface,
                                outbound_iface,
                            );
                        }
                        RelayLinkAdmission::Existing => {
                            return IngestResult::Duplicate;
                        }
                        RelayLinkAdmission::Full => {
                            return IngestResult::LinkTableFull {
                                link_id: lid,
                                table: LinkTableKind::Relay,
                            };
                        }
                    }
                } else {
                    // Python RNS uses an unbounded dictionary here. Rete's
                    // embedded table is bounded, so DATA admission must
                    // retain the complete reverse route transactionally
                    // before the caller-owned packet is rewritten or emitted.
                    let reverse_hash = pkt_hash[..TRUNCATED_HASH_LEN]
                        .try_into()
                        .expect("truncated packet hash slice has fixed length");
                    let reverse_entry = ReverseEntry {
                        timestamp: now,
                        received_on: iface,
                        forwarded_to: outbound_iface,
                    };
                    match self.admit_reverse_route(reverse_hash, reverse_entry) {
                        ReverseRouteAdmission::Inserted | ReverseRouteAdmission::Existing => {}
                        ReverseRouteAdmission::Conflict => {
                            return IngestResult::ReverseRouteConflict {
                                truncated_hash: reverse_hash,
                            };
                        }
                        ReverseRouteAdmission::Full => {
                            return IngestResult::ReverseTableFull {
                                truncated_hash: reverse_hash,
                            };
                        }
                    }
                }

                #[allow(clippy::drop_non_drop)]
                drop(pkt);

                // The emitted wire packet carries the post-increment hop
                // count. Reverse state is already durable at this point so
                // no fallible operation remains before the Forward result.
                raw[1] = inbound_hops;
                let h2_result = match next_hop {
                    Some(via) => {
                        raw[2..2 + TRUNCATED_HASH_LEN].copy_from_slice(via.as_ref());
                        IngestResult::Forward {
                            raw: &raw[..len],
                            source_iface: iface,
                            target: ForwardTarget::ExactInterface(outbound_iface),
                        }
                    }
                    None => {
                        let forwarded_len = normalize_owned_header2(raw);
                        IngestResult::Forward {
                            raw: &raw[..forwarded_len],
                            source_iface: iface,
                            target: ForwardTarget::ExactInterface(outbound_iface),
                        }
                    }
                };
                match &h2_result {
                    IngestResult::Forward { .. } => self.stats.packets_forwarded += 1,
                    IngestResult::Invalid => self.stats.packets_dropped_invalid += 1,
                    _ => {}
                }
                return h2_result;
            }

            // Consume our transport hop before local/Link/proof dispatch. This
            // admits HEADER_2 LRPROOF only through the ordinary direction,
            // hop, identity and signature validators below.
            #[allow(clippy::drop_non_drop)]
            drop(pkt);
            len = normalize_owned_header2(raw);
        }

        let raw = &mut raw[..len];

        // Increment hops
        raw[1] = raw[1].saturating_add(1);

        // Re-parse after hops increment
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        };

        match pkt.packet_type {
            PacketType::Announce => self.handle_announce(&pkt, raw, now, iface),
            PacketType::Data => {
                let dh = DestHash::from_slice(pkt.destination_hash);

                // Path request handling
                if self.local_identity_hash.is_some() && is_path_request {
                    return self.handle_path_request(pkt.payload, now, iface);
                }

                // Link data handling: dest_type == Link
                if pkt.dest_type == DestType::Link {
                    let lid = LinkId::from_slice(dh.as_ref());
                    // If we own this link locally, handle it.
                    if self.links.contains_key(&lid) {
                        return self.handle_link_data(
                            &lid,
                            &pkt,
                            now,
                            link_now,
                            pkt_hash,
                            rng,
                        );
                    }
                    // Not our link — if we are a transport relay, check
                    // the link_table (keyed by link_id) to forward
                    // bidirectionally through this relay.
                    if self.local_identity_hash.is_some() {
                        if let Some(lte) = self.link_table.get_mut(&lid) {
                            // Exact hop-count match with direction awareness
                            // (Python Transport.py:1514-1549).
                            if let Some(outbound_iface) = link_forward_interface(lte, iface)
                                .filter(|_| link_hops_match(lte, iface, pkt.hops))
                            {
                                lte.timestamp = now; // refresh for expiry
                                relay_log!(
                                    "[relay] link_table FORWARD lid={} ctx={:#04x} iface={} hops={}",
                                    hex_short(lid.as_ref()),
                                    pkt.context,
                                    iface,
                                    pkt.hops,
                                );
                                self.stats.packets_forwarded += 1;
                                return IngestResult::Forward {
                                    raw,
                                    source_iface: iface,
                                    target: ForwardTarget::ExactInterface(outbound_iface),
                                };
                            } else {
                                relay_log!(
                                    "[relay] link_table HOP_FAIL lid={} ctx={:#04x} iface={} hops={} in_hops={} out_hops={} rcvd={} out={}",
                                    hex_short(lid.as_ref()),
                                    pkt.context,
                                    iface,
                                    pkt.hops,
                                    lte.inbound_hops,
                                    lte.outbound_hops,
                                    lte.received_on,
                                    lte.outbound_to,
                                );
                            }
                        } else {
                            relay_log!(
                                "[relay] link_table MISS lid={} ctx={:#04x} (no entry)",
                                hex_short(lid.as_ref()),
                                pkt.context,
                            );
                        }
                    }
                    // Fall through: non-transport node or no link_table entry.
                    // Try local handling (will return Invalid if link not found).
                    return self.handle_link_data(
                        &lid,
                        &pkt,
                        now,
                        link_now,
                        pkt_hash,
                        rng,
                    );
                }

                // Transport relay: if we're a transport node and this isn't
                // our own destination, forward to the next hop.
                if h2_ownership == Header2Ownership::Own && !self.is_local_destination(&dh) {
                    // An own-targeted HEADER_2 packet reaches this point only
                    // when it is outside the explicit DATA/SINGLE path-routing
                    // family above. Do not silently broaden that relay surface
                    // through HEADER_1 compatibility handling.
                    self.stats.packets_dropped_invalid += 1;
                    return IngestResult::Invalid;
                }

                // Intentional compatibility seam: unlike Python RNS 1.3.8,
                // which gates arbitrary HEADER_1 path routing on local-client
                // roles, Rete currently uses HEADER_1 ingress as its local
                // origin injection surface. Preserve that product behavior
                // until interface roles make local origin explicit.
                if self.local_identity_hash.is_some() && !self.is_local_destination(&dh) {
                    if let Some(path) = self.paths.get(&dh) {
                        let Some(outbound_iface) = path.received_on else {
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        };
                        // H1 admission intentionally remains the legacy
                        // best-effort behavior in this compatibility seam.
                        // Making it transactional before interface roles
                        // distinguish remote ingress from local injection
                        // would change the product's local-origin contract.
                        let mut trunc_hash = [0u8; TRUNCATED_HASH_LEN];
                        trunc_hash.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        self.remember_reverse_route_best_effort(
                            &pkt_hash,
                            now,
                            iface,
                            outbound_iface,
                        );
                        relay_log!(
                            "[relay] H1 DATA FORWARD dest={} reverse={}",
                            hex_short(dh.as_ref()),
                            hex_short(&trunc_hash[..]),
                        );
                        self.stats.packets_forwarded += 1;
                        return IngestResult::Forward {
                            raw: &raw[..len],
                            source_iface: iface,
                            target: ForwardTarget::ExactInterface(outbound_iface),
                        };
                    }
                }

                // Only treat as local if the destination is actually registered
                // as ours. Packets for unknown destinations are dropped — they
                // reached a dead end (no path, not local).
                if self.is_local_destination(&dh) {
                    IngestResult::LocalData {
                        dest_hash: dh,
                        dest_type: pkt.dest_type,
                        payload: pkt.payload,
                        packet_hash: pkt_hash,
                    }
                } else {
                    self.stats.packets_dropped_invalid += 1;
                    IngestResult::Invalid
                }
            }
            PacketType::Proof => {
                // For proof packets, the destination_hash may be a link_id (Link type)
                // or a truncated packet hash (Single type). We use both typed forms below.
                // Proof dest_hash is overloaded: link_id for Link-typed, truncated
                // packet hash for Single-typed. Keep raw bytes for ReverseMap/ReceiptMap.
                let raw_dh: [u8; TRUNCATED_HASH_LEN] = pkt.destination_hash.try_into().unwrap();
                #[allow(unused_variables)]
                let dh = DestHash::from(raw_dh);
                let lid = LinkId::from(raw_dh);

                if pkt.context == CONTEXT_LRPROOF && pkt.dest_type == DestType::Link {
                    relay_log!(
                        "[relay] LRPROOF_IN lid={} hops={} plen={} local_link={} link_table={} reverse={}",
                        hex_short(lid.as_ref()),
                        pkt.hops,
                        pkt.payload.len(),
                        self.links.contains_key(&lid),
                        self.link_table.contains_key(&lid),
                        self.reverse_table.contains_key(&raw_dh),
                    );
                }

                // Check for LRPROOF (link proof from responder to initiator).
                // Only handle locally if we have a pending link for this link_id;
                // otherwise fall through to reverse-table forwarding (relay case).
                if pkt.context == CONTEXT_LRPROOF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&lid)
                {
                    return self.handle_lrproof(&lid, pkt.payload, link_now, iface);
                }

                // Check for RESOURCE_PRF (resource completion proof from receiver).
                // Like LRPROOF, handle locally when the link is ours; otherwise
                // fall through to relay forwarding.  Resource proofs are NOT
                // link-encrypted (Python: Packet.pack special-cases RESOURCE_PRF).
                if pkt.context == CONTEXT_RESOURCE_PRF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&lid)
                {
                    if let Some(link) = self.links.get_mut(&lid) {
                        link.touch_inbound_at(link_now);
                    }
                    return self.handle_resource_data(&lid, pkt.context, pkt.payload, now, rng);
                }

                // Check channel receipts for delivery proof (channel messages).
                // Proof payload format: packet_hash[32] || sig[64].
                // Link proofs use dest_type=Link with dest_hash=link_id, so we
                // extract the truncated packet hash from the payload for lookup.
                // Channel lookup precedes DATA receipt lookup for Link-typed
                // proofs, matching the candidate-reservation preflight above.
                if pkt.dest_type == DestType::Link && pkt.payload.len() >= 96 {
                    let mut full_hash = [0u8; 32];
                    full_hash.copy_from_slice(&pkt.payload[..32]);
                    let mut receipt_key = [0u8; TRUNCATED_HASH_LEN];
                    receipt_key.copy_from_slice(&full_hash[..TRUNCATED_HASH_LEN]);

                    if let Some(cr) = self.channel_receipts.get(&receipt_key).filter(|receipt| {
                        receipt.link_id == lid && receipt.packet_hash == full_hash
                    }) {
                        let link_id = cr.link_id;
                        let sequence = cr.sequence;
                        let sig = &pkt.payload[32..96];
                        // Verify using the link peer's signing key (peer_ed25519_pub).
                        // Python initiators use an ephemeral Ed25519 key (not their
                        // node identity) for link signing, so we must use the key
                        // from the LINKREQUEST/LRPROOF handshake.
                        let verified = if let Some(link) = self.links.get(&link_id) {
                            Identity::verify_raw_ed25519(&link.peer_ed25519_pub, &full_hash, sig)
                                .is_ok()
                        } else {
                            false
                        };
                        if verified {
                            self.channel_receipts.remove(&receipt_key);
                            if let Some(link) = self.links.get_mut(&link_id) {
                                link.touch_inbound_at(link_now);
                                let rtt = link.rtt;
                                if let Some(channel) = link.channel.as_mut() {
                                    channel.mark_delivered(sequence, rtt as f32);
                                }
                            }
                            return IngestResult::ProofReceived {
                                packet_hash: full_hash,
                            };
                        }
                    }
                }

                // Validate ordinary context-NONE Link DATA proofs against the
                // peer signing key captured with the receipt at send time.
                // The canonical proof is explicit and addressed to its Link.
                if pkt.dest_type == DestType::Link
                    && pkt.context == CONTEXT_NONE
                    && self.links.contains_key(&lid)
                {
                    if let Some(packet_hash) =
                        self.link_data_receipts.validate_proof(&lid, pkt.payload)
                    {
                        if let Some(link) = self.links.get_mut(&lid) {
                            link.touch_inbound_at(link_now);
                        }
                        return IngestResult::ProofReceived { packet_hash };
                    }
                }

                // Check receipt table for ordinary DATA delivery proofs after
                // Link-typed channel proofs have been disambiguated.
                if let Some(packet_hash) = self.receipts.validate_proof(&raw_dh, pkt.payload) {
                    return IngestResult::ProofReceived { packet_hash };
                }

                if self.local_identity_hash.is_some() {
                    // Link-destined proofs use the persistent link route.  In
                    // particular, an LRPROOF destination is also the truncated
                    // hash of its LINKREQUEST, so consulting the reverse table
                    // first would bypass the link direction, hop and signature
                    // checks below.
                    if pkt.dest_type == DestType::Link {
                        if let Some(lte) = self.link_table.get(&lid) {
                            let target_iface = if pkt.context == CONTEXT_LRPROOF {
                                // A LINKREQUEST proof may only return from the
                                // responder side at the stored remaining hops.
                                (iface == lte.outbound_to && pkt.hops == lte.outbound_hops)
                                    .then_some(lte.received_on)
                            } else {
                                link_forward_interface(lte, iface)
                                    .filter(|_| link_hops_match(lte, iface, pkt.hops))
                            };
                            let Some(target_iface) = target_iface else {
                                self.stats.packets_dropped_invalid += 1;
                                return IngestResult::Invalid;
                            };
                            let dest_hash_for_link = lte.destination_hash;

                            // An LRPROOF can only be transported after its
                            // responder identity has been reconstructed and
                            // its signature has been validated.  This mirrors
                            // Python Reticulum's fail-closed recall path.
                            if pkt.context == CONTEXT_LRPROOF {
                                let Some(pub_key) = self.known_identities.get(&dest_hash_for_link)
                                else {
                                    relay_log!(
                                        "[relay] LRPROOF REJECTED lid={} dest={} has_identity=false",
                                        hex_short(lid.as_ref()),
                                        hex_short(dest_hash_for_link.as_ref()),
                                    );
                                    self.stats.packets_dropped_invalid += 1;
                                    return IngestResult::Invalid;
                                };
                                let Ok(dest_id) = Identity::from_public_key(pub_key) else {
                                    relay_log!(
                                        "[relay] LRPROOF REJECTED lid={} dest={} identity_invalid=true",
                                        hex_short(lid.as_ref()),
                                        hex_short(dest_hash_for_link.as_ref()),
                                    );
                                    self.stats.packets_dropped_invalid += 1;
                                    return IngestResult::Invalid;
                                };
                                relay_log!(
                                    "[relay] LRPROOF_VALIDATE lid={} dest={} has_identity=true",
                                    hex_short(lid.as_ref()),
                                    hex_short(dest_hash_for_link.as_ref()),
                                );
                                if !self.validate_lrproof_relay(pkt.payload, &lid, &dest_id) {
                                    relay_log!(
                                        "[relay] LRPROOF REJECTED lid={} dest={}",
                                        hex_short(lid.as_ref()),
                                        hex_short(dest_hash_for_link.as_ref()),
                                    );
                                    self.stats.packets_dropped_invalid += 1;
                                    return IngestResult::Invalid;
                                }
                                relay_log!(
                                    "[relay] LRPROOF_VALID lid={} dest={}",
                                    hex_short(lid.as_ref()),
                                    hex_short(dest_hash_for_link.as_ref()),
                                );
                            }

                            // Only direction-, hop- and signature-validated
                            // traffic refreshes the relay entry's lifetime.
                            if let Some(lte) = self.link_table.get_mut(&lid) {
                                lte.timestamp = now;
                            }

                            relay_log!(
                                "[relay] PROOF link_table FORWARD lid={} ctx={:#04x} raw[0..20]={:02x?}",
                                hex_short(lid.as_ref()),
                                pkt.context,
                                &raw[..core::cmp::min(20, raw.len())],
                            );
                            self.stats.packets_forwarded += 1;
                            return IngestResult::Forward {
                                raw,
                                source_iface: iface,
                                target: ForwardTarget::ExactInterface(target_iface),
                            };
                        }

                        // LRPROOF is exclusively routed through a link-table
                        // entry; it must never fall back to a reverse route.
                        if pkt.context == CONTEXT_LRPROOF {
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        }
                    }

                    if let Some(reverse) = self.reverse_table.remove(&raw_dh) {
                        // Reticulum reverse routes are one-shot: consume the
                        // entry even when a proof arrives from the wrong side.
                        if iface != reverse.forwarded_to {
                            relay_log!(
                                "[relay] PROOF reverse_table WRONG_IFACE dest={} expected={} actual={}",
                                hex_short(dh.as_ref()),
                                reverse.forwarded_to,
                                iface,
                            );
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        }
                        relay_log!(
                            "[relay] PROOF reverse_table FORWARD dest={} ctx={:#04x}",
                            hex_short(dh.as_ref()),
                            pkt.context,
                        );
                        self.stats.packets_forwarded += 1;
                        IngestResult::Forward {
                            raw,
                            source_iface: iface,
                            target: ForwardTarget::ExactInterface(reverse.received_on),
                        }
                    } else {
                        self.stats.packets_dropped_invalid += 1;
                        IngestResult::Invalid
                    }
                } else if h2_ownership == Header2Ownership::Own {
                    self.stats.packets_dropped_invalid += 1;
                    IngestResult::Invalid
                } else {
                    self.stats.packets_forwarded += 1;
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                        target: ForwardTarget::AllExceptSource,
                    }
                }
            }
            PacketType::LinkRequest => {
                let dh = DestHash::from_slice(pkt.destination_hash);
                if self.is_local_destination(&dh) {
                    // Python accepts exactly the legacy 64-byte and modern
                    // 67-byte payloads. SINGLE/context-none additionally
                    // enforces the canonical form emitted by both stacks.
                    if pkt.dest_type != DestType::Single
                        || pkt.context != CONTEXT_NONE
                        || !is_valid_link_request_payload_len(pkt.payload.len())
                    {
                        self.stats.packets_dropped_invalid += 1;
                        return IngestResult::Invalid;
                    }
                    self.handle_link_request(
                        raw,
                        &dh,
                        pkt.payload,
                        link::LinkRequestIngress {
                            now: link_now,
                            hops: pkt.hops,
                            interface: iface,
                        },
                        rng,
                        identity,
                    )
                } else {
                    if h2_ownership == Header2Ownership::Own {
                        // Remote HEADER_2 LINKREQUEST/SINGLE was handled by
                        // the narrow exact-path branch above. Remaining owned
                        // forms must not inherit HEADER_1 propagation behavior.
                        self.stats.packets_dropped_invalid += 1;
                        return IngestResult::Invalid;
                    }

                    // For HEADER_1 LINKREQUEST forwarding on a transport node:
                    // also create a link_table entry so link traffic can be
                    // routed bidirectionally (same as HEADER_2 handling above).
                    //
                    // This is the same intentional local-origin compatibility
                    // seam as HEADER_1 DATA above. A later ingress-role patch
                    // should distinguish local injection from arbitrary remote
                    // ingress before narrowing it to Python's behavior.
                    if self.local_identity_hash.is_some() {
                        let Some(path) = self.paths.get(&dh) else {
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        };
                        let Some(outbound_iface) = path.received_on else {
                            self.stats.packets_dropped_invalid += 1;
                            return IngestResult::Invalid;
                        };
                        let lid = match compute_link_id(raw) {
                            Ok(lid) => lid,
                            Err(_) => {
                                self.stats.packets_dropped_invalid += 1;
                                return IngestResult::Invalid;
                            }
                        };
                        let remaining = path.hops;
                        let entry = LinkTableEntry {
                            timestamp: now,
                            received_on: iface,
                            outbound_to: outbound_iface,
                            inbound_hops: pkt.hops,
                            outbound_hops: remaining,
                            destination_hash: dh,
                        };
                        match self.admit_relay_link(lid, entry) {
                            RelayLinkAdmission::Inserted => {
                                relay_log!(
                                    "[relay] H1 LINKREQUEST link_table INSERT lid={} dest={} out_hops={} rcvd={} out={}",
                                    hex_short(lid.as_ref()),
                                    hex_short(dh.as_ref()),
                                    remaining,
                                    iface,
                                    outbound_iface,
                                );
                            }
                            RelayLinkAdmission::Existing => {
                                return IngestResult::Duplicate;
                            }
                            RelayLinkAdmission::Full => {
                                return IngestResult::LinkTableFull {
                                    link_id: lid,
                                    table: LinkTableKind::Relay,
                                };
                            }
                        }
                        self.stats.packets_forwarded += 1;
                        return IngestResult::Forward {
                            raw,
                            source_iface: iface,
                            target: ForwardTarget::ExactInterface(outbound_iface),
                        };
                    }
                    self.stats.packets_forwarded += 1;
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                        target: ForwardTarget::AllExceptSource,
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Periodic maintenance
    // -----------------------------------------------------------------------

    fn tick_non_receipts(
        &mut self,
        now: u64,
        link_now: MonotonicInstant,
    ) -> (usize, usize) {
        // Lazy-init started_at on first tick
        if self.stats.started_at == 0 {
            self.stats.started_at = now;
        }

        // Expire old paths
        let prev_paths = self.paths.len();
        self.paths
            .retain(|_, path| now.saturating_sub(path.learned_at) <= path.expiry_time());
        let expired_count = prev_paths - self.paths.len();

        // Expire old reverse table entries
        self.reverse_table
            .retain(|_, entry| now.saturating_sub(entry.timestamp) <= REVERSE_TIMEOUT);

        // Expire old link table entries (stale relayed links)
        self.link_table.retain(|_, entry| {
            now.saturating_sub(entry.timestamp) <= crate::link::STALE_TIMEOUT_SECS
        });

        // Reclaim responders that never completed LRRTT, then check established
        // Links for staleness. Both paths close and release one owned Link
        // slot; establishment timeouts are lifecycle closures rather than
        // malformed or cryptographic handshake failures.
        let prev_links = self.links.len();
        self.links.retain(|_, link| {
            if link.check_responder_establishment_timeout_at(link_now) {
                return false;
            }
            !link.check_stale_at(link_now)
        });
        let closed_count = prev_links - self.links.len();

        // Expire stale channel receipts and reclaim receipts whose owned Link
        // was removed by timed-out Link maintenance above.
        let links = &self.links;
        self.channel_receipts.retain(|_, receipt| {
            links.contains_key(&receipt.link_id)
                && now.saturating_sub(receipt.sent_at) <= RECEIPT_TIMEOUT
        });

        self.stats.paths_expired += expired_count as u64;
        self.stats.links_closed += closed_count as u64;

        (expired_count, closed_count)
    }

    /// Expire old paths, reverse entries, timed-out links, and delivery receipts
    /// into a caller-reserved terminal sink.
    ///
    /// A DATA receipt remains tracked when the sink cannot reserve its
    /// notification slot. The caller can drain the sink and retry a later tick
    /// without losing the terminal delivery state. Channel receipt expiry is
    /// maintained separately and does not produce a failure terminal.
    pub fn tick_with_receipt_sink<T: ReceiptTerminalSink>(
        &mut self,
        now: u64,
        sink: &mut T,
    ) -> TickSummary {
        self.tick_with_receipt_sink_at(now, MonotonicInstant::from_secs(now), sink)
    }

    /// Precise Link-clock variant of [`Self::tick_with_receipt_sink`].
    pub fn tick_with_receipt_sink_at<T: ReceiptTerminalSink>(
        &mut self,
        now: u64,
        link_now: MonotonicInstant,
        sink: &mut T,
    ) -> TickSummary {
        let (expired_paths, closed_links) = self.tick_non_receipts(now, link_now);
        let receipts = self.receipts.tick_into(now, sink);
        let link_data_receipts = if receipts.deferred {
            crate::receipt::ReceiptTickSummary {
                emitted: 0,
                deferred: true,
            }
        } else {
            let links = &self.links;
            self.link_data_receipts
                .tick_into(now, sink, |link_id| links.contains_key(link_id))
        };

        TickSummary {
            expired_paths,
            closed_links,
            failed_receipts: receipts.emitted,
            failed_link_data_receipts: link_data_receipts.emitted,
            receipt_notifications_deferred: receipts.deferred || link_data_receipts.deferred,
        }
    }

    /// Expire old paths, reverse entries, timed-out links, and receipts.
    ///
    /// Timed-out receipts are removed atomically and reported in
    /// [`TickResult::failed_receipts`]; callers should consume those hashes as
    /// delivery-failure notifications. The output vector reserves enough
    /// capacity before any receipt entry is removed.
    pub fn tick(&mut self, now: u64) -> TickResult {
        self.tick_at(now, MonotonicInstant::from_secs(now))
    }

    /// Precise Link-clock variant of [`Self::tick`].
    pub fn tick_at(&mut self, now: u64, link_now: MonotonicInstant) -> TickResult {
        let (expired_paths, closed_links) = self.tick_non_receipts(now, link_now);
        let failed_receipts = self.receipts.tick(now);
        let links = &self.links;
        let failed_link_data_receipts = self
            .link_data_receipts
            .tick(now, |link_id| links.contains_key(link_id));

        TickResult {
            expired_paths,
            closed_links,
            failed_receipts,
            failed_link_data_receipts,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::announce::PendingAnnounce;
    use crate::link::{Link, compute_link_id};
    use crate::path::Path;
    use rete_core::{
        CONTEXT_CHANNEL, CONTEXT_KEEPALIVE, CONTEXT_LRPROOF, DestType, HeaderType, Identity,
        PacketBuilder, PacketType, TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
    };

    type TestTransport = Transport<crate::HeaplessStorage<64, 16, 128, 4>>;
    type TwoRelayTransport = Transport<crate::HeaplessStorage<8, 4, 16, 2>>;

    #[test]
    fn new_in_initializes_empty_transport_in_place() {
        let mut destination = MaybeUninit::<TestTransport>::uninit();
        let local_destination = DestHash::from([0xA5; TRUNCATED_HASH_LEN]);

        {
            let transport = TestTransport::new_in(&mut destination);

            assert_eq!(transport.path_count(), 0);
            assert_eq!(transport.announce_count(), 0);
            assert_eq!(transport.link_count(), 0);
            assert_eq!(transport.receipt_count(), 0);
            assert_eq!(transport.link_data_receipt_count(), 0);
            assert_eq!(transport.channel_receipt_count(), 0);
            assert_eq!(transport.reverse_count(), 0);
            assert_eq!(transport.relay_link_count(), 0);
            assert_eq!(transport.local_identity_hash(), None);
            assert_eq!(transport.stats().packets_received, 0);

            transport.add_local_destination(local_destination);
            assert!(transport.is_local_destination(&local_destination));
        }

        // SAFETY: `new_in` returned successfully, so every field is initialized,
        // and the mutable reference above no longer borrows `destination`.
        unsafe { destination.assume_init_drop() };
    }

    #[test]
    fn test_path_expiry() {
        let mut transport = TestTransport::new();
        let dest = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        // Insert a path learned at timestamp 100
        let path = Path::direct(100);
        assert!(transport.insert_path(dest, path));
        assert_eq!(transport.path_count(), 1);

        // tick() before expiry — path should remain
        let result = transport.tick(100 + PATH_EXPIRES);
        assert_eq!(result.expired_paths, 0);
        assert_eq!(transport.path_count(), 1);

        // tick() after expiry — path should be cleared
        let result = transport.tick(100 + PATH_EXPIRES + 1);
        assert_eq!(result.expired_paths, 1);
        assert_eq!(transport.path_count(), 0);
    }

    #[test]
    fn test_announce_queue_at_capacity() {
        // Try to queue more announces than MAX_ANNOUNCES (16).
        let mut transport = TestTransport::new();

        for i in 0u8..16 {
            let ann = PendingAnnounce {
                dest_hash: DestHash::from([i; TRUNCATED_HASH_LEN]),
                raw: alloc::vec![i],
                tx_count: 0,
                retransmit_timeout: 0,
                local: false,
                local_rebroadcasts: 0,
                block_rebroadcasts: false,
                received_hops: 0,
                attached_interface: None,
            };
            assert!(
                transport.queue_announce(ann),
                "announce {} should be queued",
                i
            );
        }
        assert_eq!(transport.announce_count(), 16);

        // 17th announce should fail gracefully (returns false, no panic)
        let overflow = PendingAnnounce {
            dest_hash: DestHash::from([0xFF; TRUNCATED_HASH_LEN]),
            raw: alloc::vec![0xFF],
            tx_count: 0,
            retransmit_timeout: 0,
            local: false,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            received_hops: 0,
            attached_interface: None,
        };
        assert!(
            !transport.queue_announce(overflow),
            "overflow announce should return false"
        );
        assert_eq!(transport.announce_count(), 16);
    }

    #[test]
    fn test_tick_empty_tables() {
        // tick() with completely empty tables should not panic.
        let mut transport = TestTransport::new();
        assert_eq!(transport.path_count(), 0);
        assert_eq!(transport.announce_count(), 0);
        assert_eq!(transport.link_count(), 0);

        let result = transport.tick(1000);
        assert_eq!(result.expired_paths, 0);
        assert_eq!(result.closed_links, 0);
    }

    #[test]
    fn test_build_link_proof_packet_format() {
        // Verify build_link_proof_packet produces dest_type=Link and dest_hash=link_id
        let identity = Identity::from_seed(b"link-proof-test").unwrap();
        let packet_hash = [0xAA; 32];
        let link_id = LinkId::from([0xBBu8; TRUNCATED_HASH_LEN]);

        let raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("should build link proof packet");

        let pkt = rete_core::Packet::parse(&raw).expect("should parse");
        assert_eq!(pkt.packet_type, PacketType::Proof);
        assert_eq!(pkt.dest_type, DestType::Link);
        assert_eq!(pkt.destination_hash, link_id.as_ref());
        assert_eq!(pkt.payload.len(), 96);
        assert_eq!(&pkt.payload[..32], &packet_hash);
        // Verify signature is valid
        let sig = &pkt.payload[32..96];
        assert!(identity.verify(&packet_hash, sig).is_ok());
    }

    #[test]
    fn test_build_proof_packet_still_uses_single() {
        // Verify build_proof_packet still produces dest_type=Single (non-link proofs)
        let identity = Identity::from_seed(b"single-proof-test").unwrap();
        let packet_hash = [0xCC; 32];

        let raw = TestTransport::build_proof_packet(&identity, &packet_hash)
            .expect("should build proof packet");

        let pkt = rete_core::Packet::parse(&raw).expect("should parse");
        assert_eq!(pkt.packet_type, PacketType::Proof);
        assert_eq!(pkt.dest_type, DestType::Single);
        assert_eq!(pkt.destination_hash, &packet_hash[..TRUNCATED_HASH_LEN]);
        assert_eq!(pkt.payload.len(), 96);
    }

    #[test]
    fn validated_data_proof_reclaims_receipt_for_direct_transport_caller() {
        let mut transport = TestTransport::new();
        let peer = Identity::from_seed(b"direct-transport-receipt-peer").unwrap();
        let packet_hash = [0x5au8; 32];
        transport
            .register_receipt(packet_hash, peer.public_key(), 100, RECEIPT_TIMEOUT)
            .unwrap();
        assert_eq!(transport.receipt_count(), 1);

        let mut proof = TestTransport::build_proof_packet(&peer, &packet_hash)
            .expect("proof packet should build");
        let mut rng = rand::thread_rng();
        let result = transport.ingest(&mut proof, 101, &mut rng, &peer);

        assert!(matches!(
            result,
            IngestResult::ProofReceived { packet_hash: hash } if hash == packet_hash
        ));
        assert_eq!(transport.receipt_count(), 0);
        assert_eq!(transport.receipt_status(&packet_hash), None);
    }

    #[test]
    fn own_header2_receipt_proof_reserves_then_reaches_typed_dispatch() {
        let mut transport = TestTransport::new();
        let relay_hash = IdentityHash::from([0x11; TRUNCATED_HASH_LEN]);
        let peer = Identity::from_seed(b"own-header2-receipt-peer").unwrap();
        let packet_hash = [0x5a; 32];
        let destination = DestHash::from_slice(&packet_hash[..TRUNCATED_HASH_LEN]);
        transport.set_local_identity(relay_hash);
        transport
            .register_receipt(packet_hash, peer.public_key(), 100, RECEIPT_TIMEOUT)
            .unwrap();

        let ordinary_proof = TestTransport::build_proof_packet(&peer, &packet_hash).unwrap();
        let proof_payload = Packet::parse(&ordinary_proof).unwrap().payload.to_vec();
        let mut forwarded = [0u8; rete_core::MTU];
        let forwarded_len = PacketBuilder::new(&mut forwarded)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Single)
            .transport_id(relay_hash.as_ref())
            .destination_hash(destination.as_ref())
            .payload(&proof_payload)
            .build()
            .unwrap();
        let mut full_sink = crate::FixedReceiptTerminalSink::<0>::new();
        let mut rng = rand::thread_rng();
        let original = forwarded[..forwarded_len].to_vec();

        assert_eq!(
            transport
                .ingest_on_with_receipt_sink(
                    &mut forwarded[..forwarded_len],
                    101,
                    3,
                    &mut rng,
                    &peer,
                    &mut full_sink,
                )
                .unwrap_err(),
            ReceiptSinkFull
        );
        assert_eq!(&forwarded[..forwarded_len], original.as_slice());
        assert_eq!(transport.stats().started_at, 0);
        assert_eq!(transport.stats().packets_received, 0);
        assert_eq!(
            transport.receipt_status(&packet_hash),
            Some(crate::ReceiptStatus::Sent)
        );

        let mut sink = crate::FixedReceiptTerminalSink::<1>::new();
        let result = transport
            .ingest_on_with_receipt_sink(
                &mut forwarded[..forwarded_len],
                101,
                3,
                &mut rng,
                &peer,
                &mut sink,
            )
            .expect("reserved own proof should reach typed validation");

        assert!(matches!(
            result,
            IngestResult::ProofReceived { packet_hash: hash } if hash == packet_hash
        ));
        assert_eq!(transport.receipt_status(&packet_hash), None);
        assert_eq!(sink.as_slice(), &[ReceiptTerminal::Delivered(packet_hash)]);
        assert_eq!(transport.reverse_count(), 0);
    }

    #[test]
    fn foreign_header2_proof_cannot_reserve_a_local_receipt() {
        let mut transport = TestTransport::new();
        let relay_hash = IdentityHash::from([0x11; TRUNCATED_HASH_LEN]);
        let foreign_hash = IdentityHash::from([0x22; TRUNCATED_HASH_LEN]);
        let peer = Identity::from_seed(b"foreign-header2-receipt-peer").unwrap();
        let packet_hash = [0x6b; 32];
        let destination = DestHash::from_slice(&packet_hash[..TRUNCATED_HASH_LEN]);
        transport.set_local_identity(relay_hash);
        transport
            .register_receipt(packet_hash, peer.public_key(), 100, RECEIPT_TIMEOUT)
            .unwrap();

        let ordinary_proof = TestTransport::build_proof_packet(&peer, &packet_hash).unwrap();
        let proof_payload = Packet::parse(&ordinary_proof).unwrap().payload.to_vec();
        let mut foreign = [0u8; rete_core::MTU];
        let foreign_len = PacketBuilder::new(&mut foreign)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Single)
            .transport_id(foreign_hash.as_ref())
            .destination_hash(destination.as_ref())
            .payload(&proof_payload)
            .build()
            .unwrap();
        let original = foreign[..foreign_len].to_vec();
        let mut full_sink = crate::FixedReceiptTerminalSink::<0>::new();
        let mut rng = rand::thread_rng();

        assert!(matches!(
            transport
                .ingest_on_with_receipt_sink(
                    &mut foreign[..foreign_len],
                    101,
                    3,
                    &mut rng,
                    &peer,
                    &mut full_sink,
                )
                .expect("foreign proof must not reserve terminal capacity"),
            IngestResult::Invalid
        ));
        assert_eq!(&foreign[..foreign_len], original.as_slice());
        assert_eq!(transport.stats().started_at, 0);
        assert_eq!(transport.stats().packets_received, 0);
        assert_eq!(
            transport.receipt_status(&packet_hash),
            Some(crate::ReceiptStatus::Sent)
        );
        assert!(full_sink.is_empty());
    }

    #[test]
    fn channel_candidate_requires_full_hash_and_destination_link_match() {
        let mut transport = TestTransport::new();
        let expected_hash = [0x44; 32];
        let expected_link = LinkId::from([0x77; TRUNCATED_HASH_LEN]);
        let mut key = [0u8; TRUNCATED_HASH_LEN];
        key.copy_from_slice(&expected_hash[..TRUNCATED_HASH_LEN]);
        transport
            .channel_receipts
            .insert(
                key,
                ChannelReceipt {
                    link_id: expected_link,
                    packet_hash: expected_hash,
                    sequence: 7,
                    sent_at: 100,
                },
            )
            .unwrap();

        let signer = Identity::from_seed(b"channel-candidate-exactness").unwrap();
        let mut colliding_hash = expected_hash;
        colliding_hash[TRUNCATED_HASH_LEN..].fill(0x55);
        let wrong_hash_proof =
            TestTransport::build_link_proof_packet(&signer, &colliding_hash, &expected_link)
                .unwrap();
        let other_link = LinkId::from([0x88; TRUNCATED_HASH_LEN]);
        let wrong_link_proof =
            TestTransport::build_link_proof_packet(&signer, &expected_hash, &other_link).unwrap();
        let mut full_sink = crate::FixedReceiptTerminalSink::<0>::new();
        let mut rng = rand::thread_rng();

        for mut proof in [wrong_hash_proof, wrong_link_proof] {
            let result = transport
                .ingest_on_with_receipt_sink(
                    &mut proof,
                    101,
                    0,
                    &mut rng,
                    &signer,
                    &mut full_sink,
                )
                .expect("a non-matching channel proof must not reserve a terminal slot");
            assert!(!matches!(result, IngestResult::ProofReceived { .. }));
            assert_eq!(transport.channel_receipt_count(), 1);
        }
        assert!(full_sink.is_empty());
    }

    #[test]
    fn test_link_proof_vs_single_proof_differ() {
        // Link proof and single proof for the same packet_hash should differ
        // in dest_type and destination_hash
        let identity = Identity::from_seed(b"diff-proof-test").unwrap();
        let packet_hash = [0xDD; 32];
        let link_id = LinkId::from([0xEEu8; TRUNCATED_HASH_LEN]);

        let link_raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("link proof");
        let single_raw =
            TestTransport::build_proof_packet(&identity, &packet_hash).expect("single proof");

        let link_pkt = rete_core::Packet::parse(&link_raw).unwrap();
        let single_pkt = rete_core::Packet::parse(&single_raw).unwrap();

        assert_eq!(link_pkt.dest_type, DestType::Link);
        assert_eq!(single_pkt.dest_type, DestType::Single);
        assert_eq!(link_pkt.destination_hash, link_id.as_ref());
        assert_eq!(
            single_pkt.destination_hash,
            &packet_hash[..TRUNCATED_HASH_LEN]
        );
        // Payloads should be the same (packet_hash + signature)
        assert_eq!(link_pkt.payload, single_pkt.payload);
    }

    // -----------------------------------------------------------------------
    // Link relay forwarding via link_table
    // -----------------------------------------------------------------------

    /// Helper: build a HEADER_1 LINKREQUEST packet.
    fn build_h1_linkrequest(dest_hash: &DestHash, payload: &[u8]) -> ([u8; rete_core::MTU], usize) {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .hops(0)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(payload)
            .build()
            .unwrap();
        (buf, n)
    }

    /// Helper: build a HEADER_2 LINKREQUEST packet targeting a relay.
    fn build_h2_linkrequest(
        relay_id: &IdentityHash,
        dest_hash: &DestHash,
        payload: &[u8],
    ) -> ([u8; rete_core::MTU], usize) {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .hops(0)
            .transport_id(relay_id.as_ref())
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(payload)
            .build()
            .unwrap();
        (buf, n)
    }

    fn wrap_header2(
        raw: &[u8],
        transport_id: &IdentityHash,
        hops: u8,
    ) -> ([u8; rete_core::MTU], usize) {
        let packet = Packet::parse(raw).unwrap();
        let mut buf = [0u8; rete_core::MTU];
        let len = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(packet.packet_type)
            .dest_type(packet.dest_type)
            .context_flag(packet.context_flag)
            .hops(hops)
            .transport_id(transport_id.as_ref())
            .destination_hash(packet.destination_hash)
            .context(packet.context)
            .payload(packet.payload)
            .build()
            .unwrap();
        (buf, len)
    }

    /// Helper: set up a transport relay with a learned path for the destination.
    fn make_relay_transport(relay_hash: IdentityHash, dest_hash: DestHash) -> TestTransport {
        let mut t = TestTransport::new();
        t.set_local_identity(relay_hash);
        let mut path = Path::direct(0);
        path.received_on = Some(1);
        t.insert_path(dest_hash, path);
        t
    }

    fn insert_relay_path<S: crate::TransportStorage>(
        transport: &mut Transport<S>,
        dest_hash: DestHash,
        iface: u8,
    ) {
        let mut path = Path::direct(0);
        path.received_on = Some(iface);
        assert!(transport.insert_path(dest_hash, path));
    }

    fn relay_entry(tag: u8) -> LinkTableEntry {
        LinkTableEntry {
            timestamp: u64::from(tag),
            received_on: tag,
            outbound_to: tag.saturating_add(1),
            inbound_hops: tag.saturating_add(2),
            outbound_hops: tag.saturating_add(3),
            destination_hash: DestHash::from([tag; TRUNCATED_HASH_LEN]),
        }
    }

    #[test]
    fn relay_link_admission_distinguishes_existing_from_full_without_replacement() {
        let mut transport = TwoRelayTransport::new();
        let existing_id = LinkId::from([0x11; TRUNCATED_HASH_LEN]);
        let other_id = LinkId::from([0x22; TRUNCATED_HASH_LEN]);
        let overflow_id = LinkId::from([0x33; TRUNCATED_HASH_LEN]);
        let retained = relay_entry(1);
        let replacement = relay_entry(9);

        assert_eq!(
            transport.admit_relay_link(existing_id, retained),
            RelayLinkAdmission::Inserted
        );
        assert_eq!(transport.relay_link_count(), 1);
        assert_eq!(
            transport.admit_relay_link(existing_id, replacement),
            RelayLinkAdmission::Existing
        );
        assert_eq!(transport.get_relay_link(&existing_id), Some(&retained));
        assert_eq!(
            transport.admit_relay_link(other_id, relay_entry(2)),
            RelayLinkAdmission::Inserted
        );
        assert_eq!(
            transport.admit_relay_link(overflow_id, relay_entry(3)),
            RelayLinkAdmission::Full
        );
        assert_eq!(transport.relay_link_count(), 2);
        assert_eq!(transport.get_relay_link(&existing_id), Some(&retained));
        assert!(transport.get_relay_link(&other_id).is_some());
        assert!(transport.get_relay_link(&overflow_id).is_none());
    }

    #[test]
    fn h2_relay_link_capacity_rejects_before_forward_and_preserves_dedup() {
        let relay_hash = IdentityHash::from([0x31; TRUNCATED_HASH_LEN]);
        let first_dest = DestHash::from([0x41; TRUNCATED_HASH_LEN]);
        let second_dest = DestHash::from([0x42; TRUNCATED_HASH_LEN]);
        let overflow_dest = DestHash::from([0x43; TRUNCATED_HASH_LEN]);
        let identity = Identity::from_seed(b"bounded-h2-relay-link").unwrap();
        let mut rng = rand_core::OsRng;
        let mut transport = TwoRelayTransport::new();
        transport.set_local_identity(relay_hash);
        insert_relay_path(&mut transport, first_dest, 7);
        insert_relay_path(&mut transport, second_dest, 8);
        insert_relay_path(&mut transport, overflow_dest, 9);

        let (mut first, first_len) = build_h2_linkrequest(&relay_hash, &first_dest, &[0x51; 64]);
        let first_id = compute_link_id(&first[..first_len]).unwrap();
        assert!(matches!(
            transport.ingest_on(&mut first[..first_len], 100, 3, &mut rng, &identity),
            IngestResult::Forward {
                source_iface: 3,
                target: ForwardTarget::ExactInterface(7),
                ..
            }
        ));
        let retained = *transport.get_relay_link(&first_id).unwrap();
        let (mut second, second_len) = build_h2_linkrequest(&relay_hash, &second_dest, &[0x52; 64]);
        assert!(matches!(
            transport.ingest_on(&mut second[..second_len], 101, 4, &mut rng, &identity),
            IngestResult::Forward {
                source_iface: 4,
                target: ForwardTarget::ExactInterface(8),
                ..
            }
        ));
        assert_eq!(transport.relay_link_count(), 2);
        assert_eq!(transport.reverse_count(), 0);

        let (overflow, overflow_len) =
            build_h2_linkrequest(&relay_hash, &overflow_dest, &[0x53; 64]);
        let overflow_id = compute_link_id(&overflow[..overflow_len]).unwrap();
        let mut rejected = overflow;
        let forwarded_before = transport.stats().packets_forwarded;
        assert!(matches!(
            transport.ingest_on(
                &mut rejected[..overflow_len],
                102,
                5,
                &mut rng,
                &identity,
            ),
            IngestResult::LinkTableFull {
                link_id,
                table: LinkTableKind::Relay,
            } if link_id == overflow_id
        ));
        assert_eq!(
            &rejected[..overflow_len],
            &overflow[..overflow_len],
            "capacity rejection must not rewrite an unforwarded H2 packet"
        );
        assert_eq!(transport.stats().packets_forwarded, forwarded_before);
        assert_eq!(transport.relay_link_count(), 2);
        assert_eq!(transport.get_relay_link(&first_id), Some(&retained));
        assert!(transport.get_relay_link(&overflow_id).is_none());
        assert_eq!(transport.reverse_count(), 0);

        let _ = transport.tick(101 + crate::link::STALE_TIMEOUT_SECS + 1);
        assert_eq!(transport.relay_link_count(), 0);
        let mut replay = overflow;
        assert!(matches!(
            transport.ingest_on(
                &mut replay[..overflow_len],
                101 + crate::link::STALE_TIMEOUT_SECS + 2,
                5,
                &mut rng,
                &identity,
            ),
            IngestResult::Duplicate
        ));
        assert_eq!(transport.relay_link_count(), 0);

        let (mut fresh, fresh_len) = build_h2_linkrequest(&relay_hash, &overflow_dest, &[0x54; 64]);
        assert!(matches!(
            transport.ingest_on(
                &mut fresh[..fresh_len],
                101 + crate::link::STALE_TIMEOUT_SECS + 3,
                5,
                &mut rng,
                &identity,
            ),
            IngestResult::Forward {
                source_iface: 5,
                target: ForwardTarget::ExactInterface(9),
                ..
            }
        ));
        assert_eq!(transport.relay_link_count(), 1);
    }

    #[test]
    fn h1_relay_link_capacity_rejects_without_forwarding() {
        let relay_hash = IdentityHash::from([0x61; TRUNCATED_HASH_LEN]);
        let first_dest = DestHash::from([0x71; TRUNCATED_HASH_LEN]);
        let second_dest = DestHash::from([0x72; TRUNCATED_HASH_LEN]);
        let overflow_dest = DestHash::from([0x73; TRUNCATED_HASH_LEN]);
        let identity = Identity::from_seed(b"bounded-h1-relay-link").unwrap();
        let mut rng = rand_core::OsRng;
        let mut transport = TwoRelayTransport::new();
        transport.set_local_identity(relay_hash);
        insert_relay_path(&mut transport, first_dest, 7);
        insert_relay_path(&mut transport, second_dest, 8);
        insert_relay_path(&mut transport, overflow_dest, 9);

        let (mut first, first_len) = build_h1_linkrequest(&first_dest, &[0x81; 64]);
        let first_id = compute_link_id(&first[..first_len]).unwrap();
        assert!(matches!(
            transport.ingest_on(&mut first[..first_len], 100, 3, &mut rng, &identity),
            IngestResult::Forward {
                source_iface: 3,
                target: ForwardTarget::ExactInterface(7),
                ..
            }
        ));
        let retained = *transport.get_relay_link(&first_id).unwrap();

        let (mut second, second_len) = build_h1_linkrequest(&second_dest, &[0x82; 64]);
        assert!(matches!(
            transport.ingest_on(&mut second[..second_len], 101, 4, &mut rng, &identity),
            IngestResult::Forward {
                source_iface: 4,
                target: ForwardTarget::ExactInterface(8),
                ..
            }
        ));

        let (mut overflow, overflow_len) = build_h1_linkrequest(&overflow_dest, &[0x83; 64]);
        let overflow_id = compute_link_id(&overflow[..overflow_len]).unwrap();
        let forwarded_before = transport.stats().packets_forwarded;
        assert!(matches!(
            transport.ingest_on(
                &mut overflow[..overflow_len],
                102,
                5,
                &mut rng,
                &identity,
            ),
            IngestResult::LinkTableFull {
                link_id,
                table: LinkTableKind::Relay,
            } if link_id == overflow_id
        ));
        assert_eq!(transport.stats().packets_forwarded, forwarded_before);
        assert_eq!(transport.relay_link_count(), 2);
        assert_eq!(transport.get_relay_link(&first_id), Some(&retained));
        assert!(transport.get_relay_link(&overflow_id).is_none());
        assert_eq!(transport.reverse_count(), 0);
    }

    #[test]
    fn relay_link_missing_or_unbound_path_never_allocates_state() {
        let relay_hash = IdentityHash::from([0x91; TRUNCATED_HASH_LEN]);
        let missing_dest = DestHash::from([0x92; TRUNCATED_HASH_LEN]);
        let unbound_dest = DestHash::from([0x93; TRUNCATED_HASH_LEN]);
        let identity = Identity::from_seed(b"relay-link-missing-route").unwrap();
        let mut rng = rand_core::OsRng;
        let mut transport = TwoRelayTransport::new();
        transport.set_local_identity(relay_hash);
        assert!(transport.insert_path(unbound_dest, Path::direct(0)));

        let (mut h2, h2_len) = build_h2_linkrequest(&relay_hash, &missing_dest, &[0x94; 64]);
        assert!(matches!(
            transport.ingest_on(&mut h2[..h2_len], 100, 3, &mut rng, &identity),
            IngestResult::Invalid
        ));
        assert_eq!(transport.relay_link_count(), 0);

        let (mut h1, h1_len) = build_h1_linkrequest(&unbound_dest, &[0x95; 64]);
        assert!(matches!(
            transport.ingest_on(&mut h1[..h1_len], 101, 4, &mut rng, &identity),
            IngestResult::Invalid
        ));
        assert_eq!(transport.relay_link_count(), 0);
        assert_eq!(transport.reverse_count(), 0);
    }

    /// Set up a relay link entry and a cryptographically valid LRPROOF.
    fn make_relay_with_valid_lrproof(
        now: u64,
    ) -> (TestTransport, LinkId, alloc::vec::Vec<u8>, Identity) {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let initiator = Identity::from_seed(b"relay-valid-proof-initiator").unwrap();
        let responder = Identity::from_seed(b"relay-valid-proof-responder").unwrap();
        let destination_hash =
            rete_core::destination_hash("test.link.relay-proof", Some(&responder.hash()));
        let mut transport = make_relay_transport(relay_hash, destination_hash);
        transport.register_identity(destination_hash, responder.public_key(), now);
        // register_identity() also creates a direct path without a bound
        // interface. Rebind the test path to the responder-side interface.
        let mut path = Path::direct(now);
        path.received_on = Some(1);
        transport.insert_path(destination_hash, path);

        let mut rng = rand_core::OsRng;
        let (_, request_payload) =
            Link::new_initiator(destination_hash, initiator.ed25519_pub(), &mut rng, now);
        let (mut request, request_len) =
            build_h2_linkrequest(&relay_hash, &destination_hash, &request_payload);
        let link_id = compute_link_id(&request[..request_len]).unwrap();
        assert!(matches!(
            transport.ingest_on(&mut request[..request_len], now, 0, &mut rng, &initiator,),
            IngestResult::Forward {
                source_iface: 0,
                target: ForwardTarget::ExactInterface(1),
                ..
            }
        ));

        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, now).unwrap();
        let proof_payload = responder_link.build_proof(&responder).unwrap();
        let mut proof = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
            .unwrap();

        (transport, link_id, proof[..proof_len].to_vec(), initiator)
    }

    #[test]
    fn test_h2_linkrequest_creates_link_table_entry() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-lr-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build LINKREQUEST payload (x25519_pub[32] || ed25519_pub[32])
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);

        // Before ingest, link_table should be empty
        assert_eq!(transport.link_table.len(), 0);

        let result = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Should forward (H2 -> H1 conversion since path is direct)
        assert!(matches!(
            result,
            IngestResult::Forward {
                source_iface: 0,
                target: ForwardTarget::ExactInterface(1),
                ..
            }
        ));

        // link_table should now have an entry
        assert_eq!(
            transport.link_table.len(),
            1,
            "link_table should have 1 entry after LINKREQUEST"
        );
        assert_eq!(
            transport.reverse_table.len(),
            0,
            "LINKREQUEST relay admission must not consume reverse-table capacity"
        );
    }

    #[test]
    fn test_link_data_forwarded_via_link_table() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-data-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Step 1: Forward a LINKREQUEST to create a link_table entry
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.len(), 1);

        // Step 2: Build link DATA and target this transport with HEADER_2.
        // It must normalize into typed Link routing, not generic path/reverse
        // handling.
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();
        let (mut header2_data, header2_len) = wrap_header2(&data_buf[..data_len], &relay_hash, 0);

        match transport.ingest_on(
            &mut header2_data[..header2_len],
            101,
            0,
            &mut rng,
            &identity,
        ) {
            IngestResult::Forward {
                raw,
                source_iface: 0,
                target: ForwardTarget::ExactInterface(1),
            } => assert_eq!(Packet::parse(raw).unwrap().header_type, HeaderType::Header1),
            other => panic!("expected typed exact-interface Link forward, got {other:?}"),
        }
        assert_eq!(transport.reverse_count(), 0);
    }

    #[test]
    fn test_link_proof_forwarded_via_link_table() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-proof-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Step 1: Forward a LINKREQUEST to create a link_table entry
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Step 2: Build a non-LRPROOF packet addressed to the link. Link
        // proofs follow the general bidirectional link-table rules.
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_CHANNEL)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut proof_buf[..proof_len], 101, 1, &mut rng, &identity);

        assert!(matches!(
            result,
            IngestResult::Forward {
                source_iface: 1,
                target: ForwardTarget::ExactInterface(0),
                ..
            }
        ));
    }

    #[test]
    fn test_valid_lrproof_is_forwarded_and_refreshes_link_entry() {
        let mut rng = rand_core::OsRng;
        let (mut transport, link_id, mut proof, identity) = make_relay_with_valid_lrproof(100);

        assert!(matches!(
            transport.ingest_on(&mut proof, 500, 1, &mut rng, &identity),
            IngestResult::Forward {
                source_iface: 1,
                target: ForwardTarget::ExactInterface(0),
                ..
            }
        ));
        assert_eq!(transport.link_table.get(&link_id).unwrap().timestamp, 500);
    }

    #[test]
    fn test_header2_lrproof_normalizes_into_strict_relay_validation() {
        let mut rng = rand_core::OsRng;
        let (mut transport, link_id, proof, identity) = make_relay_with_valid_lrproof(100);
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let (mut header2_proof, proof_len) = wrap_header2(&proof, &relay_hash, 0);

        let forwarded_before = transport.stats().packets_forwarded;
        match transport.ingest_on(&mut header2_proof[..proof_len], 500, 1, &mut rng, &identity) {
            IngestResult::Forward {
                raw,
                source_iface: 1,
                target: ForwardTarget::ExactInterface(0),
            } => {
                let normalized = Packet::parse(raw).unwrap();
                assert_eq!(normalized.header_type, HeaderType::Header1);
                assert_eq!(normalized.packet_type, PacketType::Proof);
                assert_eq!(normalized.dest_type, DestType::Link);
                assert_eq!(normalized.context, CONTEXT_LRPROOF);
            }
            other => panic!("expected validated exact-interface LRPROOF forward, got {other:?}"),
        }
        assert_eq!(
            transport.link_table.get(&link_id).unwrap().timestamp,
            500,
            "a validated HEADER_2 LRPROOF must refresh the relay entry"
        );
        assert_eq!(transport.stats().packets_forwarded, forwarded_before + 1);
        assert_eq!(transport.stats().packets_dropped_invalid, 0);
        assert_eq!(
            transport.reverse_table.len(),
            0,
            "HEADER_2 LRPROOF must not allocate reverse state"
        );
    }

    #[test]
    fn invalid_header2_lrproof_never_refreshes_or_allocates_reverse_state() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);

        for case in ["signature", "direction", "hops"] {
            let mut rng = rand_core::OsRng;
            let (mut transport, link_id, proof, identity) = make_relay_with_valid_lrproof(100);
            let (mut header2, len) = wrap_header2(&proof, &relay_hash, u8::from(case == "hops"));
            if case == "signature" {
                header2[len - 1] ^= 0x80;
            }
            let iface = if case == "direction" { 0 } else { 1 };

            assert!(matches!(
                transport.ingest_on(&mut header2[..len], 500, iface, &mut rng, &identity),
                IngestResult::Invalid
            ));
            assert_eq!(transport.link_table.get(&link_id).unwrap().timestamp, 100);
            assert_eq!(transport.stats().packets_forwarded, 1);
            assert_eq!(transport.stats().packets_dropped_invalid, 1);
            assert_eq!(transport.reverse_count(), 0);
        }
    }

    #[test]
    fn test_lrproof_from_initiator_side_is_rejected_without_refresh() {
        let (mut transport, link_id, mut proof, identity) = make_relay_with_valid_lrproof(100);
        let mut rng = rand_core::OsRng;

        assert!(matches!(
            transport.ingest_on(&mut proof, 500, 0, &mut rng, &identity),
            IngestResult::Invalid
        ));
        assert_eq!(
            transport.link_table.get(&link_id).unwrap().timestamp,
            100,
            "a wrong-side LRPROOF must not refresh the relay entry"
        );
    }

    #[test]
    fn test_lrproof_with_wrong_hops_is_rejected_without_refresh() {
        let (mut transport, link_id, mut proof, identity) = make_relay_with_valid_lrproof(100);
        let mut rng = rand_core::OsRng;

        // The relay increments this to two, while the direct responder side
        // recorded outbound_hops=1. Hop bytes are not covered by LRPROOF's
        // responder signature, so the proof remains cryptographically valid.
        proof[1] = 1;

        assert!(matches!(
            transport.ingest_on(&mut proof, 500, 1, &mut rng, &identity),
            IngestResult::Invalid
        ));
        assert_eq!(
            transport.link_table.get(&link_id).unwrap().timestamp,
            100,
            "a wrong-hop LRPROOF must not refresh the relay entry"
        );
    }

    #[test]
    fn test_link_data_without_link_table_entry_is_invalid() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut transport = TestTransport::new();
        transport.set_local_identity(relay_hash);
        let identity = Identity::from_seed(b"relay-no-entry-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build a link DATA packet for a link_id we don't know about
        let unknown_link_id = [0xFFu8; TRUNCATED_HASH_LEN];
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(&unknown_link_id)
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut data_buf[..data_len], 101, 0, &mut rng, &identity);

        assert!(
            matches!(result, IngestResult::Invalid),
            "Link DATA without link_table entry should be Invalid, got {:?}",
            core::mem::discriminant(&result)
        );
    }

    #[test]
    fn test_link_table_entry_refreshed_on_traffic() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-refresh-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward a LINKREQUEST at time=100
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.get(&link_id).unwrap().timestamp, 100);

        // Forward link DATA at time=500 — should refresh the timestamp
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let _ = transport.ingest_on(&mut data_buf[..data_len], 500, 0, &mut rng, &identity);

        assert_eq!(
            transport.link_table.get(&link_id).unwrap().timestamp,
            500,
            "link_table timestamp should be refreshed on traffic"
        );
    }

    #[test]
    fn test_link_table_entry_expires_after_stale_timeout() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-expiry-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward a LINKREQUEST at time=100
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let _link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.len(), 1);

        // tick() before stale timeout — entry should remain
        let _ = transport.tick(100 + crate::link::STALE_TIMEOUT_SECS);
        assert_eq!(transport.link_table.len(), 1, "should not expire yet");

        // tick() after stale timeout — entry should be removed
        let _ = transport.tick(100 + crate::link::STALE_TIMEOUT_SECS + 1);
        assert_eq!(
            transport.link_table.len(),
            0,
            "should expire after stale timeout"
        );
    }

    #[test]
    fn test_multiple_link_data_forwarded_via_link_table() {
        // Verify that multiple DATA packets can be forwarded (entry persists)
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-multi-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Forward 5 DATA packets — all should succeed
        for i in 0u8..5 {
            let mut data_buf = [0u8; rete_core::MTU];
            let data_len = PacketBuilder::new(&mut data_buf)
                .packet_type(PacketType::Data)
                .dest_type(DestType::Link)
                .destination_hash(link_id.as_ref())
                .context(0x00)
                .payload(&[i; 16])
                .build()
                .unwrap();

            let result = transport.ingest_on(
                &mut data_buf[..data_len],
                101 + i as u64,
                0,
                &mut rng,
                &identity,
            );

            assert!(
                matches!(result, IngestResult::Forward { .. }),
                "DATA packet {} should be forwarded",
                i
            );
        }

        // link_table entry should still exist
        assert_eq!(transport.link_table.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Link relay correctness: hop counts, direction, interface tracking
    // (Bugs found via Python RNS reference comparison)
    // -----------------------------------------------------------------------

    #[test]
    fn test_h2_link_table_stores_post_increment_hops() {
        // Bug A: H2 handler captured inbound_hops BEFORE incrementing raw[1].
        // Python stores post-increment (Transport.py:1319,1488).
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-hops-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build H2 LINKREQUEST with hops=0 (freshly sent by initiator)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        assert_eq!(buf[1], 0, "initial hops should be 0");

        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // After processing, the relay incremented hops (0 -> 1).
        // The stored inbound_hops must be the POST-increment value (1),
        // matching Python's behavior.
        let entry = transport
            .link_table
            .get(&link_id)
            .expect("link_table entry");
        assert_eq!(
            entry.inbound_hops, 1,
            "H2 link_table inbound_hops should be post-increment (1), not pre-increment (0)"
        );
    }

    #[test]
    fn test_link_data_rejected_with_wrong_hop_count() {
        // Bug B: Rust used hops <= max_hops (lax). Python uses exact match
        // (Transport.py:1530-1537). Wrong hop count must be rejected.
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-exact-hops-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST from iface 0 (initiator side)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        let entry = transport.link_table.get(&link_id).expect("entry exists");
        let expected_inbound = entry.inbound_hops;
        let expected_outbound = entry.outbound_hops;

        // Send link DATA from initiator side (iface 0) with CORRECT hops.
        // After the global +1 at line 986, pkt.hops should match inbound_hops.
        // Build with hops = expected_inbound - 1 (pre-increment, since ingest adds 1).
        let correct_hops = expected_inbound.saturating_sub(1);
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .hops(correct_hops)
            .context(CONTEXT_CHANNEL)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut data_buf[..data_len], 101, 0, &mut rng, &identity);
        assert!(
            matches!(result, IngestResult::Forward { .. }),
            "Link DATA with correct hops should be forwarded"
        );

        // Now send from responder side (iface 1) with WRONG hops.
        // Use a hops value that's within max_hops range but doesn't
        // match the exact expected value.
        let wrong_hops = expected_outbound.saturating_add(1); // off by 1
        let mut bad_buf = [0u8; rete_core::MTU];
        let bad_len = PacketBuilder::new(&mut bad_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .hops(wrong_hops)
            .context(CONTEXT_CHANNEL)
            .payload(&[0x43; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut bad_buf[..bad_len], 102, 1, &mut rng, &identity);
        assert!(
            !matches!(result, IngestResult::Forward { .. }),
            "Link DATA with wrong hop count should NOT be forwarded (exact match required)"
        );
    }

    #[test]
    fn test_link_table_tracks_outbound_interface() {
        // Bug C: LinkTableEntry must track the outbound interface (toward
        // responder) so bidirectional routing can validate packet direction,
        // matching Python's IDX_LT_NH_IF.
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-iface-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST received on iface 0 (toward initiator)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        let _ = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        let entry = transport.link_table.get(&link_id).expect("entry exists");

        // received_on should be 0 (the interface the LINKREQUEST arrived on)
        assert_eq!(entry.received_on, 0, "received_on should be iface 0");

        // outbound_to must preserve the interface where the destination path
        // was learned. It must never fall back to interface zero.
        assert_eq!(
            entry.outbound_to, 1,
            "outbound_to should be path interface 1"
        );
    }

    // -----------------------------------------------------------------------
    // Link lifecycle tests (keepalive, stale expiry)
    // -----------------------------------------------------------------------

    /// Helper: create a transport with one active link via the handshake flow.
    /// Returns (transport, link_id, responder_identity).
    fn make_transport_with_active_link(now: u64) -> (TestTransport, LinkId, Identity) {
        let mut transport = TestTransport::new();
        let mut rng = rand_core::OsRng;

        let initiator_identity = Identity::from_seed(b"transport-test-initiator").unwrap();
        let responder_identity = Identity::from_seed(b"transport-test-responder").unwrap();

        // Compute the destination hash for the responder
        let id_hash = responder_identity.hash();
        let dest_hash = rete_core::destination_hash("test.link.target", Some(&id_hash));

        // Register the responder's identity so validate_proof can look it up
        transport.register_identity(dest_hash, responder_identity.public_key(), now);

        // Initiate a link (creates a Pending/Handshake link)
        let (lr_raw, link_id) = transport
            .initiate_link(dest_hash, &initiator_identity, &mut rng, now)
            .expect("initiate_link should succeed");

        // Parse the LINKREQUEST to extract the initiator's payload
        let lr_pkt = rete_core::Packet::parse(&lr_raw).unwrap();
        // Determine raw payload offset: for HEADER_2 packets, strip the
        // transport_id prefix that PacketBuilder may have added.
        let request_payload = lr_pkt.payload;

        // Responder creates a link from the request
        let responder_link = Link::from_request(link_id, request_payload, &mut rng, now).unwrap();

        // Responder builds LRPROOF
        let proof_payload = responder_link.build_proof(&responder_identity).unwrap();

        // Build an LRPROOF packet and feed it through ingest to complete the handshake
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
            .unwrap();

        let result = transport.ingest_on(
            &mut proof_buf[..proof_len],
            now,
            0,
            &mut rng,
            &initiator_identity,
        );
        assert!(
            matches!(result, IngestResult::LinkEstablished { .. }),
            "handshake should complete, got {:?}",
            core::mem::discriminant(&result)
        );

        // Verify link is active
        let link = transport.get_link(&link_id).unwrap();
        assert!(link.is_active());

        (transport, link_id, responder_identity)
    }

    #[test]
    fn responder_link_binds_linkrequest_ingress_interface() {
        let now = 100;
        let mut transport = TestTransport::new();
        let responder = Identity::from_seed(b"bound-responder").unwrap();
        let initiator = Identity::from_seed(b"bound-initiator").unwrap();
        let dest_hash = rete_core::destination_hash("test.bound.responder", Some(&responder.hash()));
        transport.add_local_destination(dest_hash);
        let mut rng = rand_core::OsRng;
        let (_, request_payload) =
            Link::new_initiator(dest_hash, initiator.ed25519_pub(), &mut rng, now);
        let (mut request, request_len) = build_h1_linkrequest(&dest_hash, &request_payload);
        let link_id = compute_link_id(&request[..request_len]).unwrap();

        assert!(matches!(
            transport.ingest_on(
                &mut request[..request_len],
                now,
                6,
                &mut rng,
                &responder,
            ),
            IngestResult::LinkRequestReceived { .. }
        ));
        assert_eq!(transport.link_interface(&link_id), Some(6));
        assert_eq!(
            transport.get_link(&link_id).unwrap().bound_interface(),
            Some(6)
        );
    }

    #[test]
    fn initiator_binds_only_valid_lrproof_ingress_and_never_migrates() {
        let now = 200;
        let mut transport = TestTransport::new();
        let initiator = Identity::from_seed(b"proof-bound-initiator").unwrap();
        let responder = Identity::from_seed(b"proof-bound-responder").unwrap();
        let dest_hash =
            rete_core::destination_hash("test.bound.initiator", Some(&responder.hash()));
        transport.register_identity(dest_hash, responder.public_key(), now);
        let mut learned = Path::direct(now);
        learned.received_on = Some(7);
        assert!(transport.insert_path(dest_hash, learned));
        let mut rng = rand_core::OsRng;

        let (request, link_id) = transport
            .initiate_link(dest_hash, &initiator, &mut rng, now)
            .unwrap();
        assert_eq!(transport.link_interface(&link_id), None);
        let pending = transport.get_link(&link_id).unwrap();
        assert_eq!(pending.state, crate::link::LinkState::Handshake);
        assert_eq!(pending.expected_hops(), Some(1));

        // The pending Link retains the path height from construction even if
        // routing knowledge changes before its LRPROOF returns.
        let mut changed_path = Path::via_repeater(initiator.hash(), 4, now + 1);
        changed_path.received_on = Some(3);
        assert!(transport.insert_path(dest_hash, changed_path));
        assert_eq!(
            transport.get_link(&link_id).unwrap().expected_hops(),
            Some(1)
        );

        let request_payload = Packet::parse(&request).unwrap().payload;
        let responder_link =
            Link::from_request(link_id, request_payload, &mut rng, now).unwrap();
        let proof_payload = responder_link.build_proof(&responder).unwrap();
        let build_proof = |payload: &[u8]| {
            let mut proof = [0u8; rete_core::MTU];
            let len = PacketBuilder::new(&mut proof)
                .packet_type(PacketType::Proof)
                .dest_type(DestType::Link)
                .destination_hash(link_id.as_ref())
                .context(CONTEXT_LRPROOF)
                .payload(payload)
                .build()
                .unwrap();
            (proof, len)
        };

        let mut invalid_payload = proof_payload;
        invalid_payload[0] ^= 0x80;

        // Hop bytes are excluded from the packet hash. A valid proof first
        // observed one hop too high must be rejected before dedup admission,
        // leaving the authoritative copy below eligible for validation.
        let (mut wrong_hops, wrong_hops_len) = build_proof(&proof_payload);
        wrong_hops[1] = 1; // local ingress increments this to 2; retained path is 1
        assert!(matches!(
            transport.ingest_on(
                &mut wrong_hops[..wrong_hops_len],
                now + 1,
                4,
                &mut rng,
                &initiator,
            ),
            IngestResult::Invalid
        ));
        let pending = transport.get_link(&link_id).unwrap();
        assert_eq!(pending.state, crate::link::LinkState::Handshake);
        assert_eq!(pending.bound_interface(), None);
        assert_eq!(transport.stats().packets_dropped_dedup, 0);

        let (mut invalid, invalid_len) = build_proof(&invalid_payload);
        assert!(matches!(
            transport.ingest_on(
                &mut invalid[..invalid_len],
                now + 1,
                4,
                &mut rng,
                &initiator,
            ),
            IngestResult::Invalid
        ));
        let pending = transport.get_link(&link_id).unwrap();
        assert_eq!(pending.state, crate::link::LinkState::Handshake);
        assert_eq!(pending.bound_interface(), None);

        let (mut valid, valid_len) = build_proof(&proof_payload);
        assert!(matches!(
            transport.ingest_on(
                &mut valid[..valid_len],
                now + 2,
                9,
                &mut rng,
                &initiator,
            ),
            IngestResult::LinkEstablished { .. }
        ));
        let active = transport.get_link(&link_id).unwrap();
        assert!(active.is_active());
        assert_eq!(active.bound_interface(), Some(9));
        assert_eq!(active.expected_hops(), Some(1));
        assert_eq!(transport.stats().packets_dropped_dedup, 0);

        assert!(matches!(
            transport.handle_lrproof(
                &link_id,
                &proof_payload,
                rete_core::MonotonicInstant::from_secs(now + 3),
                5,
            ),
            IngestResult::Invalid
        ));
        let unchanged = transport.get_link(&link_id).unwrap();
        assert!(unchanged.is_active());
        assert_eq!(unchanged.bound_interface(), Some(9));
    }

    #[test]
    fn initiator_without_path_accepts_lrproof_at_unknown_height() {
        let now = 250;
        let mut transport = TestTransport::new();
        let initiator = Identity::from_seed(b"proof-unknown-initiator").unwrap();
        let responder = Identity::from_seed(b"proof-unknown-responder").unwrap();
        let dest_hash =
            rete_core::destination_hash("test.unknown.initiator", Some(&responder.hash()));
        transport.register_identity(dest_hash, responder.public_key(), now);
        transport.remove_path(&dest_hash);
        let mut rng = rand_core::OsRng;

        let (request, link_id) = transport
            .initiate_link(dest_hash, &initiator, &mut rng, now)
            .unwrap();
        assert_eq!(
            transport.get_link(&link_id).unwrap().expected_hops(),
            Some(PATHFINDER_M)
        );

        let request_payload = Packet::parse(&request).unwrap().payload;
        let responder_link =
            Link::from_request(link_id, request_payload, &mut rng, now).unwrap();
        let proof_payload = responder_link.build_proof(&responder).unwrap();
        let mut proof = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .hops(6)
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
            .unwrap();

        assert!(matches!(
            transport.ingest_on(
                &mut proof[..proof_len],
                now + 1,
                5,
                &mut rng,
                &initiator,
            ),
            IngestResult::LinkEstablished { .. }
        ));
        let active = transport.get_link(&link_id).unwrap();
        assert!(active.is_active());
        assert_eq!(active.expected_hops(), Some(PATHFINDER_M));
    }

    #[test]
    fn owned_link_data_wrong_interface_does_not_poison_correct_copy() {
        let now = 300;
        let (mut transport, link_id, initiator) = make_transport_with_active_link(now);
        let mut rng = rand_core::OsRng;
        let mut data = transport
            .build_link_data_packet(&link_id, b"authoritative interface", 0, &mut rng)
            .unwrap();
        let last_inbound = transport.get_link(&link_id).unwrap().last_inbound;

        assert!(matches!(
            transport.ingest_on(&mut data, now + 1, 7, &mut rng, &initiator),
            IngestResult::Invalid
        ));
        assert_eq!(
            transport.get_link(&link_id).unwrap().last_inbound,
            last_inbound
        );
        assert_eq!(transport.stats().packets_dropped_dedup, 0);

        assert!(matches!(
            transport.ingest_on(&mut data, now + 2, 0, &mut rng, &initiator),
            IngestResult::LinkData { data, .. } if data == b"authoritative interface"
        ));
        assert_eq!(transport.stats().packets_dropped_dedup, 0);
    }

    #[test]
    fn resource_proof_wrong_interface_does_not_poison_correct_copy() {
        let now = 400;
        let (mut transport, link_id, initiator) = make_transport_with_active_link(now);
        let mut rng = rand_core::OsRng;
        transport
            .start_resource(
                &link_id,
                b"resource proof route",
                b"resource proof route",
                false,
                &mut rng,
            )
            .unwrap();
        let resource = transport.resources.first().unwrap();
        let resource_hash = resource.resource_hash;
        let proof_payload = resource.build_proof();
        let mut proof = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(rete_core::CONTEXT_RESOURCE_PRF)
            .payload(&proof_payload)
            .build()
            .unwrap();

        assert!(matches!(
            transport.ingest_on(
                &mut proof[..proof_len],
                now + 1,
                8,
                &mut rng,
                &initiator,
            ),
            IngestResult::Invalid
        ));
        assert_eq!(transport.stats().packets_dropped_dedup, 0);

        assert!(matches!(
            transport.ingest_on(
                &mut proof[..proof_len],
                now + 2,
                0,
                &mut rng,
                &initiator,
            ),
            IngestResult::ResourceComplete {
                resource_hash: observed,
                ..
            } if observed == resource_hash[..TRUNCATED_HASH_LEN]
        ));
        assert_eq!(transport.stats().packets_dropped_dedup, 0);
    }

    #[test]
    fn test_tick_expires_stale_link() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        assert_eq!(transport.link_count(), 1);

        let stale_time = transport.get_link(&link_id).unwrap().stale_time;
        let active_at = rete_core::MonotonicInstant::from_secs(now);
        let stale_at = active_at + stale_time;
        let grace = transport.get_link(&link_id).unwrap().stale_grace();

        // At stale_time the link enters Stale but remains retained for revival.
        let result = transport.tick_at(stale_at.as_secs(), stale_at);
        assert_eq!(result.closed_links, 0);
        assert_eq!(transport.link_count(), 1);
        assert_eq!(
            transport.get_link(&link_id).unwrap().state,
            crate::link::LinkState::Stale
        );

        let before_close = stale_at + grace - rete_core::MonotonicDuration::from_micros(1);
        let result = transport.tick_at(before_close.as_secs(), before_close);
        assert_eq!(result.closed_links, 0);
        assert_eq!(transport.link_count(), 1);

        // Python RNS 1.3.8's watchdog gives the final probe five seconds.
        let close_at = stale_at + grace;
        let result = transport.tick_at(close_at.as_secs(), close_at);
        assert_eq!(result.closed_links, 1);
        assert_eq!(transport.link_count(), 0);
    }

    #[test]
    fn test_late_tick_retains_stale_link_for_full_transition_grace() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        let stale_time = transport.get_link(&link_id).unwrap().stale_time;
        let transition_at = rete_core::MonotonicInstant::from_secs(now)
            + stale_time
            + rete_core::MonotonicDuration::from_secs(100);

        // Even though the nominal stale deadline is long past, this first
        // watchdog observation starts (rather than consumes) the grace window.
        let result = transport.tick_at(transition_at.as_secs(), transition_at);
        assert_eq!(result.closed_links, 0);
        assert_eq!(transport.link_count(), 1);
        assert_eq!(
            transport.get_link(&link_id).unwrap().state,
            crate::link::LinkState::Stale
        );

        let grace = transport.get_link(&link_id).unwrap().stale_grace();
        let before_close = transition_at + grace - rete_core::MonotonicDuration::from_micros(1);
        let result = transport.tick_at(before_close.as_secs(), before_close);
        assert_eq!(result.closed_links, 0);
        assert_eq!(transport.link_count(), 1);

        let close_at = transition_at + grace;
        let result = transport.tick_at(close_at.as_secs(), close_at);
        assert_eq!(result.closed_links, 1);
        assert_eq!(transport.link_count(), 0);
    }

    #[test]
    fn test_keepalive_updates_last_outbound() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        let mut rng = rand_core::OsRng;

        let keepalive_interval = transport.get_link(&link_id).unwrap().keepalive_interval;
        let active_at = rete_core::MonotonicInstant::from_secs(now);

        // A full interval of inbound silence is required.
        assert!(transport
            .build_pending_keepalives_at(
                active_at + keepalive_interval - rete_core::MonotonicDuration::from_micros(1),
                &mut rng,
            )
            .is_empty());
        let ka_time = active_at + keepalive_interval;
        let packets = transport.build_pending_keepalives_at(ka_time, &mut rng);
        assert!(
            !packets.is_empty(),
            "should produce at least one keepalive packet"
        );

        // Verify last_outbound was updated
        let link = transport.get_link(&link_id).unwrap();
        assert_eq!(
            link.last_outbound, ka_time,
            "last_outbound should be updated to keepalive time"
        );
        assert_eq!(link.last_keepalive, ka_time);
    }

    #[test]
    fn python_1_3_8_keepalive_wire_vectors_are_exact() {
        use sha2::{Digest, Sha256};

        let link_id = LinkId::from([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        let identity = Identity::from_seed(b"python-keepalive-vector").unwrap();
        let destination = DestHash::from([0xAA; TRUNCATED_HASH_LEN]);
        let mut rng = rand_core::OsRng;
        let (mut link, _) =
            Link::new_initiator(destination, identity.ed25519_pub(), &mut rng, 0);
        link.set_link_id(link_id);
        link.activate(0);
        link.bound_interface = Some(0);
        let mut transport = TestTransport::new();
        assert!(transport.links.insert(link_id, link).is_ok());

        let request_raw = transport
            .build_keepalive_packet(&link_id, true, 100)
            .expect("should build keepalive request");
        assert_eq!(
            transport.build_keepalive_packet(&link_id, false, 100),
            Err(SendError::KeepaliveRoleMismatch)
        );
        transport.get_link_mut(&link_id).unwrap().role = crate::link::LinkRole::Responder;
        let response_raw = transport
            .build_keepalive_packet(&link_id, false, 101)
            .expect("should build keepalive response");
        assert_eq!(
            transport.build_keepalive_packet(&link_id, true, 101),
            Err(SendError::KeepaliveRoleMismatch)
        );

        assert_eq!(
            hex::encode(&request_raw),
            "0c00000102030405060708090a0b0c0d0e0ffaff"
        );
        assert_eq!(
            hex::encode(&response_raw),
            "0c00000102030405060708090a0b0c0d0e0ffafe"
        );
        assert_eq!(request_raw.len(), 20);
        assert_eq!(response_raw.len(), 20);

        let req_pkt = Packet::parse(&request_raw).expect("should parse request");
        assert_eq!(req_pkt.dest_type, DestType::Link);
        assert_eq!(req_pkt.context, CONTEXT_KEEPALIVE);
        assert_eq!(req_pkt.destination_hash, link_id.as_ref());
        assert_eq!(req_pkt.payload, &[0xFF]);

        let resp_pkt = Packet::parse(&response_raw).expect("should parse response");
        assert_eq!(resp_pkt.dest_type, DestType::Link);
        assert_eq!(resp_pkt.context, CONTEXT_KEEPALIVE);
        assert_eq!(resp_pkt.destination_hash, link_id.as_ref());
        assert_eq!(resp_pkt.payload, &[0xFE]);

        // These are RNS packet hashes, not SHA-256(raw). Packet hashing masks
        // header/transport bits and omits the hop byte.
        assert_eq!(
            hex::encode(req_pkt.compute_hash()),
            "3d973d3383729c255f74ee75aca2ae85af9247a25a46f9a3c066b1fd4a1c8437"
        );
        assert_eq!(
            hex::encode(resp_pkt.compute_hash()),
            "fe935be6791ba9fd2a49692d20f587c98719feff40ec27832719d61f749634ba"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&request_raw)),
            "e3a8d6f805de1e27e26af23e34bf18a47dc986d43185ad59ecbbbb0b1f6a38fb"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&response_raw)),
            "8b3618e403c7868f0548dbb5d86b004e29b3ce378f1bc04492265baca91344bd"
        );
    }

    #[test]
    fn test_transport_stats_announce_ingest() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);

        // Sender identity — builds the announce
        let sender = Identity::from_seed(b"stats-test-sender").unwrap();

        // Build a raw announce packet
        let mut announce_buf = [0u8; rete_core::MTU];
        let announce_len = TestTransport::create_announce(
            &sender,
            "test",
            &["stats"],
            None,
            None,
            &mut rng,
            1000,
            &mut announce_buf,
        )
        .expect("should build announce");

        // Receiver transport — receives the announce
        let receiver_identity = Identity::from_seed(b"stats-test-receiver").unwrap();
        let mut transport = TestTransport::new();

        // Before any ingest, all stats should be zero
        assert_eq!(transport.stats().packets_received, 0);
        assert_eq!(transport.stats().announces_received, 0);
        assert_eq!(transport.stats().paths_learned, 0);
        assert_eq!(transport.stats().packets_dropped_dedup, 0);
        assert_eq!(transport.stats().packets_dropped_invalid, 0);

        // Ingest the announce
        let result = transport.ingest(
            &mut announce_buf[..announce_len],
            1000,
            &mut rng,
            &receiver_identity,
        );
        assert!(
            matches!(result, IngestResult::AnnounceReceived { .. }),
            "expected AnnounceReceived, got {:?}",
            result,
        );

        // Verify counters were incremented
        assert_eq!(transport.stats().packets_received, 1, "packets_received");
        assert_eq!(
            transport.stats().announces_received,
            1,
            "announces_received"
        );
        assert_eq!(transport.stats().paths_learned, 1, "paths_learned");
        assert_eq!(transport.stats().packets_dropped_dedup, 0, "no dedup yet");
        assert_eq!(transport.stats().packets_dropped_invalid, 0, "no invalid");
        assert_eq!(transport.stats().started_at, 1000, "started_at");

        // Rebuild the same announce (same raw bytes) and ingest again — should be dedup
        let mut announce_buf2 = announce_buf;
        let result2 = transport.ingest(
            &mut announce_buf2[..announce_len],
            1001,
            &mut rng,
            &receiver_identity,
        );
        assert!(
            matches!(result2, IngestResult::Duplicate),
            "expected Duplicate on second ingest",
        );

        // Parse succeeds before the dedup check, so packets_received increments; then dedup fires.
        assert_eq!(transport.stats().packets_dropped_dedup, 1, "dedup counter");
        // announces_received should stay at 1 (dedup fires before announce processing)
        assert_eq!(transport.stats().announces_received, 1, "still 1 announce");
    }

    #[test]
    fn test_create_announce_with_ratchet() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(99);
        let sender = Identity::from_seed(b"ratchet-announce-sender").unwrap();
        let ratchet_pub = [0x42u8; 32];

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["ratchet"],
            None,
            Some(&ratchet_pub),
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build ratchet announce");

        // Parse and verify context_flag is set
        let pkt = rete_core::Packet::parse(&buf[..n]).expect("should parse");
        assert!(
            pkt.context_flag,
            "context_flag should be set for ratchet announce"
        );
        assert_eq!(pkt.packet_type, rete_core::PacketType::Announce);

        // Validate the announce and check ratchet is extracted
        let info =
            crate::announce::validate_announce(pkt.destination_hash, pkt.payload, pkt.context_flag)
                .expect("should validate");
        assert!(info.ratchet.is_some(), "ratchet should be present");
        assert_eq!(info.ratchet.unwrap(), &ratchet_pub[..]);
    }

    #[test]
    fn test_announce_without_ratchet_has_none() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(100);
        let sender = Identity::from_seed(b"no-ratchet-sender").unwrap();

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["noratchet"],
            None,
            None,
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build announce");

        let pkt = rete_core::Packet::parse(&buf[..n]).expect("should parse");
        assert!(!pkt.context_flag, "context_flag should NOT be set");

        let info =
            crate::announce::validate_announce(pkt.destination_hash, pkt.payload, pkt.context_flag)
                .expect("should validate");
        assert!(info.ratchet.is_none(), "ratchet should be None");
    }

    #[test]
    fn test_ingest_ratchet_announce_returns_ratchet() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(101);
        let sender = Identity::from_seed(b"ratchet-ingest-sender").unwrap();
        let receiver = Identity::from_seed(b"ratchet-ingest-receiver").unwrap();
        let ratchet_pub = [0xAB; 32];

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["ratchet"],
            None,
            Some(&ratchet_pub),
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build");

        let mut transport = TestTransport::new();
        let result = transport.ingest(&mut buf[..n], 1000, &mut rng, &receiver);

        match result {
            IngestResult::AnnounceReceived { ratchet, .. } => {
                assert_eq!(
                    ratchet,
                    Some(ratchet_pub),
                    "ratchet should be passed through"
                );
            }
            other => panic!("expected AnnounceReceived, got {:?}", other),
        }
    }
}
