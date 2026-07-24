//! Link — encrypted session state machine.
//!
//! A Link provides a bidirectional encrypted channel between two Reticulum
//! identities. The handshake uses ephemeral X25519 keys for forward secrecy.
//!
//! # Handshake (responder perspective)
//! 1. Receive LINKREQUEST: extract peer's X25519_pub, Ed25519_pub, and signalling[3]
//! 2. Compute link_id from hashable part of the request
//! 3. Generate our ephemeral X25519 keypair
//! 4. ECDH(our_prv, peer_pub) → shared_key
//! 5. HKDF-SHA256(ikm=shared_key, salt=link_id, info=b"", length=64) → derived_key
//! 6. Create Token from derived_key
//! 7. Build LRPROOF: sign(link_id || our_x25519_pub || our_ed25519_pub || signalling) || our_x25519_pub || signalling
//!
//! # Handshake (initiator perspective)
//! 1. Generate ephemeral X25519 keypair
//! 2. Build LINKREQUEST: our_x25519_pub[32] || our_ed25519_pub[32] || signalling[3]
//! 3. Send LINKREQUEST to destination
//! 4. Receive LRPROOF: extract signature[64] || responder_x25519_pub[32] [|| signalling[3]]
//! 5. Verify signature over (link_id || responder_x25519_pub || responder_ed25519_pub [|| signalling])
//! 6. ECDH(our_prv, responder_pub) → shared_key
//! 7. HKDF-SHA256(ikm=shared_key, salt=link_id, info=b"", length=64) → derived_key
//! 8. Create Token from derived_key

use crate::channel::Channel;
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestHash, Identity, IdentityHash, LinkId, MonotonicDuration, MonotonicInstant, Token,
    TRUNCATED_HASH_LEN,
};
use sha2::{Digest, Sha256};
use core::num::NonZeroU64;
use zeroize::Zeroize;

/// Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Waiting for LINKREQUEST to be sent or received.
    Pending,
    /// Handshake in progress (LINKREQUEST received, proof not yet validated).
    Handshake,
    /// Link is active — encrypted data can flow.
    Active,
    /// Link has gone stale (no traffic for stale_time).
    Stale,
    /// Link is closed.
    Closed,
}

/// Whether we initiated or responded to this link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    /// We sent the LINKREQUEST.
    Initiator,
    /// We received the LINKREQUEST and responded.
    Responder,
}

/// Teardown reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    /// Timeout with no traffic.
    Timeout,
    /// Initiator closed the link.
    InitiatorClosed,
    /// Destination closed the link.
    DestinationClosed,
}

/// Default keepalive interval in seconds (6 minutes, matches Python RNS).
pub const KEEPALIVE_INTERVAL_SECS: u64 = 360;
/// Default stale timeout in seconds (2x keepalive = 720s, matches Python RNS).
/// Python: `STALE_FACTOR = 2`, `STALE_TIME = STALE_FACTOR * KEEPALIVE = 2 * 360 = 720`.
pub const STALE_TIMEOUT_SECS: u64 = 720;

/// Maximum RTT that produces the maximum keepalive interval.
/// Python: `Link.KEEPALIVE_TIMEOUT_FACTOR = 4` → `360 / (4/1.75*1) = 1.75` effectively.
/// Formula: `keepalive = rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)`.
pub const KEEPALIVE_MAX_RTT: f32 = 1.75;
/// Maximum keepalive interval in seconds.
pub const KEEPALIVE_MAX: f32 = 360.0;
/// Minimum keepalive interval in seconds.
pub const KEEPALIVE_MIN: f32 = 5.0;
/// Stale timeout multiplier relative to keepalive interval.
pub const STALE_FACTOR: f32 = 2.0;
/// Grace period added to stale detection (seconds). Python: `STALE_GRACE = 5`.
pub const STALE_GRACE: u64 = 5;
/// Minimum traffic timeout in milliseconds. Python: `TRAFFIC_TIMEOUT_MIN_MS = 5`.
pub const TRAFFIC_TIMEOUT_MIN_MS: u64 = 5;
/// Traffic timeout multiplier for receipt timeouts. Python: `TRAFFIC_TIMEOUT_FACTOR = 6`.
pub const TRAFFIC_TIMEOUT_FACTOR: u64 = 6;
/// Keepalive timeout factor. Python: `KEEPALIVE_TIMEOUT_FACTOR = 4`.
pub const KEEPALIVE_TIMEOUT_FACTOR: f32 = 4.0;
/// Establishment timeout per hop (seconds). Python: `DEFAULT_PER_HOP_TIMEOUT = 6`.
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: u64 = 6;

/// An encrypted link session.
pub struct Link {
    /// Unique 16-byte link identifier.
    pub link_id: LinkId,
    /// Current state.
    pub state: LinkState,
    /// Our role in this link.
    pub role: LinkRole,
    /// Symmetric cipher for encrypt/decrypt.
    token: Option<Token>,
    /// Peer's X25519 public key (from LINKREQUEST or LRPROOF).
    pub peer_x25519_pub: [u8; 32],
    /// Peer's Ed25519 public key.
    pub peer_ed25519_pub: [u8; 32],
    /// Our ephemeral X25519 private key.
    our_x25519_prv: [u8; 32],
    /// Our ephemeral X25519 public key.
    pub our_x25519_pub: [u8; 32],
    /// Our Ed25519 public key (sent in LINKREQUEST for initiator).
    #[allow(dead_code)]
    our_ed25519_pub: [u8; 32],
    /// Measured round-trip time (seconds).
    pub rtt: f64,
    /// Last authenticated inbound activity.
    pub last_inbound: MonotonicInstant,
    /// Last outbound timestamp.
    pub last_outbound: MonotonicInstant,
    /// Last outbound keepalive timestamp.
    ///
    /// Keepalives are deterministic on the wire, so this is tracked separately
    /// from ordinary outbound traffic. Python RNS schedules probes from inbound
    /// silence and the previous probe, not from arbitrary outbound data.
    pub last_keepalive: MonotonicInstant,
    /// Immutable start of the Link request/response timing exchange.
    ///
    /// A provisional value is installed during logical packet construction so
    /// legacy callers remain functional. A runtime may replace it exactly once
    /// with a dispatch-edge confirmation before the Link activates.
    request_started_at: MonotonicInstant,
    /// Post-ingress hop count from the LINKREQUEST that created a responder.
    ///
    /// This is distinct from `expected_hops`: the latter is authenticated Link
    /// routing state learned from LRRTT, while this value only fixes the
    /// responder's bounded establishment timeout.
    responder_inbound_hops: Option<u8>,
    request_time_confirmed: bool,
    outbound_protocol_token: Option<NonZeroU64>,
    request_dispatch_interface: Option<u8>,
    /// Timestamp at which the watchdog actually transitioned this Link to Stale.
    ///
    /// The revival grace starts at the transition/final-probe time, not at the
    /// nominal `last_inbound + stale_time` deadline. This matters when watchdog
    /// ticks are delayed.
    stale_since: Option<MonotonicInstant>,
    /// Precise keepalive interval.
    pub keepalive_interval: MonotonicDuration,
    /// Stale timeout = keepalive × 2.
    pub stale_time: MonotonicDuration,
    /// Destination hash this link is associated with.
    pub destination_hash: DestHash,
    /// Hop count retained when the Link was created.
    ///
    /// Initiators snapshot the learned path and use it to admit LRPROOF.
    /// Responders start without a value and learn it from authenticated LRRTT.
    /// Initiators may retain [`crate::transport::PATHFINDER_M`] as the explicit
    /// compatibility wildcard when they were created before a path was known.
    expected_hops: Option<u8>,
    /// Runtime interface selected for this locally owned Link.
    ///
    /// Initiators bind only from validated LRPROOF ingress. Responders bind to
    /// the interface that supplied the LINKREQUEST. A learned path may select
    /// the initial LINKREQUEST egress, but it is not authoritative Link state.
    ///
    /// This is an interface-slot index, not a hosted shared-instance client
    /// identity. A Hub that multiplexes clients behind one slot therefore does
    /// not gain Python's per-client interface isolation from this field.
    pub(crate) bound_interface: Option<u8>,
    /// MTU signalling bytes (3 bytes: MTU + encryption mode).
    /// Included in LINKREQUEST and LRPROOF for protocol completeness.
    pub signalling: [u8; LINK_MTU_SIZE],
    /// Reliable ordered channel (lazy-initialized on first channel message).
    pub(crate) channel: Option<Channel>,
    /// Peer's identified identity, set after LINKIDENTIFY verification.
    identified: Option<IdentifiedPeer>,
}

/// Identity revealed by a remote peer via LINKIDENTIFY.
pub struct IdentifiedPeer {
    pub_key: [u8; 64],
    hash: IdentityHash,
}

impl Link {
    /// Runtime interface bound to this locally owned Link, if established.
    pub const fn bound_interface(&self) -> Option<u8> {
        self.bound_interface
    }

    /// Maximum plaintext size for one encrypted packet on this Link.
    pub fn mdu(&self) -> usize {
        let mtu = decode_mtu(&self.signalling) as usize;
        if mtu == 0 {
            LINK_MDU
        } else {
            compute_link_mdu(mtu)
        }
    }

    /// Hop count expected for this Link.
    ///
    /// A responder returns `None` until authenticated LRRTT establishes its
    /// inbound height. An initiator always returns `Some`, where
    /// [`crate::transport::PATHFINDER_M`] is the Reticulum compatibility
    /// sentinel for an initiator created before a path was known.
    pub const fn expected_hops(&self) -> Option<u8> {
        self.expected_hops
    }

    /// Whether an LRPROOF arrived at the retained path height.
    pub(crate) const fn accepts_lrproof_hops(&self, hops: u8) -> bool {
        matches!(
            self.expected_hops,
            Some(expected) if expected == crate::transport::PATHFINDER_M || expected == hops
        )
    }

    /// Retain the authenticated inbound height learned from LRRTT.
    pub(crate) fn set_expected_hops(&mut self, hops: u8) {
        self.expected_hops = Some(hops);
    }

    /// Create a Link as responder from a received LINKREQUEST.
    ///
    /// Extracts the peer's keys, generates our ephemeral key, performs ECDH+HKDF,
    /// and creates the Token for symmetric encryption.
    ///
    /// # Arguments
    /// - `link_id` — computed from the hashable part of the LINKREQUEST
    /// - `request_payload` — 64 legacy key bytes, optionally followed by exactly
    ///   3 modern signalling bytes
    /// - `rng` — cryptographic RNG
    /// - `now` — current monotonic time
    ///
    /// # Errors
    ///
    /// Returns [`rete_core::Error::PacketTooShort`] for payloads shorter than
    /// 64 bytes, and [`rete_core::Error::InvalidArgument`] for every other
    /// payload length except 64 or 67 bytes.
    pub fn from_request<R: RngCore + CryptoRng>(
        link_id: LinkId,
        request_payload: &[u8],
        rng: &mut R,
        now: u64,
    ) -> Result<Self, rete_core::Error> {
        Self::from_request_at(
            link_id,
            request_payload,
            rng,
            MonotonicInstant::from_secs(now),
        )
    }

    /// Precise-clock variant of [`Self::from_request`].
    pub fn from_request_at<R: RngCore + CryptoRng>(
        link_id: LinkId,
        request_payload: &[u8],
        rng: &mut R,
        now: MonotonicInstant,
    ) -> Result<Self, rete_core::Error> {
        Self::from_request_at_with_hops(link_id, request_payload, rng, now, 0)
    }

    /// Construct a responder Link while retaining its post-ingress hop count.
    pub(crate) fn from_request_at_with_hops<R: RngCore + CryptoRng>(
        link_id: LinkId,
        request_payload: &[u8],
        rng: &mut R,
        now: MonotonicInstant,
        inbound_hops: u8,
    ) -> Result<Self, rete_core::Error> {
        if request_payload.len() < LINK_REQUEST_KEY_SIZE {
            return Err(rete_core::Error::PacketTooShort);
        }
        if !is_valid_link_request_payload_len(request_payload.len()) {
            return Err(rete_core::Error::InvalidArgument(
                "LINKREQUEST payload must be exactly 64 or 67 bytes",
            ));
        }

        let mut peer_x25519_pub = [0u8; 32];
        let mut peer_ed25519_pub = [0u8; 32];
        peer_x25519_pub.copy_from_slice(&request_payload[..32]);
        peer_ed25519_pub.copy_from_slice(&request_payload[32..LINK_REQUEST_KEY_SIZE]);

        // Extract signalling bytes if present (67-byte modern request).
        let mut peer_signalling = [0u8; LINK_MTU_SIZE];
        if request_payload.len() == LINK_REQUEST_KEY_SIZE + LINK_MTU_SIZE {
            peer_signalling.copy_from_slice(
                &request_payload[LINK_REQUEST_KEY_SIZE..LINK_REQUEST_KEY_SIZE + LINK_MTU_SIZE],
            );
        }

        // Generate our ephemeral X25519 keypair
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let our_public = x25519_dalek::PublicKey::from(&our_secret);
        let our_x25519_prv = our_secret.to_bytes();
        let our_x25519_pub = our_public.to_bytes();

        // ECDH
        let peer_pub = x25519_dalek::PublicKey::from(peer_x25519_pub);
        let shared = our_secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256(ikm=shared, salt=link_id, info=b"", length=64)
        let hk = hkdf::Hkdf::<Sha256>::new(Some(link_id.as_ref()), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| rete_core::Error::CryptoError)?;

        let token = Token::new(&derived)?;
        derived.zeroize();

        // Ephemeral private key no longer needed — Token holds the session key.
        let mut zeroed_prv = our_x25519_prv;
        zeroed_prv.zeroize();

        Ok(Link {
            link_id,
            state: LinkState::Handshake,
            role: LinkRole::Responder,
            token: Some(token),
            peer_x25519_pub,
            peer_ed25519_pub,
            our_x25519_prv: zeroed_prv,
            our_x25519_pub,
            our_ed25519_pub: [0u8; 32], // not needed for responder
            rtt: 0.0,
            last_inbound: now,
            last_outbound: now,
            last_keepalive: MonotonicInstant::default(),
            request_started_at: now,
            responder_inbound_hops: Some(inbound_hops),
            request_time_confirmed: false,
            outbound_protocol_token: None,
            request_dispatch_interface: None,
            stale_since: None,
            keepalive_interval: MonotonicDuration::from_secs(KEEPALIVE_INTERVAL_SECS),
            stale_time: MonotonicDuration::from_secs(STALE_TIMEOUT_SECS),
            destination_hash: DestHash::ZERO,
            expected_hops: None,
            bound_interface: None,
            signalling: peer_signalling,
            channel: None,
            identified: None,
        })
    }

    /// Build the LRPROOF payload for the responder.
    ///
    /// Format: `Ed25519_signature[64] || X25519_responder_pub[32] || signalling[3]`
    /// Signature covers: `link_id || responder_x25519_pub || responder_ed25519_pub || signalling`
    ///
    /// The signed data uses the responder's own keys (not the initiator's peer keys).
    /// This matches the Python reference: `Link.prove()` signs
    /// `self.link_id + self.pub_bytes + self.sig_pub_bytes + self.signalling_bytes`.
    ///
    /// Returns a 99-byte proof (64 sig + 32 x25519_pub + 3 signalling).
    /// Python's `validate_proof` handles both 96-byte and 99-byte proofs.
    pub fn build_proof(
        &self,
        owner_identity: &Identity,
    ) -> Result<[u8; 96 + LINK_MTU_SIZE], rete_core::Error> {
        // Build signed data: link_id || our_x25519_pub || owner_ed25519_pub || signalling
        let mut signed_data = [0u8; 80 + LINK_MTU_SIZE]; // 16 + 32 + 32 + 3
        signed_data[..16].copy_from_slice(self.link_id.as_ref());
        signed_data[16..48].copy_from_slice(&self.our_x25519_pub);
        signed_data[48..80].copy_from_slice(owner_identity.ed25519_pub());
        signed_data[80..80 + LINK_MTU_SIZE].copy_from_slice(&self.signalling);

        let signature = owner_identity.sign(&signed_data)?;

        // LRPROOF: signature[64] || our_x25519_pub[32] || signalling[3]
        let mut proof = [0u8; 96 + LINK_MTU_SIZE];
        proof[..64].copy_from_slice(&signature);
        proof[64..96].copy_from_slice(&self.our_x25519_pub);
        proof[96..96 + LINK_MTU_SIZE].copy_from_slice(&self.signalling);
        Ok(proof)
    }

    /// Create a Link as initiator.
    ///
    /// Generates our ephemeral X25519 keypair and returns the LINKREQUEST payload
    /// as a 67-byte array: `x25519_pub[32] || ed25519_pub[32] || signalling[3]`.
    ///
    /// The 3 signalling bytes encode MTU and encryption mode, matching Python's
    /// `Link.LINK_MTU_SIZE` format.
    ///
    /// This low-level constructor has no path table, so it retains
    /// [`crate::transport::PATHFINDER_M`] as the LRPROOF compatibility
    /// wildcard. [`crate::Transport::initiate_link`] snapshots a known path's
    /// exact hop count instead.
    pub fn new_initiator<R: RngCore + CryptoRng>(
        dest_hash: DestHash,
        our_ed25519_pub: &[u8; 32],
        rng: &mut R,
        now: u64,
    ) -> (Self, [u8; 64 + LINK_MTU_SIZE]) {
        Self::new_initiator_with_expected_hops(
            dest_hash,
            our_ed25519_pub,
            crate::transport::PATHFINDER_M,
            rng,
            now,
        )
    }

    /// Precise-clock variant of [`Self::new_initiator`].
    pub fn new_initiator_at<R: RngCore + CryptoRng>(
        dest_hash: DestHash,
        our_ed25519_pub: &[u8; 32],
        rng: &mut R,
        now: MonotonicInstant,
    ) -> (Self, [u8; 64 + LINK_MTU_SIZE]) {
        Self::new_initiator_with_expected_hops_at(
            dest_hash,
            our_ed25519_pub,
            crate::transport::PATHFINDER_M,
            rng,
            now,
        )
    }

    /// Create an initiator while atomically retaining its path height.
    pub(crate) fn new_initiator_with_expected_hops<R: RngCore + CryptoRng>(
        dest_hash: DestHash,
        our_ed25519_pub: &[u8; 32],
        expected_hops: u8,
        rng: &mut R,
        now: u64,
    ) -> (Self, [u8; 64 + LINK_MTU_SIZE]) {
        Self::new_initiator_with_expected_hops_at(
            dest_hash,
            our_ed25519_pub,
            expected_hops,
            rng,
            MonotonicInstant::from_secs(now),
        )
    }

    pub(crate) fn new_initiator_with_expected_hops_at<R: RngCore + CryptoRng>(
        dest_hash: DestHash,
        our_ed25519_pub: &[u8; 32],
        expected_hops: u8,
        rng: &mut R,
        now: MonotonicInstant,
    ) -> (Self, [u8; 64 + LINK_MTU_SIZE]) {
        // Generate ephemeral X25519
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let our_public = x25519_dalek::PublicKey::from(&our_secret);
        let our_x25519_prv = our_secret.to_bytes();
        let our_x25519_pub = our_public.to_bytes();

        // Compute signalling bytes: default MTU + AES-CBC mode
        let sig_bytes = signalling_bytes(rete_core::MTU as u32, MODE_AES_CBC);

        // Build LINKREQUEST payload: x25519_pub[32] || ed25519_pub[32] || signalling[3]
        let mut payload = [0u8; 64 + LINK_MTU_SIZE];
        payload[..32].copy_from_slice(&our_x25519_pub);
        payload[32..64].copy_from_slice(our_ed25519_pub);
        payload[64..64 + LINK_MTU_SIZE].copy_from_slice(&sig_bytes);

        let link = Link {
            link_id: LinkId::ZERO, // will be computed after send
            state: LinkState::Pending,
            role: LinkRole::Initiator,
            token: None,
            peer_x25519_pub: [0u8; 32],
            peer_ed25519_pub: [0u8; 32],
            our_x25519_prv,
            our_x25519_pub,
            our_ed25519_pub: *our_ed25519_pub,
            rtt: 0.0,
            last_inbound: now,
            last_outbound: now,
            last_keepalive: MonotonicInstant::default(),
            request_started_at: now,
            responder_inbound_hops: None,
            request_time_confirmed: false,
            outbound_protocol_token: None,
            request_dispatch_interface: None,
            stale_since: None,
            keepalive_interval: MonotonicDuration::from_secs(KEEPALIVE_INTERVAL_SECS),
            stale_time: MonotonicDuration::from_secs(STALE_TIMEOUT_SECS),
            destination_hash: dest_hash,
            expected_hops: Some(expected_hops),
            bound_interface: None,
            signalling: sig_bytes,
            channel: None,
            identified: None,
        };

        (link, payload)
    }

    /// Set the link_id (called after sending the LINKREQUEST and computing the hash).
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.link_id = link_id;
        self.state = LinkState::Handshake;
    }

    /// Validate the LRPROOF as initiator.
    ///
    /// Proof format: `signature[64] || responder_x25519_pub[32]`
    /// Verifies signature over (link_id || responder_x25519_pub || responder_ed25519_pub),
    /// performs ECDH+HKDF, and creates the Token.
    ///
    /// The signed data uses the responder's own keys. This matches the Python reference:
    /// `Link.validate_proof()` verifies `link_id + peer_pub_bytes + peer_sig_pub_bytes`.
    pub fn validate_proof(
        &mut self,
        proof_payload: &[u8],
        dest_identity: &Identity,
    ) -> Result<(), rete_core::Error> {
        if proof_payload.len() < 96 {
            return Err(rete_core::Error::PacketTooShort);
        }

        let signature = &proof_payload[..64];
        let mut responder_x25519_pub = [0u8; 32];
        responder_x25519_pub.copy_from_slice(&proof_payload[64..96]);
        // Signalling bytes: 0 bytes (no MTU signalling) or 3 bytes (Link.LINK_MTU_SIZE).
        // Reject anything outside this range to prevent buffer overflow.
        let signalling = &proof_payload[96..];
        if signalling.len() > 3 {
            return Err(rete_core::Error::PacketTooShort);
        }

        // Verify signature: responder signed
        // (link_id || responder_x25519_pub || responder_ed25519_pub [|| signalling_bytes])
        // Python includes signalling_bytes in the signed data when present (Link.py:373).
        let mut signed_data = [0u8; 83]; // max: 16+32+32+3
        let signed_len = 80 + signalling.len();
        signed_data[..16].copy_from_slice(self.link_id.as_ref());
        signed_data[16..48].copy_from_slice(&responder_x25519_pub);
        signed_data[48..80].copy_from_slice(dest_identity.ed25519_pub());
        signed_data[80..signed_len].copy_from_slice(signalling);

        dest_identity.verify(&signed_data[..signed_len], signature)?;

        // ECDH with responder's X25519 pub
        let our_secret = x25519_dalek::StaticSecret::from(self.our_x25519_prv);
        let peer_pub = x25519_dalek::PublicKey::from(responder_x25519_pub);
        let shared = our_secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256(ikm=shared, salt=link_id, info=b"", length=64)
        let hk = hkdf::Hkdf::<Sha256>::new(Some(self.link_id.as_ref()), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| rete_core::Error::CryptoError)?;

        self.token = Some(Token::new(&derived)?);
        derived.zeroize();
        self.our_x25519_prv.zeroize(); // no longer needed
        self.peer_x25519_pub = responder_x25519_pub;
        self.peer_ed25519_pub
            .copy_from_slice(dest_identity.ed25519_pub());
        self.state = LinkState::Handshake; // will become Active after RTT

        Ok(())
    }

    /// Encrypt plaintext using the link's Token.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        self.token
            .as_ref()
            .ok_or(rete_core::Error::CryptoError)?
            .encrypt(plaintext, rng, out)
    }

    /// Decrypt ciphertext using the link's Token.
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, rete_core::Error> {
        self.token
            .as_ref()
            .ok_or(rete_core::Error::CryptoError)?
            .decrypt(ciphertext, out)
    }

    /// Update keepalive and stale timers based on measured RTT.
    ///
    /// Matches Python `Link.__update_keepalive()`:
    /// ```python
    /// self.keepalive = max(min(rtt * (360/1.75), 360), 5)
    /// self.stale_time = self.keepalive * 2
    /// ```
    pub fn update_keepalive(&mut self, rtt: f64) {
        self.rtt = rtt;
        let ka = (rtt * (KEEPALIVE_MAX as f64 / KEEPALIVE_MAX_RTT as f64))
            .clamp(KEEPALIVE_MIN as f64, KEEPALIVE_MAX as f64);
        self.keepalive_interval = MonotonicDuration::from_seconds_f64(ka);
        self.stale_time = self
            .keepalive_interval
            .saturating_mul(STALE_FACTOR as u64);
    }

    /// Immutable request timing origin, provisional or confirmed.
    pub const fn request_started_at(&self) -> MonotonicInstant {
        self.request_started_at
    }

    /// Python-compatible responder establishment budget.
    ///
    /// Reticulum keeps a responder Link in Handshake for one keepalive period
    /// plus six seconds per inbound hop, with a minimum of one hop.
    fn responder_establishment_timeout(&self) -> Option<MonotonicDuration> {
        self.responder_inbound_hops.map(|hops| {
            MonotonicDuration::from_secs(
                KEEPALIVE_INTERVAL_SECS.saturating_add(compute_establishment_timeout(u64::from(
                    hops.max(1),
                ))),
            )
        })
    }

    /// Whether a runtime dispatch edge replaced the provisional request time.
    pub const fn request_time_confirmed(&self) -> bool {
        self.request_time_confirmed
    }

    /// Elapsed request exchange time at `now` using the immutable origin.
    pub fn request_elapsed_seconds(&self, now: MonotonicInstant) -> f64 {
        now.saturating_duration_since(self.request_started_at)
            .as_seconds_f64()
    }

    /// Confirm the request timing origin exactly once before activation.
    pub(crate) fn assign_outbound_protocol_token(&mut self, token: NonZeroU64) -> bool {
        if self.outbound_protocol_token.is_some()
            || matches!(self.state, LinkState::Active | LinkState::Stale | LinkState::Closed)
        {
            return false;
        }
        self.outbound_protocol_token = Some(token);
        true
    }

    pub(crate) const fn outbound_protocol_token(&self) -> Option<NonZeroU64> {
        self.outbound_protocol_token
    }

    pub(crate) fn confirm_request_started_at(
        &mut self,
        token: NonZeroU64,
        interface: u8,
        at: MonotonicInstant,
    ) -> bool {
        if self.request_time_confirmed
            || self.outbound_protocol_token != Some(token)
            || matches!(self.state, LinkState::Active | LinkState::Stale | LinkState::Closed)
        {
            return false;
        }
        if self.role == LinkRole::Responder && self.bound_interface != Some(interface) {
            return false;
        }
        self.request_started_at = at;
        self.request_time_confirmed = true;
        self.request_dispatch_interface = Some(interface);
        self.outbound_protocol_token = None;
        true
    }

    /// Interface whose first successful dispatch edge confirmed request timing.
    pub const fn request_dispatch_interface(&self) -> Option<u8> {
        self.request_dispatch_interface
    }

    /// Precise keepalive interval retained for Link scheduling.
    pub fn keepalive_interval_seconds(&self) -> f64 {
        self.keepalive_interval.as_seconds_f64()
    }

    /// Precise stale interval retained for Link scheduling.
    pub fn stale_time_seconds(&self) -> f64 {
        self.stale_time.as_seconds_f64()
    }

    /// Revival grace after an Active Link first transitions to Stale.
    pub fn stale_grace(&self) -> MonotonicDuration {
        MonotonicDuration::from_seconds_f64(
            self.rtt * KEEPALIVE_TIMEOUT_FACTOR as f64 + STALE_GRACE as f64,
        )
    }

    /// Activate the link (after RTT measurement completes).
    pub fn activate(&mut self, now: u64) {
        self.activate_at(MonotonicInstant::from_secs(now));
    }

    /// Activate the link using a precise monotonic timestamp.
    pub fn activate_at(&mut self, now: MonotonicInstant) {
        self.state = LinkState::Active;
        self.last_inbound = now;
        self.stale_since = None;
    }

    /// Mark the link as closed.
    pub fn close(&mut self) {
        self.state = LinkState::Closed;
        self.stale_since = None;
    }

    /// Check if the link is active.
    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    /// Whether authenticated inbound Link traffic may revive this session.
    pub(crate) fn accepts_inbound(&self) -> bool {
        self.state == LinkState::Active || self.state == LinkState::Stale
    }

    /// Access the channel (if initialized).
    pub fn channel(&self) -> Option<&Channel> {
        self.channel.as_ref()
    }

    /// Record the peer's identified identity after LINKIDENTIFY verification.
    /// Derives the identity hash internally from the public key.
    pub fn set_identified(&mut self, pub_key: [u8; 64]) {
        let digest = Sha256::digest(&pub_key);
        let mut hash = [0u8; TRUNCATED_HASH_LEN];
        hash.copy_from_slice(&digest[..TRUNCATED_HASH_LEN]);
        self.identified = Some(IdentifiedPeer { pub_key, hash: IdentityHash::from(hash) });
    }

    /// Identity hash of the peer, if they have sent LINKIDENTIFY.
    pub fn identified_identity_hash(&self) -> Option<&IdentityHash> {
        self.identified.as_ref().map(|p| &p.hash)
    }

    /// Full public key of the peer, if they have sent LINKIDENTIFY.
    pub fn identified_public_key(&self) -> Option<&[u8; 64]> {
        self.identified.as_ref().map(|p| &p.pub_key)
    }

    /// Update last inbound timestamp.
    pub fn touch_inbound(&mut self, now: u64) {
        self.touch_inbound_at(MonotonicInstant::from_secs(now));
    }

    /// Update inbound liveness using a precise monotonic timestamp.
    pub fn touch_inbound_at(&mut self, now: MonotonicInstant) {
        self.last_inbound = now;
        if self.state == LinkState::Stale {
            self.state = LinkState::Active;
        }
        self.stale_since = None;
    }

    /// Classify a conforming inbound keepalive without mutating Link state.
    ///
    /// Python RNS initiators send the exact one-byte request `0xFF`; responders
    /// send the exact one-byte response `0xFE`. Reversing those roles or adding
    /// any bytes is invalid. `Some(true)` means a response must be emitted,
    /// `Some(false)` means a response was consumed, and `None` means invalid.
    pub(crate) fn classify_keepalive(&self, payload: &[u8]) -> Option<bool> {
        if !self.accepts_inbound() {
            return None;
        }

        match (self.role, payload) {
            (LinkRole::Responder, [0xFF]) => Some(true),
            (LinkRole::Initiator, [0xFE]) => Some(false),
            _ => None,
        }
    }

    /// Process a conforming inbound keepalive with role-aware outcome.
    ///
    /// Valid keepalives count as inbound Link activity and revive a stale Link.
    /// Invalid or wrong-role values do not mutate any liveness state.
    pub(crate) fn consume_keepalive(&mut self, payload: &[u8], now: u64) -> Option<bool> {
        self.consume_keepalive_at(payload, MonotonicInstant::from_secs(now))
    }

    pub(crate) fn consume_keepalive_at(
        &mut self,
        payload: &[u8],
        now: MonotonicInstant,
    ) -> Option<bool> {
        let reply = self.classify_keepalive(payload)?;
        self.touch_inbound_at(now);
        Some(reply)
    }

    /// Process an inbound keepalive and return the legacy response byte shape.
    ///
    /// This preserves the public Link API while applying strict role and exact
    /// payload validation. A valid initiator-side `0xFE` response is consumed
    /// and returns `None`, as did the previous API; transport dispatch uses the
    /// role-aware internal result above to distinguish it from rejection.
    pub fn handle_keepalive(&mut self, payload: &[u8], now: u64) -> Option<u8> {
        self.consume_keepalive(payload, now)?.then_some(0xFE)
    }

    /// Record a keepalive after its raw packet has been built successfully.
    pub(crate) fn note_keepalive_outbound_at(&mut self, now: MonotonicInstant) {
        self.last_outbound = now;
        self.last_keepalive = now;
    }

    /// Record ordinary outbound Link traffic without altering request timing.
    pub(crate) fn note_outbound_at(&mut self, now: MonotonicInstant) {
        self.last_outbound = now;
    }

    /// Whole-second compatibility wrapper for [`Self::note_outbound_at`].
    pub(crate) fn note_outbound(&mut self, now: u64) {
        self.note_outbound_at(MonotonicInstant::from_secs(now));
    }

    /// Process a LINKCLOSE payload. Returns true if the link should be closed.
    ///
    /// The payload should be the encrypted link_id (16 bytes after decryption).
    pub fn handle_close(&mut self, decrypted_payload: &[u8]) -> bool {
        if decrypted_payload.len() >= TRUNCATED_HASH_LEN
            && decrypted_payload[..TRUNCATED_HASH_LEN] == *self.link_id.as_bytes()
        {
            self.close();
            true
        } else {
            false
        }
    }

    /// Build LINKCLOSE payload (encrypt link_id).
    pub fn build_close<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        self.encrypt(self.link_id.as_ref(), rng, out)
    }

    /// Whether a keepalive should be sent proactively.
    ///
    /// Only an active initiator sends probes. A probe is due after one complete
    /// keepalive interval without inbound traffic, and no more often than one
    /// complete interval since the previous probe. Ordinary outbound traffic
    /// deliberately does not postpone the probe.
    pub fn needs_keepalive(&self, now: u64) -> bool {
        self.needs_keepalive_at(MonotonicInstant::from_secs(now))
    }

    /// Precise-clock variant of [`Self::needs_keepalive`].
    pub fn needs_keepalive_at(&self, now: MonotonicInstant) -> bool {
        self.state == LinkState::Active
            && self.role == LinkRole::Initiator
            && now.saturating_duration_since(self.last_inbound) >= self.keepalive_interval
            && now.saturating_duration_since(self.last_keepalive) >= self.keepalive_interval
    }

    /// Check for staleness. Returns true if the link should be closed.
    pub fn check_stale(&mut self, now: u64) -> bool {
        self.check_stale_at(MonotonicInstant::from_secs(now))
    }

    /// Precise-clock variant of [`Self::check_stale`].
    pub fn check_stale_at(&mut self, now: MonotonicInstant) -> bool {
        let silence = now.saturating_duration_since(self.last_inbound);
        if self.state == LinkState::Active && silence >= self.stale_time {
            self.state = LinkState::Stale;
            self.stale_since = Some(now);
            return false;
        }
        if self.state == LinkState::Stale {
            let Some(stale_since) = self.stale_since else {
                self.stale_since = Some(now);
                return false;
            };
            let grace = self.stale_grace();
            if now.saturating_duration_since(stale_since) >= grace {
                self.state = LinkState::Closed;
                self.stale_since = None;
                return true;
            }
        }
        false
    }

    /// Close a responder that never completed its LRRTT handshake.
    ///
    /// No LINKCLOSE is emitted for this maintenance timeout, matching Python
    /// Reticulum. The transport removes the closed Link from owned capacity.
    pub(crate) fn check_responder_establishment_timeout_at(
        &mut self,
        now: MonotonicInstant,
    ) -> bool {
        if self.role != LinkRole::Responder || self.state != LinkState::Handshake {
            return false;
        }
        let Some(timeout) = self.responder_establishment_timeout() else {
            return false;
        };
        if now.saturating_duration_since(self.request_started_at) < timeout {
            return false;
        }
        self.state = LinkState::Closed;
        self.stale_since = None;
        true
    }
}

/// Maximum data unit for link-encrypted payloads.
///
/// Computed as: `floor((MTU - 1 - HEADER_1_OVERHEAD - TOKEN_OVERHEAD) / 16) * 16 - 1`
/// where TOKEN_OVERHEAD = 48 (32-byte FERNET token header + 16-byte IV).
/// This gives 431 bytes — the largest plaintext that fits in one link packet.
pub const LINK_MDU: usize = 431;

/// Compute link MDU from a given MTU.
///
/// Python: `math.floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / 16) * 16 - 1`
/// where IFAC_MIN_SIZE=1, HEADER_MINSIZE=19, TOKEN_OVERHEAD=48 → overhead=68.
/// For radio (500) = 431; for TCP (8192) = 8111.
pub fn compute_link_mdu(mtu: usize) -> usize {
    const OVERHEAD: usize = 68; // IFAC_MIN_SIZE(1) + HEADER_MINSIZE(19) + TOKEN_OVERHEAD(48)
    if mtu <= OVERHEAD {
        return 0;
    }
    ((mtu - OVERHEAD) / 16) * 16 - 1
}

/// Compute resource SDU from a given MTU.
///
/// Python: `mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` (35 + 1 = 36).
/// For radio (500) = 464; for TCP (8192) = 8156.
pub fn compute_resource_sdu(mtu: usize) -> usize {
    const OVERHEAD: usize = 36; // HEADER_MAXSIZE(35) + IFAC_MIN_SIZE(1)
    if mtu <= OVERHEAD {
        return 0;
    }
    mtu - OVERHEAD
}

/// Compute keepalive interval and stale time from RTT.
///
/// Returns `(keepalive_interval_s, stale_time_s)` as floats.
/// Python: `max(KEEPALIVE_MIN, min(KEEPALIVE_MAX, rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)))`
/// and `stale_time = keepalive * STALE_FACTOR`. The watchdog's revival grace
/// is separate from `stale_time`.
pub fn compute_keepalive(rtt: f32) -> (f32, f32) {
    let keepalive = if rtt <= 0.0 {
        KEEPALIVE_MIN
    } else {
        let ka = rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT);
        ka.clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
    };
    let stale = keepalive * STALE_FACTOR;
    (keepalive, stale)
}

/// Compute traffic timeout in milliseconds from RTT.
///
/// Python: `max(TRAFFIC_TIMEOUT_MIN_MS, rtt_ms * TRAFFIC_TIMEOUT_FACTOR)`
pub fn compute_traffic_timeout_ms(rtt: f32) -> f32 {
    let rtt_ms = rtt * 1000.0;
    let timeout = rtt_ms * TRAFFIC_TIMEOUT_FACTOR as f32;
    if timeout < TRAFFIC_TIMEOUT_MIN_MS as f32 {
        TRAFFIC_TIMEOUT_MIN_MS as f32
    } else {
        timeout
    }
}

/// Compute establishment timeout from hop count.
///
/// Python: `hops * ESTABLISHMENT_TIMEOUT_PER_HOP`
pub fn compute_establishment_timeout(hops: u64) -> u64 {
    hops * ESTABLISHMENT_TIMEOUT_PER_HOP
}

/// Size of MTU signalling bytes appended to LINKREQUEST and LRPROOF.
/// Python: `Link.LINK_MTU_SIZE = 3`.
pub const LINK_MTU_SIZE: usize = 3;

const LINK_REQUEST_KEY_SIZE: usize = 64;

pub(crate) const fn is_valid_link_request_payload_len(length: usize) -> bool {
    length == LINK_REQUEST_KEY_SIZE || length == LINK_REQUEST_KEY_SIZE + LINK_MTU_SIZE
}

/// Encryption mode: AES-256-CBC (Python: `Link.ENCRYPT_AES = 0x01`).
const MODE_AES_CBC: u8 = 0x01;

/// Encode MTU and encryption mode into 3 signalling bytes.
///
/// Matches Python's encoding:
/// ```python
/// struct.pack("!I", (mtu & 0x1FFFFF) | ((mode & 0x07) << 21))[1:]
/// ```
/// This packs a 32-bit big-endian integer with MTU in bits 0..20 and mode in
/// bits 21..23, then drops the leading byte to produce 3 bytes.
pub fn signalling_bytes(mtu: u32, mode: u8) -> [u8; LINK_MTU_SIZE] {
    let packed = (mtu & 0x1F_FFFF) | ((mode as u32 & 0x07) << 21);
    let be = packed.to_be_bytes(); // [0] is MSB, we drop it
    [be[1], be[2], be[3]]
}

/// Decode MTU from 3 signalling bytes.
///
/// Inverse of `signalling_bytes`: extracts the 21-bit MTU field.
pub fn decode_mtu(sig: &[u8; LINK_MTU_SIZE]) -> u32 {
    let packed = u32::from_be_bytes([0, sig[0], sig[1], sig[2]]);
    packed & 0x1F_FFFF
}

/// Compute the link_id from a LINKREQUEST packet's raw bytes.
///
/// ```text
/// hashable_part = (flags & 0x0F) || raw[2:]   (HEADER_1)
/// If payload > 64 bytes (MTU signalling), strip extra bytes from hashable_part.
/// link_id = SHA-256(hashable_part)[0:16]
/// ```
///
/// # Errors
/// Returns an error if the raw bytes cannot be parsed as a valid packet.
pub fn compute_link_id(raw: &[u8]) -> Result<LinkId, rete_core::Error> {
    let pkt = rete_core::Packet::parse(raw)?;
    let mut hashable_buf = [0u8; rete_core::MTU];
    let hashable_len = pkt.write_hashable_part(&mut hashable_buf)?;

    // Strip MTU signalling bytes (if payload > 64 bytes)
    let signalling_len = if pkt.payload.len() > 64 {
        pkt.payload.len() - 64
    } else {
        0
    };
    let effective_len = hashable_len - signalling_len;

    let digest = Sha256::digest(&hashable_buf[..effective_len]);
    let mut link_id = [0u8; TRUNCATED_HASH_LEN];
    link_id.copy_from_slice(&digest[..TRUNCATED_HASH_LEN]);
    Ok(LinkId::from(link_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::{DestType, PacketBuilder, PacketType, MTU};

    #[test]
    fn link_id_computation() {
        // Build a LINKREQUEST
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..].copy_from_slice(&ed25519_pub);

        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&payload)
            .build()
            .unwrap();

        let link_id = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id.as_ref().len(), 16);

        // Same input → same link_id
        let link_id2 = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id, link_id2);
    }

    #[test]
    fn link_from_request_state() {
        let mut rng = rand_core::OsRng;
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..].copy_from_slice(&ed25519_pub);

        let link_id = LinkId::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        assert_eq!(link.state, LinkState::Handshake);
        assert_eq!(link.role, LinkRole::Responder);
        assert_eq!(link.expected_hops(), None);
        assert_eq!(link.peer_x25519_pub, x25519_pub);
        assert_eq!(link.peer_ed25519_pub, ed25519_pub);
    }

    #[test]
    fn link_from_request_requires_canonical_payload_length() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"canonical-request-length").unwrap();
        let dest_hash = DestHash::from([0xBBu8; TRUNCATED_HASH_LEN]);
        let (_, request_payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);
        let link_id = LinkId::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut extended_payload = request_payload.to_vec();
        extended_payload.resize(100, 0);

        for length in [64, 67] {
            assert!(Link::from_request(link_id, &request_payload[..length], &mut rng, 100).is_ok());
        }

        for length in [0, 63] {
            let error = Link::from_request(link_id, &extended_payload[..length], &mut rng, 100)
                .err()
                .expect("short LINKREQUEST payload must be rejected");
            assert_eq!(error, rete_core::Error::PacketTooShort);
        }

        for length in [65, 66, 68, 100] {
            let error = Link::from_request(link_id, &extended_payload[..length], &mut rng, 100)
                .err()
                .expect("non-canonical LINKREQUEST payload must be rejected");
            assert_eq!(
                error,
                rete_core::Error::InvalidArgument(
                    "LINKREQUEST payload must be exactly 64 or 67 bytes"
                )
            );
        }
    }

    #[test]
    fn link_handshake_derives_key() {
        // Simulate both sides of the handshake with known keys
        let mut rng = rand_core::OsRng;

        // Initiator generates ephemeral key
        let initiator_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let initiator_pub = x25519_dalek::PublicKey::from(&initiator_secret);

        let ed25519_pub = [0xCCu8; 32]; // dummy ed25519 pub
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(initiator_pub.as_bytes());
        payload[32..].copy_from_slice(&ed25519_pub);

        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);

        // Responder creates link
        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        // Initiator derives same key
        let shared =
            initiator_secret.diffie_hellman(&x25519_dalek::PublicKey::from(link.our_x25519_pub));
        let hk = hkdf::Hkdf::<Sha256>::new(Some(link_id.as_ref()), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived).unwrap();
        let initiator_token = Token::new(&derived).unwrap();

        // Both should encrypt/decrypt symmetrically
        let mut ct = [0u8; 256];
        let ct_len = link
            .encrypt(b"hello from responder", &mut rng, &mut ct)
            .unwrap();

        let mut pt = [0u8; 256];
        let pt_len = initiator_token.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"hello from responder");

        // And the other direction
        let ct_len2 = initiator_token
            .encrypt(b"hello from initiator", &mut rng, &mut ct)
            .unwrap();
        let pt_len2 = link.decrypt(&ct[..ct_len2], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len2], b"hello from initiator");
    }

    #[test]
    fn link_build_proof_signature_valid() {
        let mut rng = rand_core::OsRng;
        let owner = Identity::from_seed(b"link-responder-identity").unwrap();

        // 67-byte payload: x25519[32] || ed25519[32] || signalling[3]
        let identity = Identity::from_seed(b"peer-for-proof-test").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let (_peer_link, request_payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        let proof = link.build_proof(&owner).unwrap();
        assert_eq!(proof.len(), 99); // sig[64] + x25519_pub[32] + signalling[3]

        // Verify the signature: covers link_id || x25519_pub || ed25519_pub || signalling
        let sig = &proof[..64];
        let responder_x25519_pub = &proof[64..96];
        let signalling = &proof[96..99];
        let mut signed_data = [0u8; 83];
        signed_data[..16].copy_from_slice(link_id.as_ref());
        signed_data[16..48].copy_from_slice(responder_x25519_pub);
        signed_data[48..80].copy_from_slice(owner.ed25519_pub());
        signed_data[80..83].copy_from_slice(signalling);

        assert!(owner.verify(&signed_data, sig).is_ok());
    }

    #[test]
    fn link_encrypt_decrypt_round_trip() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64]; // dummy LINKREQUEST payload
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);

        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        let mut ct = [0u8; 256];
        let ct_len = link.encrypt(b"test data", &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = link.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"test data");
    }

    #[test]
    fn full_handshake_both_sides() {
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-full").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        // Initiator creates link
        let initiator_identity = Identity::from_seed(b"initiator-full").unwrap();
        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        // Build LINKREQUEST packet to compute link_id
        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        // Responder receives LINKREQUEST
        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Responder builds proof
        let proof_payload = responder_link.build_proof(&responder_identity).unwrap();

        // Initiator validates proof
        initiator_link
            .validate_proof(&proof_payload, &responder_identity)
            .unwrap();

        // Both should derive the same key — test encrypt/decrypt
        let mut ct = [0u8; 256];
        let ct_len = responder_link
            .encrypt(b"from responder", &mut rng, &mut ct)
            .unwrap();
        let mut pt = [0u8; 256];
        let pt_len = initiator_link.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"from responder");

        let ct_len2 = initiator_link
            .encrypt(b"from initiator", &mut rng, &mut ct)
            .unwrap();
        let pt_len2 = responder_link.decrypt(&ct[..ct_len2], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len2], b"from initiator");
    }

    #[test]
    fn validate_proof_bad_sig_rejected() {
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-bad-sig").unwrap();
        let wrong_identity = Identity::from_seed(b"wrong-identity").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let initiator_identity = Identity::from_seed(b"initiator-bad-sig").unwrap();
        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Sign with wrong identity
        let proof_payload = responder_link.build_proof(&wrong_identity).unwrap();

        // Should fail verification (signed with wrong_identity, verified against responder_identity)
        assert!(initiator_link
            .validate_proof(&proof_payload, &responder_identity)
            .is_err());
    }

    #[test]
    fn initiate_link_creates_pending() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"initiator-pending").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let (link, payload) = Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(link.state, LinkState::Pending);
        assert_eq!(link.role, LinkRole::Initiator);
        assert_eq!(
            link.expected_hops(),
            Some(crate::transport::PATHFINDER_M)
        );
        assert_eq!(payload.len(), 67); // 64 keys + 3 signalling
        assert_eq!(&payload[..32], &link.our_x25519_pub);
    }

    #[test]
    fn responder_handshake_timeout_matches_python_boundary_and_hop_scaling() {
        let payload = [0xBBu8; 64];
        let origin = MonotonicInstant::from_micros(100_250_000);

        for (request_hops, expected_seconds) in [(0, 366), (1, 366), (3, 378)] {
            let mut rng = rand_core::OsRng;
            let link_id = LinkId::from([request_hops; TRUNCATED_HASH_LEN]);
            let mut link = Link::from_request_at_with_hops(
                link_id,
                &payload,
                &mut rng,
                origin,
                request_hops,
            )
            .unwrap();
            let timeout = MonotonicDuration::from_secs(expected_seconds);

            assert_eq!(link.responder_inbound_hops, Some(request_hops));
            assert_eq!(link.responder_establishment_timeout(), Some(timeout));
            assert!(!link.check_responder_establishment_timeout_at(
                origin + timeout - MonotonicDuration::from_micros(1)
            ));
            assert_eq!(link.state, LinkState::Handshake);
            assert!(link.check_responder_establishment_timeout_at(origin + timeout));
            assert_eq!(link.state, LinkState::Closed);
            assert!(!link.check_responder_establishment_timeout_at(
                origin + timeout + MonotonicDuration::from_secs(1)
            ));
        }
    }

    #[test]
    fn responder_handshake_timeout_does_not_own_initiator_or_active_lifecycle() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"establishment-timeout-scope").unwrap();
        let origin = MonotonicInstant::from_secs(100);
        let deadline = origin + MonotonicDuration::from_secs(10_000);

        let (mut initiator, _) = Link::new_initiator_at(
            DestHash::from([0xA1; TRUNCATED_HASH_LEN]),
            identity.ed25519_pub(),
            &mut rng,
            origin,
        );
        initiator.set_link_id(LinkId::from([0xA2; TRUNCATED_HASH_LEN]));
        assert_eq!(initiator.state, LinkState::Handshake);
        assert_eq!(initiator.responder_inbound_hops, None);
        assert_eq!(initiator.responder_establishment_timeout(), None);
        assert!(!initiator.check_responder_establishment_timeout_at(deadline));
        assert_eq!(initiator.state, LinkState::Handshake);

        let payload = [0xBBu8; 64];
        let mut responder = Link::from_request_at_with_hops(
            LinkId::from([0xA3; TRUNCATED_HASH_LEN]),
            &payload,
            &mut rng,
            origin,
            1,
        )
        .unwrap();
        responder.activate_at(origin);
        assert!(!responder.check_responder_establishment_timeout_at(deadline));
        assert_eq!(responder.state, LinkState::Active);
    }

    #[test]
    fn link_stale_detection() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        let active_at = MonotonicInstant::from_secs(100);
        link.activate_at(active_at);

        // Not stale yet
        assert!(!link.check_stale_at(MonotonicInstant::from_secs(200)));
        assert_eq!(link.state, LinkState::Active);

        // Remains active for the full two-keepalive stale interval.
        assert!(!link.check_stale_at(
            active_at + link.keepalive_interval + MonotonicDuration::from_secs(1)
        ));
        assert_eq!(link.state, LinkState::Active);

        // Goes stale at stale_time, then retains a five-second revival grace.
        let stale_at = active_at + link.stale_time;
        assert!(!link.check_stale_at(stale_at));
        assert_eq!(link.state, LinkState::Stale);
        let grace = link.stale_grace();
        assert!(!link.check_stale_at(
            stale_at + grace - MonotonicDuration::from_micros(1)
        ));
        assert_eq!(link.state, LinkState::Stale);

        assert!(link.check_stale_at(stale_at + grace));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn delayed_stale_check_starts_full_grace_at_transition() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        let active_at = MonotonicInstant::from_secs(100);
        link.activate_at(active_at);

        // A delayed watchdog must not consume the revival grace retroactively.
        let transition_at =
            active_at + link.stale_time + MonotonicDuration::from_secs(100);
        assert!(!link.check_stale_at(transition_at));
        assert_eq!(link.state, LinkState::Stale);
        let grace = link.stale_grace();
        assert!(!link.check_stale_at(
            transition_at + grace - MonotonicDuration::from_micros(1)
        ));
        assert_eq!(link.state, LinkState::Stale);

        assert!(link.check_stale_at(transition_at + grace));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn keepalive_payloads_are_exact_and_role_specific() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut responder = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        responder.activate(100);

        assert_eq!(responder.consume_keepalive(&[0xFF], 200), Some(true));
        assert_eq!(responder.handle_keepalive(&[0xFF], 201), Some(0xFE));
        assert_eq!(responder.last_inbound.as_secs(), 201);

        for invalid in [&[][..], &[0xFE][..], &[0xFF, 0x00][..]] {
            assert_eq!(responder.consume_keepalive(invalid, 300), None);
            assert_eq!(responder.last_inbound.as_secs(), 201);
        }

        let identity = Identity::from_seed(b"keepalive-role-initiator").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let (mut initiator, _) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);
        initiator.activate(100);
        assert_eq!(initiator.consume_keepalive(&[0xFE], 200), Some(false));
        assert_eq!(initiator.last_inbound.as_secs(), 200);

        for invalid in [&[][..], &[0xFF][..], &[0xFE, 0x00][..]] {
            assert_eq!(initiator.consume_keepalive(invalid, 300), None);
            assert_eq!(initiator.last_inbound.as_secs(), 200);
        }
    }

    #[test]
    fn linkclose_tears_down() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Receive LINKCLOSE with encrypted link_id
        let mut close_buf = [0u8; 256];
        let close_len = link.build_close(&mut rng, &mut close_buf).unwrap();

        // Decrypt and verify
        let mut pt = [0u8; 256];
        let pt_len = link.decrypt(&close_buf[..close_len], &mut pt).unwrap();
        assert!(link.handle_close(&pt[..pt_len]));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn linkclose_wrong_id_rejected() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Wrong link_id
        let wrong_id = [0xFFu8; TRUNCATED_HASH_LEN];
        assert!(!link.handle_close(&wrong_id));
        assert_eq!(link.state, LinkState::Active);
    }

    #[test]
    fn keepalive_on_pending_link_is_rejected_without_liveness_mutation() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"keepalive-pending").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let (mut link, _payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(link.state, LinkState::Pending);

        assert_eq!(link.consume_keepalive(&[0xFE], 200), None);
        assert_eq!(link.last_inbound.as_secs(), 100);
    }

    #[test]
    fn test_double_close() {
        // close() twice should not panic, state should be Closed.
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        assert_eq!(link.state, LinkState::Active);

        link.close();
        assert_eq!(link.state, LinkState::Closed);

        link.close(); // second close should not panic
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn test_linkrequest_with_oversized_payload() {
        // Link ID derivation strips arbitrary bytes after the 64 key bytes,
        // even though transport admission rejects non-canonical lengths.
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];

        // 64 key bytes plus 4 arbitrary trailing bytes.
        let mut payload = [0u8; 68];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..64].copy_from_slice(&ed25519_pub);
        payload[64..68].copy_from_slice(&[0x01, 0xF4, 0x00, 0x00]);

        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&payload)
            .build()
            .unwrap();

        // compute_link_id should not fail
        let link_id = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id.as_ref().len(), 16);

        // Also compute with standard 64-byte payload for comparison
        let mut buf2 = [0u8; MTU];
        let n2 = PacketBuilder::new(&mut buf2)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&payload[..64])
            .build()
            .unwrap();

        let link_id2 = compute_link_id(&buf2[..n2]).unwrap();
        // The link_ids should be the same (MTU signalling is stripped)
        assert_eq!(
            link_id, link_id2,
            "link_id should be same with or without MTU signalling"
        );
    }

    // -----------------------------------------------------------------------
    // Dynamic keepalive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_keepalive_low_rtt() {
        // RTT=0.05s (loopback) → keepalive ≈ 10s, stale ≈ 20s
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.05);
        // Preserve sub-second scheduling precision instead of truncating.
        assert!((link.keepalive_interval_seconds() - 10.285_714).abs() < 0.000_001);
        assert!((link.stale_time_seconds() - 20.571_428).abs() < 0.000_001);
        assert!((link.rtt - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_update_keepalive_high_rtt() {
        // RTT=2.0s → keepalive = 360 (clamped to max), stale = 720
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(2.0);
        // 2.0 * (360/1.75) ≈ 411.4 → clamped to 360
        assert_eq!(link.keepalive_interval, MonotonicDuration::from_secs(360));
        assert_eq!(link.stale_time, MonotonicDuration::from_secs(720));
    }

    #[test]
    fn test_update_keepalive_medium_rtt() {
        // RTT=0.5s → keepalive ≈ 102, stale ≈ 205
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.5);
        assert!((link.keepalive_interval_seconds() - 102.857_143).abs() < 0.000_001);
        assert!((link.stale_time_seconds() - 205.714_286).abs() < 0.000_001);
    }

    #[test]
    fn test_update_keepalive_very_low_rtt() {
        // RTT=0.001s → keepalive = 5 (clamped to min)
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.001);
        // 0.001 * (360/1.75) ≈ 0.206 → clamped to max(5, ...) = 5
        assert_eq!(link.keepalive_interval, MonotonicDuration::from_secs(5));
        assert_eq!(link.stale_time, MonotonicDuration::from_secs(10));
    }

    #[test]
    fn test_update_keepalive_zero_rtt_uses_minimum_interval() {
        // Zero is a valid RTT sample and still applies the five-second floor.
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.0);
        assert_eq!(link.rtt, 0.0);
        assert_eq!(link.keepalive_interval, MonotonicDuration::from_secs(5));
        assert_eq!(link.stale_time, MonotonicDuration::from_secs(10));
    }

    #[test]
    fn test_check_stale_with_dynamic_keepalive() {
        // After update_keepalive(0.05), stale triggers at ~10s not 360s
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.update_keepalive(0.05);
        let active_at = MonotonicInstant::from_secs(100);
        link.activate_at(active_at);

        // At 109 (9s elapsed) — should still be active
        assert!(!link.check_stale_at(MonotonicInstant::from_secs(109)));
        assert_eq!(link.state, LinkState::Active);

        // A Link stays active until stale_time (20 seconds), not one keepalive.
        assert!(!link.check_stale_at(MonotonicInstant::from_secs(111)));
        assert_eq!(link.state, LinkState::Active);

        let stale_at = active_at + link.stale_time;
        assert!(!link.check_stale_at(stale_at));
        assert_eq!(link.state, LinkState::Stale);

        // Five seconds of grace allows a final keepalive response to revive it.
        assert!(!link.check_stale_at(stale_at + MonotonicDuration::from_secs(4)));
        link.touch_inbound_at(stale_at + MonotonicDuration::from_secs(4));
        assert_eq!(link.state, LinkState::Active);
        assert!(!link.check_stale_at(stale_at + MonotonicDuration::from_secs(5)));

        // A later silence period closes at stale_time plus grace.
        let second_stale_at = stale_at + MonotonicDuration::from_secs(4) + link.stale_time;
        assert!(!link.check_stale_at(second_stale_at));
        assert_eq!(link.state, LinkState::Stale);
        assert!(link.check_stale_at(second_stale_at + link.stale_grace()));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn test_needs_keepalive_with_dynamic_keepalive() {
        // After update_keepalive(0.05), initiators probe after the full 10s.
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"keepalive-schedule-initiator").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let (mut link, _) = Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);
        link.update_keepalive(0.05);
        let active_at = MonotonicInstant::from_secs(100);
        link.activate_at(active_at);

        assert!(!link.needs_keepalive_at(MonotonicInstant::from_secs(110)));
        let due_at = active_at + link.keepalive_interval;
        assert!(link.needs_keepalive_at(due_at));

        // Ordinary outbound data does not conceal inbound silence.
        link.last_outbound = MonotonicInstant::from_secs(109);
        assert!(link.needs_keepalive_at(due_at));

        // A recorded probe rate-limits the next identical request.
        link.note_keepalive_outbound_at(due_at);
        assert!(!link.needs_keepalive_at(
            due_at + link.keepalive_interval - MonotonicDuration::from_micros(1)
        ));
        assert!(link.needs_keepalive_at(due_at + link.keepalive_interval));

        // Responders never initiate probes.
        let payload = [0xBBu8; 64];
        let link_id = LinkId::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut responder = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        responder.update_keepalive(0.05);
        responder.activate(100);
        assert!(!responder.needs_keepalive(1_000));
    }

    #[test]
    fn link_data_decrypt_deliver() {
        // Full handshake + data exchange
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-data").unwrap();
        let initiator_identity = Identity::from_seed(b"initiator-data").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let (mut initiator, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator.set_link_id(link_id);

        let responder = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();
        let proof = responder.build_proof(&responder_identity).unwrap();
        initiator
            .validate_proof(&proof, &responder_identity)
            .unwrap();

        // Send data from initiator to responder
        let message = b"encrypted message via link";
        let mut ct = [0u8; 256];
        let ct_len = initiator.encrypt(message, &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = responder.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], message);
    }

    // -----------------------------------------------------------------------
    // MTU signalling tests
    // -----------------------------------------------------------------------

    #[test]
    fn signalling_bytes_encoding() {
        // Python: struct.pack("!I", (500 & 0x1FFFFF) | ((1 & 0x07) << 21))[1:]
        // = struct.pack("!I", 500 | (1 << 21))[1:] = struct.pack("!I", 0x2001F4)[1:]
        // = b'\x20\x01\xf4'
        let sb = signalling_bytes(500, 0x01);
        assert_eq!(sb, [0x20, 0x01, 0xF4]);

        // Zero MTU, zero mode
        let sb0 = signalling_bytes(0, 0);
        assert_eq!(sb0, [0x00, 0x00, 0x00]);

        // Max MTU (21 bits) = 0x1FFFFF = 2097151
        let sb_max = signalling_bytes(0x1FFFFF, 0x07);
        // (0x1FFFFF | (0x07 << 21)) = 0xFFFFFF
        assert_eq!(sb_max, [0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn initiator_payload_includes_signalling() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"signalling-test").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let (_link, payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(payload.len(), 67);
        // Last 3 bytes should be signalling for MTU=500, mode=1
        let expected = signalling_bytes(rete_core::MTU as u32, MODE_AES_CBC);
        assert_eq!(&payload[64..67], &expected);
    }

    #[test]
    fn proof_signed_data_is_83_bytes() {
        let mut rng = rand_core::OsRng;
        let owner = Identity::from_seed(b"proof-83-test-owner").unwrap();
        let peer_id = Identity::from_seed(b"proof-83-test-peer").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        // Build initiator payload (67 bytes with signalling)
        let (_peer_link, request_payload) =
            Link::new_initiator(dest_hash, peer_id.ed25519_pub(), &mut rng, 100);

        let link_id = LinkId::from([0x22u8; TRUNCATED_HASH_LEN]);
        let link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        let proof = link.build_proof(&owner).unwrap();

        // Independently verify the signature covers exactly 83 bytes
        let sig = &proof[..64];
        let resp_x25519_pub = &proof[64..96];
        let signalling = &proof[96..99];

        let mut signed_data = [0u8; 83];
        signed_data[..16].copy_from_slice(link_id.as_ref());
        signed_data[16..48].copy_from_slice(resp_x25519_pub);
        signed_data[48..80].copy_from_slice(owner.ed25519_pub());
        signed_data[80..83].copy_from_slice(signalling);

        assert!(owner.verify(&signed_data, sig).is_ok());

        // Verify truncated 80-byte data does NOT match
        assert!(owner.verify(&signed_data[..80], sig).is_err());
    }

    #[test]
    fn validate_proof_backward_compat_96_bytes() {
        // When responder returns a 96-byte proof (no signalling),
        // initiator should still validate it.
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"compat-responder").unwrap();
        let initiator_identity = Identity::from_seed(b"compat-initiator").unwrap();
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        // Simulate a Python node that accepts 67-byte request but returns 96-byte proof
        // (backward compat: no signalling in proof)
        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Manually build 96-byte proof (old format, no signalling in signed data)
        let mut signed_data_80 = [0u8; 80];
        signed_data_80[..16].copy_from_slice(link_id.as_ref());
        signed_data_80[16..48].copy_from_slice(&responder_link.our_x25519_pub);
        signed_data_80[48..80].copy_from_slice(responder_identity.ed25519_pub());
        let sig = responder_identity.sign(&signed_data_80).unwrap();
        let mut proof_96 = [0u8; 96];
        proof_96[..64].copy_from_slice(&sig);
        proof_96[64..96].copy_from_slice(&responder_link.our_x25519_pub);

        // Initiator should accept 96-byte proof (signalling slice is empty → 80-byte signed_data)
        assert!(initiator_link
            .validate_proof(&proof_96, &responder_identity)
            .is_ok());
    }
}
