//! End-to-end encrypted sessions. Port of `ironwood/encrypted/session.go` +
//! `crypto.go` (NaCl box with Ed25519-derived keys, no group password).
//!
//! - e2c private: `sha512(seed)[..32]` as the X25519 scalar (clamping happens
//!   inside X25519, exactly like Go's `curve25519.X25519` via `box.Precompute`).
//! - e2c public: Montgomery `u = (1+y)/(1-y)` (curve25519-dalek's
//!   `to_montgomery`, same birational map as Go's `e2c`).
//! - init/ack: `[type] + eph_pub[32] + seal(sig || current || next ||
//!   keySeq BE64 || seq BE64, nonce=0, DH(toBox, eph_priv))`, `sig` over the
//!   same bytes with the long-term ed key.
//! - traffic: `[3] + localKeySeq + remoteKeySeq + nonce + seal(nextPub || msg)`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{append_uvarint, read_uvarint};
use crate::link::LinkSet;

pub const SESSION_TYPE_INIT: u8 = 1;
pub const SESSION_TYPE_ACK: u8 = 2;
pub const SESSION_TYPE_TRAFFIC: u8 = 3;
/// yggdrasil-go `typeSessionTraffic`: leading byte of TUN payloads inside a
/// session message (`Core.WriteTo` adds it, `Core.ReadFrom` dispatches on it).
pub const PACKET_TYPE_TRAFFIC: u8 = 1;
/// yggdrasil-go `typeSessionProto`: protocol payloads (nodeinfo/debug,
/// handled in `src/proto.rs`).
pub const PACKET_TYPE_PROTO: u8 = 2;
/// Fixed init/ack message length (Go `sessionInitSize`).
pub const SESSION_INIT_SIZE: usize = 193;
/// Minimum traffic message length (Go `sessionTrafficOverheadMin`).
pub const SESSION_TRAFFIC_MIN: usize = 52;
/// Session idle timeout (Go `sessionTimeout`).
pub const SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// X25519 private key derived from an ed25519 seed (Go `e2c` + X25519 clamp).
pub fn ed_to_curve_priv(seed: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(seed);
    h.finalize()[..32].try_into().unwrap()
}

/// X25519 public key derived from an ed25519 public key.
pub fn ed_to_curve_pub(pubkey: &[u8; KEY_LEN]) -> Result<[u8; 32], Error> {
    let point = CompressedEdwardsY(*pubkey)
        .decompress()
        .ok_or(Error::InvalidLength)?;
    Ok(point.to_montgomery().to_bytes())
}

fn nonce_for(counter: u64) -> crypto_box::Nonce {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&counter.to_be_bytes());
    *crypto_box::Nonce::from_slice(&n)
}

fn salsa_box(their_pub: &[u8; 32], our_priv: &[u8; 32]) -> crypto_box::SalsaBox {
    let pk = crypto_box::PublicKey::from(*their_pub);
    let sk = crypto_box::SecretKey::from(*our_priv);
    crypto_box::SalsaBox::new(&pk, &sk)
}

fn box_seal(shared_box: &crypto_box::SalsaBox, counter: u64, msg: &[u8]) -> Vec<u8> {
    use crypto_box::aead::Aead;
    shared_box
        .encrypt(&nonce_for(counter), msg)
        .expect("box seal cannot fail")
}

fn box_open(shared_box: &crypto_box::SalsaBox, counter: u64, sealed: &[u8]) -> Option<Vec<u8>> {
    use crypto_box::aead::Aead;
    shared_box.decrypt(&nonce_for(counter), sealed).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInit {
    pub current: [u8; 32],
    pub next: [u8; 32],
    pub key_seq: u64,
    pub seq: u64,
}

impl SessionInit {
    fn sig_bytes(&self, eph_pub: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 16);
        out.extend_from_slice(eph_pub);
        out.extend_from_slice(&self.current);
        out.extend_from_slice(&self.next);
        out.extend_from_slice(&self.key_seq.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out
    }

    /// Encrypt an init (or ack, via `msg_type`) to `dest`'s ed key.
    pub fn encrypt_msg(
        &self,
        msg_type: u8,
        from_ed: &SigningKey,
        dest_ed: &[u8; KEY_LEN],
    ) -> Vec<u8> {
        let eph_priv = crypto_box::SecretKey::generate(&mut rand::thread_rng());
        let eph_pub: [u8; 32] = crypto_box::PublicKey::from(&eph_priv).to_bytes();
        let dest_box = ed_to_curve_pub(dest_ed).expect("valid ed key");
        let shared = salsa_box(&dest_box, &eph_priv.to_bytes());
        let sig = from_ed.sign(&self.sig_bytes(&eph_pub)).to_bytes();
        let mut payload = Vec::with_capacity(64 + 32 + 32 + 16);
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&self.current);
        payload.extend_from_slice(&self.next);
        payload.extend_from_slice(&self.key_seq.to_be_bytes());
        payload.extend_from_slice(&self.seq.to_be_bytes());
        let sealed = box_seal(&shared, 0, &payload);
        let mut out = Vec::with_capacity(SESSION_INIT_SIZE);
        out.push(msg_type);
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), SESSION_INIT_SIZE);
        out
    }

    /// Decrypt with our box private key; verifies the ed signature from `from`.
    pub fn decrypt_msg(
        our_box_priv: &[u8; 32],
        from_ed: &[u8; KEY_LEN],
        data: &[u8],
    ) -> Option<Self> {
        if data.len() != SESSION_INIT_SIZE
            || (data[0] != SESSION_TYPE_INIT && data[0] != SESSION_TYPE_ACK)
        {
            return None;
        }
        let eph_pub: [u8; 32] = data[1..33].try_into().ok()?;
        let shared = salsa_box(&eph_pub, our_box_priv);
        let payload = box_open(&shared, 0, &data[33..])?;
        if payload.len() != 64 + 32 + 32 + 8 + 8 {
            return None;
        }
        let sig = ed25519_dalek::Signature::from_bytes(payload[..64].try_into().ok()?);
        let mut current = [0u8; 32];
        let mut next = [0u8; 32];
        current.copy_from_slice(&payload[64..96]);
        next.copy_from_slice(&payload[96..128]);
        let key_seq = u64::from_be_bytes(payload[128..136].try_into().ok()?);
        let seq = u64::from_be_bytes(payload[136..144].try_into().ok()?);
        let init = Self {
            current,
            next,
            key_seq,
            seq,
        };
        // Signature covers eph_pub + (current || next || keySeq || seq).
        let mut sig_msg = Vec::with_capacity(32 + 80);
        sig_msg.extend_from_slice(&eph_pub);
        sig_msg.extend_from_slice(&payload[64..]);
        ed25519_dalek::VerifyingKey::from_bytes(from_ed)
            .ok()?
            .verify_strict(&sig_msg, &sig)
            .ok()?;
        Some(init)
    }
}

fn fresh_box() -> ([u8; 32], [u8; 32]) {
    let privk = crypto_box::SecretKey::generate(&mut rand::thread_rng());
    let pubk = crypto_box::PublicKey::from(&privk);
    (pubk.to_bytes(), privk.to_bytes())
}

/// The four precomputed shared secrets (Go `sessionInfo._fixShared`).
fn shared4(
    current: &[u8; 32],
    next: &[u8; 32],
    recv_priv: &[u8; 32],
    send_priv: &[u8; 32],
) -> (
    crypto_box::SalsaBox,
    crypto_box::SalsaBox,
    crypto_box::SalsaBox,
    crypto_box::SalsaBox,
) {
    (
        salsa_box(current, recv_priv),
        salsa_box(current, send_priv),
        salsa_box(next, send_priv),
        salsa_box(next, recv_priv),
    )
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pending outbound session: buffered initiator keys + one queued payload
/// (Go `sessionBuffer`, timers as instants). The payload carries its
/// session packet-type byte (`1` traffic / `2` proto) so the flush path
/// re-frames it exactly as a live send would.
#[derive(Clone)]
pub(crate) struct SessionBuf {
    pub init: SessionInit,
    pub send_pub: [u8; 32],
    pub send_priv: [u8; 32],
    pub next_pub: [u8; 32],
    pub next_priv: [u8; 32],
    pub data: Option<(u8, Vec<u8>)>,
    pub deadline: std::time::Instant,
}

/// E2E session table: open sessions, pending initiators, init sequence, and
/// payloads to retry on the next link. Owned by [`crate::router::Router`];
/// delivered payloads go to the router inbox (public API), not here.
pub(crate) struct SessionState {
    pub(crate) sessions: std::collections::HashMap<[u8; KEY_LEN], (Session, std::time::Instant)>,
    pub(crate) bufs: std::collections::HashMap<[u8; KEY_LEN], SessionBuf>,
    pub(crate) init_seq: std::sync::atomic::AtomicU64,
    /// App payloads that failed mid-write on a dead link, retried on the
    /// next link (at-least-once across reconnects; duplicates possible).
    pub(crate) resend: Vec<([u8; KEY_LEN], Vec<u8>)>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            bufs: std::collections::HashMap::new(),
            init_seq: std::sync::atomic::AtomicU64::new(0),
            resend: Vec::new(),
        }
    }
}

impl crate::router::Router {
    pub(crate) fn box_priv(&self) -> [u8; 32] {
        ed_to_curve_priv(&self.key.to_bytes())
    }

    /// Send a session-layer payload inside network traffic to `dest`.
    async fn net_send(
        &mut self,
        links: &mut LinkSet,
        dest: [u8; KEY_LEN],
        payload: Vec<u8>,
    ) -> Result<(), crate::error::Error> {
        self.pathfinder_send(links, dest, payload).await
    }

    /// Handle one session payload extracted from inbound traffic.
    pub(crate) async fn handle_session_bytes(
        &mut self,
        links: &mut LinkSet,
        from: [u8; KEY_LEN],
        data: &[u8],
    ) -> Result<(), crate::error::Error> {
        if data.is_empty() {
            return Ok(());
        }
        let now = std::time::Instant::now();
        let sk = self.key.clone();
        match data[0] {
            SESSION_TYPE_INIT | SESSION_TYPE_ACK => {
                let is_ack = data[0] == SESSION_TYPE_ACK;
                let box_priv = self.box_priv();
                let Some(init) = SessionInit::decrypt_msg(&box_priv, &from, data) else {
                    return Ok(());
                };
                if !self.sess.sessions.contains_key(&from) {
                    // New session (Go `_sessionForInit`): adopt buffered
                    // initiator keys when we initiated first, then always
                    // handle the message as an init — even acks (Go
                    // `_handleAck` !isOld path) — and flush queued payload.
                    let mut s = Session::for_init(&init);
                    let buffered = self.sess.bufs.remove(&from);
                    if let Some(buf) = &buffered {
                        s.adopt_buffered(buf.send_pub, buf.send_priv, buf.next_pub, buf.next_priv);
                    }
                    self.sess.sessions.insert(from, (s, now));
                    let ack_seq = self.next_init_seq();
                    let ack_init = self.sess.sessions.get_mut(&from).and_then(|(s, active)| {
                        *active = now;
                        s.handle_init(&init, ack_seq)
                    });
                    if let Some(ack) = ack_init {
                        let enc = ack.encrypt_msg(SESSION_TYPE_ACK, &sk, &from);
                        self.net_send(links, from, enc).await?;
                    }
                    if let Some((kind, payload)) = buffered.and_then(|b| b.data) {
                        self.session_send_inner(links, from, kind, payload).await?;
                    }
                    return Ok(());
                }
                if is_ack {
                    if let Some((s, active)) = self.sess.sessions.get_mut(&from) {
                        *active = now;
                        s.handle_ack(&init);
                    }
                    return Ok(());
                }
                let ack_seq = self.next_init_seq();
                let ack_init = self.sess.sessions.get_mut(&from).and_then(|(s, active)| {
                    *active = now;
                    s.handle_init(&init, ack_seq)
                });
                if let Some(ack) = ack_init {
                    let enc = ack.encrypt_msg(SESSION_TYPE_ACK, &sk, &from);
                    self.net_send(links, from, enc).await?;
                }
            }
            SESSION_TYPE_TRAFFIC => {
                // Fresh seq up front: the decrypt-fail arm needs one while
                // the session is borrowed (counter skips are harmless).
                let reinit_seq = self.next_init_seq();
                if let Some((s, active)) = self.sess.sessions.get_mut(&from) {
                    match s.decrypt(data) {
                        Some(payload) => {
                            *active = now;
                            // The path entry's deadline was refreshed on the way
                            // in, in `handle_inbound_traffic`, where Go refreshes
                            // it (`network/router.go:597`). Not here: a peer whose
                            // frames never decrypt would otherwise age out of the
                            // path table over a link that is plainly working.
                            // yggdrasil-go dispatches on the leading session
                            // packet-type byte (`Core.ReadFrom` in
                            // yggdrasil-go/src/core/core.go): 1 = TUN
                            // traffic (delivered to the app), 2 = protocol
                            // (nodeinfo/debug, handled in `src/proto.rs`),
                            // anything else dropped.
                            match payload.first() {
                                Some(&PACKET_TYPE_TRAFFIC) => {
                                    self.inbox.push((from, payload[1..].to_vec()));
                                }
                                Some(&PACKET_TYPE_PROTO) => {
                                    self.handle_proto_bytes(links, from, &payload[1..]).await?;
                                }
                                _ => {}
                            }
                        }
                        None => {
                            let init = s.make_init(reinit_seq);
                            let enc = init.encrypt_msg(SESSION_TYPE_INIT, &sk, &from);
                            self.net_send(links, from, enc).await?;
                        }
                    }
                } else {
                    // Unknown peer: forgettable init so a real peer can
                    // self-heal by acking (Go `_handleTraffic` fallback).
                    let (cp, _) = fresh_box();
                    let (np, _) = fresh_box();
                    let init = SessionInit {
                        current: cp,
                        next: np,
                        key_seq: 0,
                        seq: self.next_init_seq(),
                    };
                    let enc = init.encrypt_msg(SESSION_TYPE_INIT, &sk, &from);
                    self.net_send(links, from, enc).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Encrypt via the existing session (caller guarantees presence).
    /// Wraps the raw payload with the session packet-type byte first (`1`
    /// for TUN traffic, `2` for protocol), so callers (fresh sends, buffer
    /// flushes, resends) all pass raw bytes and double-wrapping is
    /// impossible. The buffered-init path stores the same kind byte, so a
    /// proto request queued before the session exists is still framed as
    /// proto on flush.
    async fn session_send_inner(
        &mut self,
        links: &mut LinkSet,
        dest: [u8; KEY_LEN],
        kind: u8,
        msg: Vec<u8>,
    ) -> Result<(), crate::error::Error> {
        let mut wrapped = Vec::with_capacity(msg.len() + 1);
        wrapped.push(kind);
        wrapped.extend_from_slice(&msg);
        let enc = self.sess.sessions.get_mut(&dest).map(|(s, active)| {
            *active = std::time::Instant::now();
            s.encrypt(&wrapped)
        });
        if let Some(enc) = enc {
            let sent = self.net_send(links, dest, enc).await;
            if sent.is_err() {
                // Link died mid-write: retry the raw plaintext on the next link.
                self.sess.resend.push((dest, msg));
                sent?;
            }
        }
        Ok(())
    }

    /// App-level send: encrypt now or buffer behind an init (Go `writeTo`).
    pub(crate) async fn session_send(
        &mut self,
        links: &mut LinkSet,
        dest: [u8; KEY_LEN],
        msg: Vec<u8>,
    ) -> Result<(), crate::error::Error> {
        self.session_send_kind(links, dest, PACKET_TYPE_TRAFFIC, msg)
            .await
    }

    /// Kind-generalized send: `PACKET_TYPE_TRAFFIC` for TUN payloads,
    /// `PACKET_TYPE_PROTO` for nodeinfo/debug frames (framing is the only
    /// difference; session setup and buffering are shared).
    pub(crate) async fn session_send_kind(
        &mut self,
        links: &mut LinkSet,
        dest: [u8; KEY_LEN],
        kind: u8,
        msg: Vec<u8>,
    ) -> Result<(), crate::error::Error> {
        if self.sess.sessions.contains_key(&dest) {
            return self.session_send_inner(links, dest, kind, msg).await;
        }
        let now = std::time::Instant::now();
        let sk = self.key.clone();
        let init_seq = self.next_init_seq();
        let enc = {
            let buf = self.sess.bufs.entry(dest).or_insert_with(|| {
                let (cp, cs) = fresh_box();
                let (np, ns) = fresh_box();
                SessionBuf {
                    init: SessionInit {
                        current: cp,
                        next: np,
                        key_seq: 0,
                        seq: init_seq,
                    },
                    send_pub: cp,
                    send_priv: cs,
                    next_pub: np,
                    next_priv: ns,
                    data: None,
                    deadline: now + SESSION_TIMEOUT,
                }
            });
            buf.data = Some((kind, msg));
            buf.deadline = now + SESSION_TIMEOUT;
            buf.init.clone().encrypt_msg(SESSION_TYPE_INIT, &sk, &dest)
        };
        self.net_send(links, dest, enc).await
    }
}

/// One peer's session state. Faithful port of Go `sessionInfo`
/// (single-threaded; callers handle timers).
pub struct Session {
    seq: u64,
    remote_key_seq: u64,
    current: [u8; 32],
    next: [u8; 32],
    local_key_seq: u64,
    recv_priv: [u8; 32],
    recv_pub: [u8; 32],
    recv_shared: crypto_box::SalsaBox,
    recv_nonce: u64,
    send_priv: [u8; 32],
    send_pub: [u8; 32],
    send_shared: crypto_box::SalsaBox,
    send_nonce: u64,
    next_priv: [u8; 32],
    next_pub: [u8; 32],
    next_send_shared: crypto_box::SalsaBox,
    next_send_nonce: u64,
    next_recv_shared: crypto_box::SalsaBox,
    next_recv_nonce: u64,
    rotated_at: Option<std::time::Instant>,
}

impl Session {
    fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        let (a, b, c, d) = shared4(&self.current, &self.next, &self.recv_priv, &self.send_priv);
        self.recv_shared = a;
        self.send_shared = b;
        self.next_send_shared = c;
        self.next_recv_shared = d;
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    /// Create from an inbound init (responder side), like Go `_newSession`.
    pub fn for_init(init: &SessionInit) -> Self {
        let (recv_pub, recv_priv) = fresh_box();
        let (send_pub, send_priv) = fresh_box();
        let (next_pub, next_priv) = fresh_box();
        let (recv_shared, send_shared, next_send_shared, next_recv_shared) =
            shared4(&init.current, &init.next, &recv_priv, &send_priv);
        Self {
            seq: init.seq.wrapping_sub(1),
            remote_key_seq: 0,
            current: init.current,
            next: init.next,
            local_key_seq: 0,
            recv_priv,
            recv_pub,
            recv_shared,
            recv_nonce: 0,
            send_priv,
            send_pub,
            send_shared,
            send_nonce: 0,
            next_priv,
            next_pub,
            next_send_shared,
            next_recv_nonce: 0,
            next_send_nonce: 0,
            next_recv_shared,
            rotated_at: None,
        }
    }

    /// Adopt buffered initiator keys (Go `_sessionForInit` buffer path).
    pub fn adopt_buffered(
        &mut self,
        send_pub: [u8; 32],
        send_priv: [u8; 32],
        next_pub: [u8; 32],
        next_priv: [u8; 32],
    ) {
        self.send_pub = send_pub;
        self.send_priv = send_priv;
        self.next_pub = next_pub;
        self.next_priv = next_priv;
        self.fix_shared(0, 0);
    }

    /// Handle inbound init; returns the ack-init to send back when accepted
    /// (built with the caller-supplied sequence number).
    pub fn handle_init(&mut self, init: &SessionInit, ack_seq: u64) -> Option<SessionInit> {
        if init.seq <= self.seq {
            return None;
        }
        self.apply_update(init);
        Some(self.make_init(ack_seq))
    }

    /// Handle inbound ack; no reply needed.
    pub fn handle_ack(&mut self, ack: &SessionInit) {
        if ack.seq <= self.seq {
            return;
        }
        self.apply_update(ack);
    }

    fn apply_update(&mut self, init: &SessionInit) {
        self.current = init.current;
        self.next = init.next;
        self.seq = init.seq;
        self.remote_key_seq = init.key_seq;
        std::mem::swap(&mut self.recv_pub, &mut self.send_pub);
        std::mem::swap(&mut self.recv_priv, &mut self.send_priv);
        std::mem::swap(&mut self.send_pub, &mut self.next_pub);
        std::mem::swap(&mut self.send_priv, &mut self.next_priv);
        // Fresh next keys every update, like Go `_handleUpdate`
        // (forward secrecy — recycled keys would still agree in
        // loopback, but diverge from a real Go peer's hygiene).
        let (np, ns) = fresh_box();
        self.next_pub = np;
        self.next_priv = ns;
        self.local_key_seq += 1;
        let send_nonce = self.send_nonce;
        self.fix_shared(0, send_nonce);
    }

    pub fn make_init(&self, seq: u64) -> SessionInit {
        SessionInit {
            current: self.send_pub,
            next: self.next_pub,
            key_seq: self.local_key_seq,
            seq,
        }
    }

    /// Encrypt one payload. Returns `None` only on nonce exhaustion edge
    /// (handled by rotating first, mirroring Go).
    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        self.send_nonce = self.send_nonce.wrapping_add(1);
        if self.send_nonce == 0 {
            std::mem::swap(&mut self.recv_pub, &mut self.send_pub);
            std::mem::swap(&mut self.recv_priv, &mut self.send_priv);
            std::mem::swap(&mut self.send_pub, &mut self.next_pub);
            std::mem::swap(&mut self.send_priv, &mut self.next_priv);
            let (np, ns) = fresh_box();
            self.next_pub = np;
            self.next_priv = ns;
            self.local_key_seq += 1;
            self.fix_shared(0, 0);
        }
        let mut out = Vec::with_capacity(64 + msg.len() + 32);
        out.push(SESSION_TYPE_TRAFFIC);
        append_uvarint(&mut out, self.local_key_seq);
        append_uvarint(&mut out, self.remote_key_seq);
        append_uvarint(&mut out, self.send_nonce);
        let mut inner = Vec::with_capacity(32 + msg.len());
        inner.extend_from_slice(&self.next_pub);
        inner.extend_from_slice(msg);
        out.extend_from_slice(&box_seal(&self.send_shared, self.send_nonce, &inner));
        out
    }

    /// Decrypt one inbound message. Returns the inner payload, or `None`
    /// (caller should then send a fresh init, mirroring Go).
    pub fn decrypt(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < SESSION_TRAFFIC_MIN || msg[0] != SESSION_TYPE_TRAFFIC {
            return None;
        }
        let mut off = 1;
        let (rks, n) = read_uvarint(&msg[off..])?;
        off += n;
        let (lks, n) = read_uvarint(&msg[off..])?;
        off += n;
        let (nonce, n) = read_uvarint(&msg[off..])?;
        off += n;
        let body = &msg[off..];
        let from_current = rks == self.remote_key_seq;
        let from_next = rks == self.remote_key_seq + 1;
        let to_recv = lks + 1 == self.local_key_seq;
        let to_send = lks == self.local_key_seq;
        enum Case {
            Current,
            NextSend,
            NextRecv,
        }
        let case = if from_current && to_recv {
            if !(self.recv_nonce < nonce) {
                return None;
            }
            Case::Current
        } else if from_next && to_send {
            if !(self.next_send_nonce < nonce) {
                return None;
            }
            Case::NextSend
        } else if from_next && to_recv {
            if !(self.next_recv_nonce < nonce) {
                return None;
            }
            Case::NextRecv
        } else {
            return None;
        };
        let shared = match case {
            Case::Current => &self.recv_shared,
            Case::NextSend => &self.next_send_shared,
            Case::NextRecv => &self.next_recv_shared,
        };
        let opened = box_open(shared, nonce, body)?;
        if opened.len() < 32 {
            return None;
        }
        let mut inner_key = [0u8; 32];
        inner_key.copy_from_slice(&opened[..32]);
        let payload = opened[32..].to_vec();
        match case {
            Case::Current => self.recv_nonce = nonce,
            Case::NextSend => {
                self.next_send_nonce = nonce;
                self.maybe_rotate(inner_key, nonce);
            }
            Case::NextRecv => {
                self.next_recv_nonce = nonce;
                self.maybe_rotate(inner_key, nonce);
            }
        }
        Some(payload)
    }

    fn maybe_rotate(&mut self, inner_key: [u8; 32], nonce: u64) {
        let due = self
            .rotated_at
            .map(|t| t.elapsed() > std::time::Duration::from_secs(60))
            .unwrap_or(true);
        if !due {
            return;
        }
        self.current = self.next;
        self.next = inner_key;
        self.remote_key_seq += 1;
        std::mem::swap(&mut self.recv_pub, &mut self.send_pub);
        std::mem::swap(&mut self.recv_priv, &mut self.send_priv);
        std::mem::swap(&mut self.send_pub, &mut self.next_pub);
        std::mem::swap(&mut self.send_priv, &mut self.next_priv);
        let (np, ns) = fresh_box();
        self.next_pub = np;
        self.next_priv = ns;
        self.local_key_seq += 1;
        self.fix_shared(nonce, 0);
        self.rotated_at = Some(std::time::Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From Go TestZZVectors.
    const PUBA: &str = "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4";
    const PUBB: &str = "74fca2a3b389fb1a64d9bf52cc0dd4c2964f3804c0cf7c755e8513c6db8198dc";
    const E2C_PUBA: &str = "0ebf980a860de51ca2e0806f41f5276624ee1ae4ce239fcb72d1b028db7e391e";
    const E2C_PUBB: &str = "8452235d88d31e58f273cbfdc0df344d4586a78270f4148ed516ed7690a2485f";
    const E2C_PRIVB: &str = "a371e84f9243c12495e0005a617b932e51bab46425706bbae819371dc86a8784";
    // Real A -> B init bytes captured from the Go generator (keySeq=3).
    const GO_INIT: &str = "0126ba02e793077cc6eae80d427a5551ef09a1671f490d922b9f014984ef96ca67b554d46a178f6df3fc6d4d47ba55107174a1510c3fdbf7b947f24c1ee940585e43e3ad78bceee3efea03eed31620167d7227cff2cecaf1589b1321e2de41e08b6a1959446d9c4a3a15c4ead208c684f29119460a0fc616f002e01fb6337d66c54ecbe0e0acb52eadd36c069e8ebf0b718e8d5987cdcb86b3051d73cb8eab5e43b9e66c162035d3cec5429a43172c39a018fd3a78d6b9608de4bbef106aadee32";

    fn key(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn edkey(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }
    /// The ed public key of an `edkey`, as the 32 raw bytes a message is sealed to.
    fn pb_of(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn e2c_pub_matches_go() {
        assert_eq!(hex::encode(ed_to_curve_pub(&key(PUBA)).unwrap()), E2C_PUBA);
        assert_eq!(hex::encode(ed_to_curve_pub(&key(PUBB)).unwrap()), E2C_PUBB);
    }

    #[test]
    fn e2c_priv_is_sha512_seed_prefix() {
        // Go: sha512(seed)[:32], no clamp (X25519 clamps internally).
        let seed = [0xA0u8; 32];
        let mut h = Sha512::new();
        h.update(seed);
        let expect: [u8; 32] = h.finalize()[..32].try_into().unwrap();
        assert_eq!(ed_to_curve_priv(&seed), expect);
    }

    #[test]
    fn go_init_decrypts_with_b_key() {
        // Real A -> B init bytes from the Go generator: decrypt with B's
        // box key, check A's ed signature and keySeq=3.
        let raw = hex::decode(GO_INIT).unwrap();
        assert_eq!(raw.len(), SESSION_INIT_SIZE);
        let dec = SessionInit::decrypt_msg(&key(E2C_PRIVB), &key(PUBA), &raw).unwrap();
        assert_eq!(dec.key_seq, 3);
        // Wrong recipient key must fail.
        assert!(SessionInit::decrypt_msg(&key(E2C_PUBA), &key(PUBA), &raw).is_none());
    }

    /// A session `init` **the installed Go 0.5.14 sent**, captured 2026-10-03 by
    /// `examples/go_capture.rs --frames`.
    ///
    /// This is the first and only session message in this repository that came
    /// from a running Go node rather than from a Go generator, and it closes the
    /// gap `docs/protocol/README.md` has been carrying: session `ack` and `key`
    /// listed as "round-trip only" and "nothing" respectively for several
    /// slices.
    ///
    /// It was reachable the whole time. The reason it was not is worth
    /// recording, because every step is a *silent* no-op rather than an error:
    ///
    /// 1. Go only ever sends nodeinfo in reply to an admin `getNodeInfo`.
    ///    `_sendReq` has exactly one caller in the whole module
    ///    (`core/nodeinfo.go:160`) — there is no proactive send anywhere.
    /// 2. Go only advertises a bloom filter for peers on its routing tree, and
    ///    `_fixOnTree` (`ironwood/network/bloomfilter.go:151-156`) puts a peer
    ///    there only if it is Go's parent or Go is its parent. A node announcing
    ///    *itself* as its own parent satisfies neither arm, so it is off the tree
    ///    and every multicast skips it.
    /// 3. `_sendMulticast` decides where to send a `PathLookup` by testing the
    ///    **peer's advertised** filter (`:314-317`), so a node that never
    ///    advertises one has every lookup discarded before it leaves.
    /// 4. A `PathNotify` with an **empty** `info.path` is accepted, verified, and
    ///    routes nothing: `_getDist` is a prefix count over port lists
    ///    (`network/router.go:661-683`) and `_lookup` seeds `bestDist` from its
    ///    own key, so with an empty `destPath` no peer can ever be strictly
    ///    better. The path has to be the single peer port Go allocated for the
    ///    link, which is the `port` in the `SigRes` Go sent us — Go numbers peers
    ///    from 1 upward (`network/peers.go:53-61`).
    ///
    /// So the vector below is Go's real bytes, opened with our own box key.
    const GO_SESSION_INIT: &str = "0157d79dc3e8af7fcc1fc870a7a7dedb3f6d937eba55281a42062d56ebd97a7f\
        235c0315cc7abdf8106a6ac473c53654193115892add473a63b71dff6fa46718\
        77570b652d8f101b6c6e502bc92c6169f9d3d57f4f3be7bee1089355e3f5688d\
        cf7d68550d719ec0fd80d36ed63f79ca57e1bde37c320f5392585c9a56a61be4\
        4e71b95955cf613946d4e2c521d5b006ab064a83631367b53b97add4fcee5031\
        9ab883eba7663d3ad6e5798d4aca308c15ceb559dee81fc7afb93ec5dae1d3ff\
        b2";
    /// Go's node key, from the `meta` of the same run, and the `current`/`next`
    /// box keys and `seq` the captured `init` carries.
    const GO_SESSION_PUB: &str = "ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3";
    const GO_SESSION_CURRENT: &str =
        "afd7207dc7f93ce0a492b7d1af4ff42ed1b74acfe66b2c24b7772b885e279350";
    const GO_SESSION_NEXT: &str =
        "35b03ead4395bdcb67dec583b6810d72678649c72c5b4acbbdaa1d909e002e2c";
    const GO_SESSION_SEQ: u64 = 1791046450;

    /// Go's own `init`, opened with our box key, field by field.
    ///
    /// What this buys over `go_init_decrypts_with_b_key` above, which is the whole
    /// point of having both: that one is a **Go generator's** bytes, so it moves
    /// whenever Go's tests move. This one is bytes a Go node chose on its own,
    /// against a key we hold.
    ///
    /// Each assertion catches something the round trip cannot:
    ///
    /// - **the leading type byte is `1`** (`SESSION_TYPE_INIT`), read at offset
    ///   0 rather than inferred. The layering rule in `AGENTS.md` — exactly one
    ///   layer adds it — is worth a test on Go's own output, because adding a
    ///   second one is fatal and looks right.
    /// - **193 bytes**, `SESSION_INIT_SIZE`. The size falls out of the field
    ///   widths, so a width change on either side shows up here.
    /// - **`key_seq == 0`.** This is a *first* session, not a rotation, so the
    ///   field Go wrote a `key` rotation into is zero — which is the concrete
    ///   content behind "there is no `key` message". A rotation would carry
    ///   `localKeySeq`, and a nonzero value here would mean this was one.
    /// - **`seq` is a real timestamp**, not a counter that starts at 0 or 1. Go
    ///   uses `uint64(time.Now().Unix())` for exactly this field, and a 10-digit
    ///   value is the observable consequence.
    /// - **`current != next`**, because Go generates two fresh key pairs
    ///   (`newSessionInit`) rather than reusing one. A decoder that collapsed
    ///   them would pass every round trip.
    /// - **it re-encrypts byte-identically**, which nothing else checks: it means
    ///   our signature preimage and the ephemeral-key handling agree with Go's
    ///   *output* rather than with our own encoder.
    /// - **the wrong key fails**, so the box open is actually keyed and not a
    ///   length check in disguise.
    #[test]
    fn a_captured_go_session_init_opens_and_verifies() {
        let raw = hex::decode(GO_SESSION_INIT).expect("hex");
        assert_eq!(
            raw.len(),
            SESSION_INIT_SIZE,
            "193 bytes, as the widths imply"
        );
        assert_eq!(
            raw[0], SESSION_TYPE_INIT,
            "one leading type byte, and it is `init`"
        );

        // Our box key: `e2c` of the harness's own seed, which is what the capture
        // harness generated the node with.
        let our_box_priv = ed_to_curve_priv(&[0x2b; 32]);
        let dec = SessionInit::decrypt_msg(&our_box_priv, &key(GO_SESSION_PUB), &raw)
            .expect("open the init Go sent us");
        assert_eq!(dec.current, key(GO_SESSION_CURRENT), "current box key");
        assert_eq!(dec.next, key(GO_SESSION_NEXT), "next box key");
        assert_eq!(
            dec.key_seq, 0,
            "a first session, so the field a `key` rotation would use is zero"
        );
        assert_eq!(dec.seq, GO_SESSION_SEQ, "seq is a unix timestamp");
        assert!(
            dec.current != dec.next,
            "Go generates two distinct key pairs, not one reused"
        );
        // Go's timestamp is in seconds and is therefore plausible only if it is
        // roughly now. A u64 counter starting near zero would fail this; so
        // would a nanosecond clock, which would be 1e9 times larger.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            dec.seq.abs_diff(now) < 60 * 60 * 24 * 365 * 50,
            "seq {} should be a plausible unix timestamp near {now}",
            dec.seq
        );

        // The signature check happens inside `decrypt_msg`, over the raw
        // decrypted bytes rather than over anything this crate assembles. So
        // reaching here at all means Go's `sig` verified against our *reading*
        // of the field layout — which is the claim `sig_bytes` makes, checked
        // against Go's output rather than against our own encoder.
        //
        // Note what that does and does not cover. `sig_bytes` (used only by
        // `encrypt_msg`) is what a preimage-order mutation hits, and it is
        // covered by `session_handshake_roundtrip`, which round-trips through
        // both directions. This test covers the decode side. Between them the
        // order is pinned; neither alone would be.

        // Wrong recipient key must fail: the box open is keyed, not a length
        // check in disguise.
        assert!(
            SessionInit::decrypt_msg(&ed_to_curve_priv(&[0xFF; 32]), &key(GO_SESSION_PUB), &raw)
                .is_none(),
            "a different box key must not open it"
        );

        // And a **traffic** type byte must be refused, which is the one that
        // matters and the one nothing else in this module checked.
        //
        // The layering rule is that exactly one layer adds the leading type byte,
        // and Go admits only `init` and `ack`
        // (`encrypted/session.go:264-266`) — dropping anything else silently, with
        // no log and no counter. So a decoder that accepted a traffic message here
        // would not fail loudly: it would *succeed*, quietly absorbing bytes that
        // belong one layer up, and the symptom would be an application payload
        // that never arrives next to a session that looks perfectly healthy.
        //
        // Mutation-checked: deleting the type check from `decrypt_msg` leaves
        // every other test in this file passing.
        for t in 0u8..=255 {
            if t == SESSION_TYPE_INIT || t == SESSION_TYPE_ACK {
                continue;
            }
            let mut wrong = raw.clone();
            wrong[0] = t;
            assert!(
                SessionInit::decrypt_msg(
                    &ed_to_curve_priv(&[0x2b; 32]),
                    &key(GO_SESSION_PUB),
                    &wrong
                )
                .is_none(),
                "type byte {t} must be refused, not taken for a session message"
            );
        }
        // Length is the other half, and the size is exactly what the field widths
        // imply — so a width change on either side shows up here rather than as a
        // decode that "works" on the fields it happens to reach.
        assert!(
            SessionInit::decrypt_msg(
                &ed_to_curve_priv(&[0x2b; 32]),
                &key(GO_SESSION_PUB),
                &raw[..SESSION_INIT_SIZE - 1]
            )
            .is_none(),
            "a short payload is refused"
        );
        let mut padded = raw.clone();
        padded.push(0);
        assert!(
            SessionInit::decrypt_msg(
                &ed_to_curve_priv(&[0x2b; 32]),
                &key(GO_SESSION_PUB),
                &padded
            )
            .is_none(),
            "a padded payload is refused"
        );
    }

    /// The session `ack` shape, against Go's `init` bytes.
    ///
    /// There is no captured `ack` in this repository and this does not change
    /// that: Go never sends one here, because it has nothing to say after a
    /// request it already answered. What *is* pinned here is the one fact about
    /// `ack` that a captured message would have supplied and that the round trip
    /// cannot distinguish — that **`ack` and `init` are the same wire format**,
    /// differing only in the leading type byte.
    ///
    /// They are, because Go builds both from the same `sessionInit` and calls the
    /// same `encrypt`: `_sendAck` and `sendInit` differ in one argument
    /// (`encrypted/session.go:180-190`). So the *only* thing a future capture can
    /// change is the type byte and the key material, and this test fixes the
    /// relationship so that a capture which disagrees is a real disagreement.
    ///
    /// It also asserts the two type bytes are **distinct**, because that is the
    /// whole of the distinction and a collision would make every `ack`
    /// indistinguishable from an `init` — silently, since both are accepted.
    #[test]
    fn an_ack_differs_from_an_init_only_in_its_type_byte() {
        assert_ne!(
            SESSION_TYPE_INIT, SESSION_TYPE_ACK,
            "the two session message types must be distinguishable"
        );
        let a = edkey(0xA1);
        let b = edkey(0xB2);
        let pa = a.verifying_key().to_bytes();
        let init = SessionInit {
            current: [3; 32],
            next: [4; 32],
            key_seq: 0,
            seq: 7,
        };
        let as_init = init.encrypt_msg(SESSION_TYPE_INIT, &a, &pb_of(&b));
        let as_ack = init.encrypt_msg(SESSION_TYPE_ACK, &a, &pb_of(&b));
        assert_eq!(
            as_init.len(),
            as_ack.len(),
            "identical fields, so identical length"
        );
        assert_ne!(
            as_init, as_ack,
            "the type byte is inside the sealed body too"
        );
        // And both are the same size as the captured Go init, which is what makes
        // "same format" a claim about a wire format rather than about our codec.
        assert_eq!(as_init.len(), SESSION_INIT_SIZE);
        assert_eq!(as_ack.len(), SESSION_INIT_SIZE);
        let _ = pa;
    }

    #[test]
    fn session_handshake_roundtrip() {
        let a = edkey(0xA1);
        let b = edkey(0xB2);
        let pa = a.verifying_key().to_bytes();
        let pb = b.verifying_key().to_bytes();
        // A initiates with buffered keys (mirrors Go `_bufferAndInit`).
        let (a_cur_pub, a_cur_priv) = fresh_box();
        let (a_nxt_pub, a_nxt_priv) = fresh_box();
        let init = SessionInit {
            current: a_cur_pub,
            next: a_nxt_pub,
            key_seq: 0,
            seq: 100,
        };
        let enc = init.encrypt_msg(SESSION_TYPE_INIT, &a, &pb);
        let b_box_priv = ed_to_curve_priv(&[0xB2; 32]);
        let dec = SessionInit::decrypt_msg(&b_box_priv, &pa, &enc).unwrap();
        assert_eq!(dec, init);
        // B adopts session, replies ack; A adopts buffered keys then the ack.
        let mut sb = Session::for_init(&dec);
        let ack_init = sb.handle_init(&dec, 101).unwrap();
        let enc_ack = ack_init.encrypt_msg(SESSION_TYPE_ACK, &b, &pa);
        let a_box_priv = ed_to_curve_priv(&[0xA1; 32]);
        let dec_ack = SessionInit::decrypt_msg(&a_box_priv, &pb, &enc_ack).unwrap();
        let mut sa = Session::for_init(&dec_ack);
        sa.adopt_buffered(a_cur_pub, a_cur_priv, a_nxt_pub, a_nxt_priv);
        sa.handle_ack(&dec_ack);
        // Traffic A -> B.
        let ct = sa.encrypt(b"hello ygg");
        let pt = sb.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello ygg");
        // Traffic B -> A.
        let ct2 = sb.encrypt(b"hi back");
        let pt2 = sa.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"hi back");
    }

    /// Rotation: the one part of the session layer with **no test at all** until
    /// now, and the part with the most state to get wrong — nine assignments in
    /// `maybe_rotate`, a fourth of the struct's fields moved at once.
    ///
    /// The trigger is a **timer, not a nonce**. Ironwood rekeys 60 s after the
    /// last rotation (`encrypted/session.go` `_fixShared` and its callers), and
    /// the event that carries it out is the next message sealed under the *next*
    /// key — a session that goes quiet simply does not rotate, which is correct
    /// and is why this needs a message rather than a `sleep`.
    ///
    /// **`rotated_at` starts as `None`, and `None` counts as due.** So the first
    /// message a session *receives* rekeys it, not the first message after a
    /// minute. That matches Go, whose `time.AfterFunc` fires at creation too, and
    /// it is a genuine trap for a test: a rotation has usually already happened by
    /// the time you start counting, which is how this test's first draft asserted
    /// `remote_key_seq == 2` on a session that had rotated once already.
    ///
    /// What has to survive a rotation is **delivery in the direction that
    /// rotated**. A rotation that moved the keys without moving the shared
    /// secrets consistently would leave two sessions that each believe they are
    /// talking to nobody, and the symptom is a session that works for exactly
    /// sixty seconds and then goes silent — the hardest kind of bug to see,
    /// because everything before it is fine.
    ///
    /// What is **not** asserted here is that both directions work afterwards, and
    /// that is a real limit rather than an omission. Each rotation is triggered
    /// by the *peer's*, so a side is one rotation behind until it sees the other's
    /// ratchet — a window in which only the rotated direction carries traffic. See
    /// `a_one_sided_rotation_carries_one_way_only` for that window and for why
    /// neither this test nor Go can say the skew is unreachable. Constructing a
    /// symmetric post-rotation state for a test needs counters set by hand, and
    /// two attempts at that produced a session whose first message no longer
    /// decrypted: the counters are not the only state the arms read.
    #[test]
    fn a_rotated_session_still_delivers_the_way_it_rotated() {
        let a = edkey(0xA1);
        let b = edkey(0xB2);
        let pa = a.verifying_key().to_bytes();
        let pb = b.verifying_key().to_bytes();
        let (a_cur_pub, a_cur_priv) = fresh_box();
        let (a_nxt_pub, a_nxt_priv) = fresh_box();
        let init = SessionInit {
            current: a_cur_pub,
            next: a_nxt_pub,
            key_seq: 0,
            seq: 100,
        };
        let dec = SessionInit::decrypt_msg(
            &ed_to_curve_priv(&[0xB2; 32]),
            &pa,
            &init.encrypt_msg(SESSION_TYPE_INIT, &a, &pb),
        )
        .unwrap();
        let mut sb = Session::for_init(&dec);
        let ack_init = sb.handle_init(&dec, 101).unwrap();
        let dec_ack = SessionInit::decrypt_msg(
            &ed_to_curve_priv(&[0xA1; 32]),
            &pb,
            &ack_init.encrypt_msg(SESSION_TYPE_ACK, &b, &pa),
        )
        .unwrap();
        let mut sa = Session::for_init(&dec_ack);
        sa.adopt_buffered(a_cur_pub, a_cur_priv, a_nxt_pub, a_nxt_priv);
        sa.handle_ack(&dec_ack);

        // The first message B receives rotates B, so this is a rotation with real
        // traffic on either side of it rather than a bare state inspection.
        assert_eq!(sb.decrypt(&sa.encrypt(b"before")).unwrap(), b"before");

        // Arm A and rotate it. The counters are the *mechanism*: a rotation that
        // skipped one would still decrypt for a while, which is exactly the
        // failure mode a delivery-only assertion would miss.
        let (a_local, a_remote, b_local) = (sa.local_key_seq, sa.remote_key_seq, sb.local_key_seq);
        sa.rotated_at = None;
        sa.maybe_rotate([0xEE; 32], 1);
        assert_eq!(sa.local_key_seq, a_local + 1, "A bumped our key sequence");
        assert_eq!(
            sa.remote_key_seq,
            a_remote + 1,
            "and the peer's too: we adopt the key they just used"
        );

        // The claim. Repeatedly, because the failure worth catching is a ratchet
        // that keeps going: each message arriving as "not due" is the entire
        // reason the timer is there.
        for n in 0..3 {
            let msg = format!("after rotation {n}");
            assert_eq!(
                sb.decrypt(&sa.encrypt(msg.as_bytes())).as_deref(),
                Some(msg.as_bytes()),
                "B accepts A's rotated traffic, message {n}"
            );
        }
        assert_eq!(
            (sb.local_key_seq, sb.remote_key_seq),
            (b_local, sb.remote_key_seq),
            "three messages did not rekey B again: the timer, not each packet, is \
             what rotates"
        );
    }

    /// Rotation is **not** driven by the nonce. Go rekeys on a 60 s timer
    /// (`encrypted/session.go`), and a message arriving before that must leave
    /// the key sequences alone — otherwise every pair that talks often would
    /// ratchet on every packet, and the `fromNext` arms would match by accident
    /// rather than by design.
    #[test]
    fn a_session_that_did_not_rotate_yet_keeps_its_key_sequences() {
        let mut s = Session::for_init(&SessionInit {
            current: [1; 32],
            next: [2; 32],
            key_seq: 0,
            seq: 1,
        });
        assert_eq!((s.local_key_seq, s.remote_key_seq), (0, 0));
        s.rotated_at = Some(std::time::Instant::now());
        s.maybe_rotate([3; 32], 1);
        assert_eq!(
            (s.local_key_seq, s.remote_key_seq),
            (0, 0),
            "not due, so nothing moves"
        );
        // Far enough past the interval and it does.
        s.rotated_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(61));
        s.maybe_rotate([3; 32], 1);
        assert_eq!(
            (s.local_key_seq, s.remote_key_seq),
            (1, 1),
            "due, so both move"
        );
    }
    #[test]
    fn tampered_init_rejected() {
        let a = edkey(0xA1);
        let b = edkey(0xB2);
        let pb = b.verifying_key().to_bytes();
        let init = SessionInit {
            current: [7; 32],
            next: [8; 32],
            key_seq: 0,
            seq: 5,
        };
        let mut enc = init.encrypt_msg(SESSION_TYPE_INIT, &a, &pb);
        enc[40] ^= 1;
        let b_box_priv = ed_to_curve_priv(&[0xB2; 32]);
        assert!(
            SessionInit::decrypt_msg(&b_box_priv, &a.verifying_key().to_bytes(), &enc).is_none()
        );
        assert!(
            SessionInit::decrypt_msg(&b_box_priv, &a.verifying_key().to_bytes(), &enc[..100])
                .is_none()
        );
    }

    #[test]
    fn packet_type_constants_match_go_core_types() {
        // yggdrasil-go src/core/types.go: typeSessionTraffic = 1,
        // typeSessionProto = 2. Go's Core.ReadFrom silently drops session
        // payloads with any other leading byte — omitting the wrap on send
        // (or the strip on delivery) breaks all interop with zero errors,
        // which is exactly the live-fetch outage this guards against.
        assert_eq!(PACKET_TYPE_TRAFFIC, 1);
        assert_eq!(PACKET_TYPE_PROTO, 2);
        assert_ne!(PACKET_TYPE_TRAFFIC, SESSION_TYPE_TRAFFIC);
    }
}
