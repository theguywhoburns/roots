//! Link transports. New protocols are compile-time primitives: implement
//! [`Transport`] for the stream type and reuse [`run_handshake`].
//!
//! URI forms (mirroring Go peer URIs):
//! `tcp://host:port[?...]`, `tls://host:port[?...]`,
//! `ws://host:port[?...]` and `wss://host:port[?...]`, where `?...` is
//! `password=..&priority=..&key=<hex pubkey>&sni=<override>`.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{self, FRAME_KINDS, FrameType, MAX_MESSAGE_SIZE};
use crate::handshake::{HEADER_LEN, Meta};

/// Timeout for the TCP connect itself (Go: 5s).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline for the whole `meta` exchange after connect (Go: 6s).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
/// Timeout for the TLS handshake inside a TLS dial (own budget on top).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default reconnect cap (Go `defaultBackoffLimit`: 1s << 12).
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(1 << 12);
/// Minimum accepted `?maxbackoff=` (Go `minimumBackoffLimit`).
pub const MIN_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Reconnect delay after `failures` consecutive errors (already incremented,
/// mirroring Go's `backoffNow`): `1s << failures`, capped at `max_backoff`.
/// First failure waits 2s.
pub fn backoff_delay(failures: u32, max_backoff: Duration) -> Duration {
    let shift = failures.min(32);
    Duration::from_secs(1u64 << shift).min(max_backoff)
}

/// Parse a Go-style duration (`300ms`, `5s`, `2m`, `1h30m`; integer values).
/// Used for `?maxbackoff=`.
pub fn parse_go_duration(s: &str) -> Result<Duration, Error> {
    if s.is_empty() {
        return Err(Error::BadUri(s.to_string()));
    }
    let mut total_ms: u128 = 0;
    let mut rest = s;
    let mut parsed_any = false;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(Error::BadUri(s.to_string()));
        }
        let n: u128 = rest[..digits]
            .parse()
            .map_err(|_| Error::BadUri(s.to_string()))?;
        rest = &rest[digits..];
        let unit_end = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
        if unit_end == 0 {
            return Err(Error::BadUri(s.to_string()));
        }
        let mult: u128 = match &rest[..unit_end] {
            "ns" => 1,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(Error::BadUri(s.to_string())),
        };
        total_ms += n * mult / 1_000_000;
        rest = &rest[unit_end..];
        parsed_any = true;
    }
    if !parsed_any {
        return Err(Error::BadUri(s.to_string()));
    }
    Ok(Duration::from_millis(total_ms.min(u64::MAX as u128) as u64))
}

/// A link transport. The associated [`Transport::Stream`] is what
/// [`run_handshake`] runs the `meta` exchange over.
pub trait Transport {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn dial(
        addr: &str,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Error>> + Send;
}

/// Byte stream usable as a link wire: one trait so links of different
/// transports (`Tcp`, `Tls`, `Ws`) erase to a single type.
pub trait LinkStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> LinkStream for T {}

/// Boxed frame read/write futures returned by [`Link`] (kept behind
/// aliases so the trait stays under clippy's type-complexity limit).
pub type LinkRead<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(FrameType, Vec<u8>), Error>> + Send + 'a>,
>;
pub type LinkWrite<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + 'a>>;

/// One open link as the router sees it: framed reads/writes without
/// naming the transport. `PeerConn<T>` implements this for every
/// transport, and [`AnyConn`] type-erases the stream, so a single
/// `Router` can drive mixed-transport links through `&mut dyn Link`
/// (the precondition for the multi-peer connection map).
pub trait Link: Send {
    /// Link priority from the handshake (lowest wins among same-key links).
    fn priority(&self) -> u8;
    /// Remote node key from the handshake.
    fn remote_key(&self) -> [u8; KEY_LEN];
    /// Which implementation the peer runs (vendor-tag based; defaults to
    /// Go for hand-rolled test links).
    fn peer_kind(&self) -> crate::peer::PeerKind {
        crate::peer::PeerKind::Go
    }
    fn read_frame<'a>(&'a mut self) -> LinkRead<'a>;
    fn write_frame<'a>(&'a mut self, ftype: FrameType, payload: &'a [u8]) -> LinkWrite<'a>;
}

impl<T: Transport> Link for PeerConn<T> {
    fn priority(&self) -> u8 {
        self.priority
    }

    fn remote_key(&self) -> [u8; KEY_LEN] {
        self.remote_key
    }

    fn peer_kind(&self) -> crate::peer::PeerKind {
        self.kind.clone()
    }

    fn read_frame<'a>(&'a mut self) -> LinkRead<'a> {
        Box::pin(async move { PeerConn::read_frame(self).await })
    }

    fn write_frame<'a>(&'a mut self, ftype: FrameType, payload: &'a [u8]) -> LinkWrite<'a> {
        Box::pin(async move { PeerConn::write_frame(self, ftype, payload).await })
    }
}

/// Identity of one completed connection, minted where the connection is built.
///
/// Go joins a `getPeers` row to its router state by `net.Conn` pointer
/// (`core/api.go:73-103`: a `map[net.Conn]DebugPeerInfo`), so a row knows
/// *which* link it is describing, not merely which node it reaches. An index
/// into the set would move when a link is removed, so this is a counter: one
/// number per connection, never reused, which stops matching the moment the
/// link it names is displaced or evicted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(u64);

static NEXT_LINK_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl LinkId {
    fn next() -> Self {
        Self(NEXT_LINK_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// An id no link will ever be given, for a caller that needs to ask about a
    /// link that is not there — "is this id still live", "what happens if I
    /// write to a link that died". A production caller has a real id and should
    /// use it; this exists so the question can be put, and so a test can build
    /// the stale case without reaching for a real socket.
    pub fn absent() -> Self {
        Self::next()
    }
}

/// Type-erased authenticated peer connection: same shape as
/// [`PeerConn`], but the stream is boxed, so links of different
/// transports share one concrete type.
pub struct AnyConn {
    pub remote_key: [u8; KEY_LEN],
    pub priority: u8,
    pub kind: crate::peer::PeerKind,
    /// Which way the socket came up (dial = outbound, accept = inbound);
    /// `getPeers` reports it, so it must survive type erasure.
    pub inbound: bool,
    /// Which connection this is, for as long as it lasts ([`LinkId`]).
    pub id: LinkId,
    /// [`PeerConn::remote_addr`], kept so the client can name an inbound link
    /// the way Go's admin socket does without the concrete transport in hand.
    pub remote_addr: Option<String>,
    pub stream: Box<dyn LinkStream>,
}

impl AnyConn {
    pub fn new<T: Transport>(conn: PeerConn<T>) -> Self {
        Self {
            remote_key: conn.remote_key,
            priority: conn.priority,
            kind: conn.kind,
            inbound: conn.inbound,
            id: LinkId::next(),
            remote_addr: conn.remote_addr,
            stream: Box::new(conn.stream),
        }
    }
}

/// The stream box has nothing to print, so this reports what the link *is*:
/// enough to tell one peer's link from another's in a test failure.
impl std::fmt::Debug for AnyConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyConn")
            .field("remote_key", &hex::encode(self.remote_key))
            .field("priority", &self.priority)
            .field("inbound", &self.inbound)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Link for AnyConn {
    fn priority(&self) -> u8 {
        self.priority
    }

    fn remote_key(&self) -> [u8; KEY_LEN] {
        self.remote_key
    }

    fn peer_kind(&self) -> crate::peer::PeerKind {
        self.kind.clone()
    }

    fn read_frame<'a>(&'a mut self) -> LinkRead<'a> {
        Box::pin(async move { read_frame_from(&mut self.stream).await })
    }

    fn write_frame<'a>(&'a mut self, ftype: FrameType, payload: &'a [u8]) -> LinkWrite<'a> {
        Box::pin(async move { write_frame_to(&mut self.stream, ftype, payload).await })
    }
}

/// One link the set owns: the conn plus what the set measures about it.
///
/// Several entries may share a `peer` key. That is ironwood's shape
/// (`peers.go:32`, `map[publicKey]map[*peer]struct{}`) and what lets a peering
/// that both sides dialled settle instead of trading closures.
struct LinkEntry {
    peer: [u8; KEY_LEN],
    link: AnyConn,
    up: std::time::Instant,
    rx: u64,
    tx: u64,
    /// Counters as of the last rate sample, which is what makes a rate a
    /// measurement rather than a division by an elapsed time.
    lastrx: u64,
    lasttx: u64,
    rxrate: u64,
    txrate: u64,
}

/// What the set measures about one live link. This is the source for
/// `getPeers`' `uptime`, `bytes_recvd`/`bytes_sent`, `rate_recvd`/`rate_sent`
/// and `inbound`.
#[derive(Clone, Copy, Debug)]
pub struct LinkStats {
    pub up: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Bytes in the last whole sample window, as Go's `_updateAverages`
    /// measures them — a difference of counters, not a smoothed average.
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub inbound: bool,
}

/// Go's rate window (`link.go:127` `time.AfterFunc(time.Second, …)`): one tick
/// for every link at once, and a rate is simply the bytes since that tick.
const RATE_WINDOW: Duration = Duration::from_secs(1);

/// The multi-peer connection map: **one entry per link**, with several
/// entries allowed to share a node key. The set **owns** its links, so it is
/// `'static` and a caller can keep it across await points or hand it to a
/// queue; all router I/O goes through this, so mixed transports share one code
/// path and every byte is counted.
///
/// Several links per key is ironwood's shape, and it is what makes a peering
/// dialled both ways settle. One slot per key made `add` displace the
/// incumbent and the node drop what came back, so each side closed the other's
/// connection, redialled, and repeated forever. Go does not flap here: its link
/// map is keyed by URI (`core/link.go:43-44`) and its router keeps both peers.
///
/// A [`LinkId`] therefore names a link and a node key no longer does, so every
/// method that touches one link takes the id.
///
/// Three send calls, deliberately different (Gate 2's silent-failure audit):
/// [`LinkSet::write`] is hard and reaches one link the caller is serving, so a
/// missing entry is a bug and says so. [`LinkSet::write_all`] is hard and
/// reaches **every** link to a key, which is what Go's per-key sends do
/// (`for p := range r.peers[peerKey]`, `router.go:373`). [`LinkSet::write_via`]
/// is soft: a next hop the pathfinder picked may have no link, which Go drops
/// silently, and we report it so the caller can count it.
#[derive(Default)]
pub struct LinkSet {
    entries: Vec<LinkEntry>,
    last_write: std::collections::HashMap<LinkId, std::time::Instant>,
    /// When the byte rates were last differenced. Go keeps this in the actor's
    /// own timer; we are called from the node's tick, so the set carries the
    /// phase and a caller may call as often as it likes.
    sampled_at: Option<std::time::Instant>,
}

impl LinkSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap a single link (single-peer callers).
    pub fn single(conn: AnyConn) -> Self {
        let mut set = Self::default();
        set.add(conn);
        set
    }

    /// Add a link, returning its [`LinkId`] — the handle every other method
    /// takes. Nothing is displaced: a second link to a peer the set already
    /// holds is a separate connection Go would keep, so keeping it is what
    /// stops the crossed-peering flap.
    pub fn add(&mut self, conn: AnyConn) -> LinkId {
        let peer = conn.remote_key;
        let id = conn.id;
        let now = std::time::Instant::now();
        self.last_write.entry(id).or_insert(now);
        self.entries.push(LinkEntry {
            peer,
            link: conn,
            up: now,
            rx: 0,
            tx: 0,
            lastrx: 0,
            lasttx: 0,
            rxrate: 0,
            txrate: 0,
        });
        id
    }

    /// Every live link's id, in insertion order. The driver reads and keeps
    /// alive one link at a time, so this is the set's unit of work.
    pub fn ids(&self) -> Vec<LinkId> {
        self.entries.iter().map(|e| e.link.id).collect()
    }

    /// Distinct peer keys, each once, in first-seen order. This is the node-key
    /// view: per-key state (a tree peer, a bloom filter) belongs to the key
    /// while the links behind it are separate.
    pub fn peers(&self) -> Vec<[u8; KEY_LEN]> {
        let mut out: Vec<[u8; KEY_LEN]> = Vec::new();
        for e in &self.entries {
            if !out.contains(&e.peer) {
                out.push(e.peer);
            }
        }
        out
    }

    /// Every link to one node key, in insertion order.
    pub fn links_to(&self, peer: &[u8; KEY_LEN]) -> Vec<LinkId> {
        self.entries
            .iter()
            .filter(|e| &e.peer == peer)
            .map(|e| e.link.id)
            .collect()
    }

    /// The node key behind a link, for a caller holding only an id.
    pub fn peer_of(&self, id: LinkId) -> Option<[u8; KEY_LEN]> {
        self.entries
            .iter()
            .find(|e| e.link.id == id)
            .map(|e| e.peer)
    }

    /// True when at least one link to this key is up. Go's `r.peers[parent]`
    /// existence test, which asks about a node rather than a connection.
    pub fn has_peer(&self, peer: &[u8; KEY_LEN]) -> bool {
        self.entries.iter().any(|e| &e.peer == peer)
    }

    /// Direct access to one link, for I/O the set itself does not mediate.
    pub fn get(&mut self, id: LinkId) -> Option<&mut AnyConn> {
        self.entries
            .iter_mut()
            .find(|e| e.link.id == id)
            .map(|e| &mut e.link)
    }

    /// Take one link out of the set (dead links, or handing ownership back to
    /// the caller). Send clocks for remaining links are untouched.
    pub fn remove(&mut self, id: LinkId) -> Option<AnyConn> {
        let at = self.entries.iter().position(|e| e.link.id == id)?;
        Some(self.entries.remove(at).link)
    }

    /// True when no links remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Counters for one identified link, or `None` once that connection is no
    /// longer live. Keyed by [`LinkId`] because two links to one node are two
    /// entries: a caller asking by key would get the other link's direction and
    /// counters, which is how Slice 7 came to report an accepted link's
    /// `inbound: true` against a dial URI.
    pub fn stats(&self, id: LinkId) -> Option<LinkStats> {
        self.entries
            .iter()
            .find(|e| e.link.id == id)
            .map(|e| LinkStats {
                up: e.up.elapsed(),
                rx_bytes: e.rx,
                tx_bytes: e.tx,
                rx_rate: e.rxrate,
                tx_rate: e.txrate,
                inbound: e.link.inbound,
            })
    }

    /// Difference every link's counters, once per [`RATE_WINDOW`] — Go's
    /// `_updateAverages` (`link.go:106-129`), which walks all links on one
    /// timer and stores the delta outright. So a link that came up partway
    /// through a window reports everything it has moved so far as its first
    /// rate, and a quiet link reports exactly zero rather than a small average.
    pub fn update_rates(&mut self) {
        let now = std::time::Instant::now();
        let due = self
            .sampled_at
            .map(|t| now.duration_since(t) >= RATE_WINDOW)
            .unwrap_or(true);
        if !due {
            return;
        }
        self.sampled_at = Some(now);
        for e in &mut self.entries {
            e.rxrate = e.rx - e.lastrx;
            e.txrate = e.tx - e.lasttx;
            e.lastrx = e.rx;
            e.lasttx = e.tx;
        }
    }

    /// Hard send to one link the caller is serving. A missing entry is
    /// [`Error::NoLink`] rather than a silent drop. Stamps the send time, which
    /// drives Go-style lazy keepalives: a keepalive goes out only after a full
    /// idle tick with no sends.
    pub async fn write(
        &mut self,
        target: LinkId,
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<(), Error> {
        if self.send(target, ftype, payload).await? {
            Ok(())
        } else {
            Err(Error::NoLink)
        }
    }

    /// Hard send to **every** link to a node key, because that is what Go's
    /// per-key sends do: announces fan out over `r.peers[peerKey]`
    /// (`router.go:373`) and `SigReq` over `r.peers[pk]` (`router.go:193`).
    /// A key with no live link is [`Error::NoLink`].
    pub async fn write_all(
        &mut self,
        peer: [u8; KEY_LEN],
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<(), Error> {
        let targets = self.links_to(&peer);
        if targets.is_empty() {
            return Err(Error::NoLink);
        }
        for id in targets {
            self.write(id, ftype, payload).await?;
        }
        Ok(())
    }

    /// Soft send to a next hop we may have no link for: `Ok(false)` means the
    /// link is gone and the frame was discarded. The caller counts it
    /// (`Router::dropped_no_link`), because a drop nobody can see is the bug
    /// this split exists to fix.
    pub async fn write_via(
        &mut self,
        target: LinkId,
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<bool, Error> {
        self.send(target, ftype, payload).await
    }

    async fn send(
        &mut self,
        target: LinkId,
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<bool, Error> {
        let Some(at) = self.entries.iter().position(|e| e.link.id == target) else {
            return Ok(false);
        };
        match self.entries[at].link.write_frame(ftype, payload).await {
            Ok(()) => {
                self.entries[at].tx += frame::wire_len(payload.len());
                self.last_write.insert(target, std::time::Instant::now());
                Ok(true)
            }
            // A socket that refuses a frame is gone: retire the link here so
            // nothing addresses it again. Go discards write errors outright
            // (`peers.go:189` `_, _ = w.wbuf.Write(bs)`, `pop()` ignores
            // `Flush`) and lets that peer's own read goroutine tear it down;
            // keeping the dead link in the set would let one failed write
            // poison every later send in the serve.
            Err(e) => {
                self.entries.remove(at);
                Err(e)
            }
        }
    }

    /// The set's only read path, so `rx` cannot be bypassed. Times out and
    /// errors exactly like [`Link::read_frame`] on the inner link; no entry for
    /// `id` is [`Error::NoLink`].
    pub async fn read_frame(&mut self, id: LinkId) -> Result<(FrameType, Vec<u8>), Error> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.link.id == id)
            .ok_or(Error::NoLink)?;
        let (ftype, payload) = entry.link.read_frame().await?;
        entry.rx += frame::wire_len(payload.len());
        Ok((ftype, payload))
    }

    /// Time since the last frame sent to one link (zero for unknown links).
    pub fn idle_for(&self, id: LinkId) -> Duration {
        self.last_write
            .get(&id)
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

/// Plain TCP transport.
pub struct Tcp;

impl Transport for Tcp {
    type Stream = TcpStream;

    async fn dial(addr: &str, timeout: Duration) -> Result<TcpStream, Error> {
        tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)
    }
}

/// Authenticated peer connection returned by [`dial`] / [`accept`].
pub struct PeerConn<T: Transport = Tcp> {
    pub remote_key: [u8; KEY_LEN],
    pub priority: u8,
    pub kind: crate::peer::PeerKind,
    /// Set by [`complete_accept`], cleared by [`complete_dial`]: which way the
    /// socket came up.
    pub inbound: bool,
    /// Where the accepted socket came from, as Go prints it
    /// (`net.TCPAddr.String()`: an IPv6 address bracketed). Go keeps this only
    /// to build the admin URI — "In order to populate a somewhat sane looking
    /// connection URI in the admin socket, we need to replace the host in the
    /// listener URL with the remote address" (`link.go:514-518`) — and a dial
    /// never needs it, because its row is named by the URI that was dialled.
    pub remote_addr: Option<String>,
    pub stream: T::Stream,
}

#[derive(Debug, Clone, Default)]
pub struct LinkOptions {
    /// Per-peer password (max 64B). Empty == no password.
    pub password: Vec<u8>,
    pub priority: u8,
    /// If set, reject peers whose key differs.
    pub pinned_key: Option<[u8; KEY_LEN]>,
    /// If non-empty, reject inbound peers not on the list.
    pub allowed_keys: Vec<[u8; KEY_LEN]>,
}

/// Parsed peer URI (any scheme; see [`Scheme`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerUri {
    pub host_port: String,
    pub password: Vec<u8>,
    pub priority: u8,
    pub pinned_key: Option<[u8; KEY_LEN]>,
    /// TLS SNI override (`?sni=`); defaults to the authority host.
    pub sni: Option<String>,
    /// Reconnect cap (`?maxbackoff=`, Go duration); defaults apply when unset.
    pub max_backoff: Option<Duration>,
}

/// Link schemes with distinct wire transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Tcp,
    Tls,
    Ws,
    Wss,
    Quic,
}

/// Parse a `tcp://`, `tls://`, `ws://`, `wss://` or `quic://` peer URI.
///
/// The option refusals are Go's, in Go's order (`links.add`, `link.go:175-218`):
/// an unknown scheme, a bad `?key=`, a bad `?priority=`, an oversize
/// `?password=` (over `blake2b.Size`) and a bad `?maxbackoff=`. Each carries
/// Go's verbatim message because the admin socket quotes it back.
pub fn parse_link_uri(uri: &str) -> Result<(Scheme, PeerUri), Error> {
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("tcp://") {
        (Scheme::Tcp, r)
    } else if let Some(r) = uri.strip_prefix("tls://") {
        (Scheme::Tls, r)
    } else if let Some(r) = uri.strip_prefix("ws://") {
        (Scheme::Ws, r)
    } else if let Some(r) = uri.strip_prefix("wss://") {
        (Scheme::Wss, r)
    } else if let Some(r) = uri.strip_prefix("quic://") {
        (Scheme::Quic, r)
    } else {
        return Err(Error::UnrecognisedSchema);
    };
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(Error::BadUri(uri.to_string()));
    }
    let mut out = PeerUri {
        host_port: authority.to_string(),
        password: Vec::new(),
        priority: 0,
        pinned_key: None,
        sni: None,
        max_backoff: None,
    };
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "password" => {
                if v.len() > crate::handshake::MAX_PASSWORD_LEN {
                    return Err(Error::PasswordInvalid);
                }
                out.password = v.as_bytes().to_vec();
            }
            "priority" => {
                out.priority = v.parse::<u8>().map_err(|_| Error::PriorityInvalid)?;
            }
            "key" => {
                let raw = hex::decode(v).map_err(|_| Error::PinnedKeyInvalid)?;
                if raw.len() != KEY_LEN {
                    return Err(Error::PinnedKeyInvalid);
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&raw);
                out.pinned_key = Some(key);
            }
            "sni" => out.sni = Some(v.to_string()),
            "maxbackoff" => {
                let d = parse_go_duration(v).map_err(|_| Error::MaxBackoffInvalid)?;
                if d < MIN_MAX_BACKOFF {
                    return Err(Error::MaxBackoffInvalid);
                }
                out.max_backoff = Some(d);
            }
            _ => {}
        }
    }
    Ok((scheme, out))
}

/// Parse a `tcp://` peer URI (rejects other schemes).
pub fn parse_peer_uri(uri: &str) -> Result<PeerUri, Error> {
    match parse_link_uri(uri)? {
        (Scheme::Tcp, peer) => Ok(peer),
        _ => Err(Error::BadUri(uri.to_string())),
    }
}

/// Run the `meta` exchange over any stream. `is_inbound` gates the allowlist
/// check (Go skips it for link-local/multicast peers). Returns the peer key,
/// negotiated priority, and the peer implementation kind (vendor-tag based;
/// absent vendor means Go).
pub async fn run_handshake<S>(
    stream: &mut S,
    local: &SigningKey,
    opts: &LinkOptions,
    is_inbound: bool,
) -> Result<([u8; KEY_LEN], u8, crate::peer::PeerKind), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let local_key = local.verifying_key().to_bytes();
    let ours = Meta::local(&local_key, opts.priority).encode(local, &opts.password)?;
    stream.write_all(&ours).await?;
    stream.flush().await?;

    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    if &header[..4] != b"meta" {
        return Err(Error::InvalidPreamble);
    }
    let body_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let mut msg = vec![0u8; HEADER_LEN + body_len];
    msg[..HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut msg[HEADER_LEN..])
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::InvalidLength
            } else {
                Error::Io(e)
            }
        })?;

    let theirs = Meta::decode(&msg, &opts.password)?;
    theirs.check()?;
    if theirs.public_key == local_key {
        return Err(Error::SelfDial);
    }
    if let Some(pin) = opts.pinned_key
        && pin != theirs.public_key
    {
        return Err(Error::PinnedMismatch);
    }
    if is_inbound
        && !opts.allowed_keys.is_empty()
        && !opts.allowed_keys.contains(&theirs.public_key)
    {
        return Err(Error::KeyNotAllowed);
    }
    Ok((
        theirs.public_key,
        theirs.priority.max(opts.priority),
        theirs.peer_kind(),
    ))
}

/// Bind a `tcp://host:port` listener. Query strings are ignored except that
/// `accept` will use `opts` (same password/priority/allowlist as dial).
pub async fn listen(uri: &str) -> Result<tokio::net::TcpListener, Error> {
    let peer = parse_peer_uri(uri)?;
    tokio::net::TcpListener::bind(&peer.host_port)
        .await
        .map_err(Error::Io)
}

/// Accept one inbound peer and complete the handshake as responder.
pub async fn accept(
    listener: &tokio::net::TcpListener,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Tcp>, Error> {
    let (stream, addr) = listener.accept().await.map_err(Error::Io)?;
    complete_accept(stream, local, opts, Some(addr.to_string())).await
}

/// Per-type frame counters from a [`PeerConn::run`] session.
#[derive(Debug, Default)]
pub struct RunStats {
    pub frames: [u64; FRAME_KINDS],
    pub keepalives_sent: u64,
    pub payload_bytes: u64,
}

/// Read one framed body (type + payload) after the length prefix, over
/// any byte stream. Shared by [`PeerConn`] and [`AnyConn`].
pub async fn read_frame_from<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(FrameType, Vec<u8>), Error> {
    let mut prefix = Vec::with_capacity(10);
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        prefix.push(b[0]);
        if b[0] < 0x80 {
            break;
        }
        if prefix.len() >= 10 {
            return Err(Error::InvalidLength);
        }
    }
    let (len, _) = frame::read_uvarint(&prefix).ok_or(Error::InvalidLength)?;
    if len == 0 || len as usize > MAX_MESSAGE_SIZE {
        return Err(Error::InvalidLength);
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::InvalidLength
        } else {
            Error::Io(e)
        }
    })?;
    let (ftype, payload) = frame::decode_body(&body)?;
    Ok((ftype, payload.to_vec()))
}

/// Write one framed body over any byte stream.
pub async fn write_frame_to<S: AsyncWrite + Unpin>(
    stream: &mut S,
    ftype: FrameType,
    payload: &[u8],
) -> Result<(), Error> {
    let enc = frame::encode_frame(ftype, payload);
    stream.write_all(&enc).await?;
    stream.flush().await?;
    Ok(())
}

impl<T: Transport> PeerConn<T> {
    /// Read one framed body (type + payload) after the length prefix.
    pub async fn read_frame(&mut self) -> Result<(FrameType, Vec<u8>), Error> {
        read_frame_from(&mut self.stream).await
    }

    pub async fn write_frame(&mut self, ftype: FrameType, payload: &[u8]) -> Result<(), Error> {
        write_frame_to(&mut self.stream, ftype, payload).await
    }

    /// Serve the link until `hold_for` elapses: reply keepalive to every
    /// non-keepalive frame (mirrors Go's `peerMonitor`), count by type.
    pub async fn run(&mut self, hold_for: Duration) -> Result<RunStats, Error> {
        let end = tokio::time::Instant::now() + hold_for;
        let mut stats = RunStats::default();
        loop {
            let remaining = end.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (ftype, payload) = match tokio::time::timeout(remaining, self.read_frame()).await {
                Ok(r) => r?,
                Err(_) => break,
            };
            stats.frames[ftype as usize] += 1;
            stats.payload_bytes += payload.len() as u64;
            match ftype {
                FrameType::KeepAlive | FrameType::Dummy => {}
                _ => {
                    self.write_frame(FrameType::KeepAlive, &[]).await?;
                    stats.keepalives_sent += 1;
                }
            }
        }
        Ok(stats)
    }
}

/// Dial a `tcp://` peer and complete the handshake.
pub async fn dial(
    uri: &str,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Tcp>, Error> {
    let peer = parse_peer_uri(uri)?;
    let stream = tokio::time::timeout(DIAL_TIMEOUT, Tcp::dial(&peer.host_port, DIAL_TIMEOUT))
        .await
        .map_err(|_| Error::Timeout)??;
    complete_dial(stream, &peer, local, opts).await
}

/// Merge URI query options over the configured defaults (Go `links.add`).
pub(crate) fn merge_opts(peer: &PeerUri, opts: &LinkOptions) -> LinkOptions {
    LinkOptions {
        password: if peer.password.is_empty() {
            opts.password.clone()
        } else {
            peer.password.clone()
        },
        priority: opts.priority.max(peer.priority),
        pinned_key: peer.pinned_key.or(opts.pinned_key),
        allowed_keys: opts.allowed_keys.clone(),
    }
}

/// Transport template: finish a dial from a connected stream. Shared tail
/// for all `*_dial` (merge opts + `meta` handshake + `PeerConn` build), so
/// each transport only supplies stream acquisition.
pub async fn complete_dial<T: Transport>(
    stream: T::Stream,
    peer: &PeerUri,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<T>, Error> {
    let merged = merge_opts(peer, opts);
    let mut stream = stream;
    let (remote_key, priority, kind) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_handshake(&mut stream, local, &merged, false),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(PeerConn {
        remote_key,
        priority,
        kind,
        inbound: false,
        remote_addr: None,
        stream,
    })
}

/// Transport template: finish an accept from an accepted stream. Shared
/// tail for all `*_accept`. `remote_addr` is the peer end of the socket, in
/// Go's text form, which is the only thing that can name an inbound row the
/// way Go's admin socket does (`link.go:514-524`).
pub async fn complete_accept<T: Transport>(
    stream: T::Stream,
    local: &SigningKey,
    opts: &LinkOptions,
    remote_addr: Option<String>,
) -> Result<PeerConn<T>, Error> {
    let mut stream = stream;
    let (remote_key, priority, kind) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_handshake(&mut stream, local, opts, true),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(PeerConn {
        remote_key,
        priority,
        kind,
        inbound: true,
        remote_addr,
        stream,
    })
}

/// Dial any scheme and type-erase to [`AnyConn`]: one `match` on [`Scheme`]
/// instead of the per-callsite `if starts_with` chains this replaces.
pub async fn dial_any(uri: &str, local: &SigningKey, opts: &LinkOptions) -> Result<AnyConn, Error> {
    let (scheme, _) = parse_link_uri(uri)?;
    match scheme {
        Scheme::Tcp => Ok(AnyConn::new(dial(uri, local, opts).await?)),
        Scheme::Tls => Ok(AnyConn::new(crate::tls::tls_dial(uri, local, opts).await?)),
        Scheme::Ws => Ok(AnyConn::new(crate::ws::ws_dial(uri, local, opts).await?)),
        Scheme::Wss => Ok(AnyConn::new(crate::ws::wss_dial(uri, local, opts).await?)),
        Scheme::Quic => Ok(AnyConn::new(
            crate::quic::quic_dial(uri, local, opts).await?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn uri_parsing() {
        let u = parse_peer_uri("tcp://1.2.3.4:1234").unwrap();
        assert_eq!(u.host_port, "1.2.3.4:1234");
        assert_eq!(u.priority, 0);
        assert!(u.pinned_key.is_none());
        let u = parse_peer_uri("tcp://host:99?password=secret&priority=8").unwrap();
        assert_eq!(u.password, b"secret");
        assert_eq!(u.priority, 8);
        let key_hex = "aa".repeat(32);
        let u = parse_peer_uri(&format!("tcp://h:1?key={key_hex}")).unwrap();
        assert_eq!(u.pinned_key, Some([0xaa; KEY_LEN]));
        assert!(parse_peer_uri("tls://h:1").is_err());
        assert!(parse_peer_uri("tcp://").is_err());
    }

    #[test]
    fn uri_option_errors_quote_go_verbatim() {
        // Go's `linkError` constants (`core/link.go:149-157`), checked in
        // `links.add` (`:175-218`), which `addPeer` hands straight to the admin
        // socket's `error` field — so the text is wire-visible, not a log line.
        let refused = |uri: &str| parse_link_uri(uri).unwrap_err().to_string();
        assert_eq!(refused("carrier://h:1"), "link schema unknown");
        assert_eq!(
            refused("tcp://h:1?key=not-hex"),
            "pinned public key is invalid"
        );
        assert_eq!(
            refused(&format!("tcp://h:1?key={}", "aa".repeat(31))),
            "pinned public key is invalid"
        );
        assert_eq!(
            refused("tcp://h:1?priority=256"),
            "priority value is invalid"
        );
        assert_eq!(
            refused(&format!("tcp://h:1?password={}", "x".repeat(65))),
            "invalid password supplied"
        );
        assert_eq!(
            refused("tcp://h:1?maxbackoff=bogus"),
            "max backoff duration invalid"
        );
        assert_eq!(
            refused("tcp://h:1?maxbackoff=1s"),
            "max backoff duration invalid"
        );
        // A 64-byte password is the last one Go accepts (`blake2b.Size`).
        assert!(parse_link_uri(&format!("tcp://h:1?password={}", "x".repeat(64))).is_ok());
    }

    #[test]
    fn backoff_matches_go() {
        let max = DEFAULT_MAX_BACKOFF;
        // Counter increments first: first failure waits 2s, then 4, 8...
        assert_eq!(backoff_delay(1, max), Duration::from_secs(2));
        assert_eq!(backoff_delay(2, max), Duration::from_secs(4));
        assert_eq!(backoff_delay(3, max), Duration::from_secs(8));
        assert_eq!(backoff_delay(12, max), Duration::from_secs(1 << 12));
        // Capped at max_backoff, counter saturates without overflow.
        assert_eq!(
            backoff_delay(20, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(backoff_delay(32, max), max);
        assert_eq!(backoff_delay(u32::MAX, max), max);
    }

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(
            parse_go_duration("300ms").unwrap(),
            Duration::from_millis(300)
        );
        assert_eq!(parse_go_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(
            parse_go_duration("1h30m").unwrap(),
            Duration::from_secs(5400)
        );
        assert!(parse_go_duration("").is_err());
        assert!(parse_go_duration("5").is_err());
        assert!(parse_go_duration("5x").is_err());
        assert!(parse_go_duration("abc").is_err());
    }

    #[test]
    fn maxbackoff_uri() {
        let (_, p) = parse_link_uri("tcp://h:1?maxbackoff=30s").unwrap();
        assert_eq!(p.max_backoff, Some(Duration::from_secs(30)));
        // Below Go's 5s minimum is rejected, like `ErrLinkMaxBackoffInvalid`.
        assert!(parse_link_uri("tcp://h:1?maxbackoff=1s").is_err());
        assert!(parse_link_uri("tcp://h:1?maxbackoff=bogus").is_err());
        let (_, p) = parse_link_uri("tcp://h:1").unwrap();
        assert_eq!(p.max_backoff, None);
    }

    #[tokio::test]
    async fn loopback_handshake_both_sides() {
        let client_sk = SigningKey::from_bytes(&[1; 32]);
        let server_sk = SigningKey::from_bytes(&[2; 32]);
        let opts = LinkOptions::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_key = server_sk.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            run_handshake(&mut sock, &server_key, &opts, true)
                .await
                .unwrap()
        });
        let uri = format!("tcp://{addr}");
        let conn = dial(&uri, &client_sk, &LinkOptions::default())
            .await
            .unwrap();
        assert_eq!(conn.remote_key, server_sk.verifying_key().to_bytes());
        assert!(conn.kind.is_roots(), "roots dial advertises vendor");
        let (seen_key, _, seen_kind) = server.await.unwrap();
        assert_eq!(seen_key, client_sk.verifying_key().to_bytes());
        assert!(seen_kind.is_roots(), "roots accept sees vendor");
    }

    #[tokio::test]
    async fn self_dial_rejected() {
        let sk = SigningKey::from_bytes(&[3; 32]);
        let opts = LinkOptions::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Server side uses the SAME key, so the client must see its own key.
        let server_key = sk.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            // Server writes its meta then reads; client key == server key.
            run_handshake(&mut sock, &server_key, &opts, true).await
        });
        let uri = format!("tcp://{addr}");
        let res = dial(&uri, &sk, &LinkOptions::default()).await;
        assert!(matches!(res, Err(Error::SelfDial)));
        let _ = server.await;
    }

    #[tokio::test]
    async fn accept_api_completes_inbound() {
        let client_sk = SigningKey::from_bytes(&[11; 32]);
        let server_sk = SigningKey::from_bytes(&[12; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_server = server_sk.verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            accept(&listener, &server_sk, &LinkOptions::default())
                .await
                .unwrap()
                .remote_key
        });
        let uri = format!("tcp://{addr}");
        let conn = dial(&uri, &client_sk, &LinkOptions::default())
            .await
            .unwrap();
        assert_eq!(conn.remote_key, expected_server);
        assert_eq!(server.await.unwrap(), client_sk.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn linkset_write_reports_missing_peer() {
        // The two send calls disagree on purpose (Gate 2's silent-failure
        // audit): naming a link we believe we serve is a bug, picking a next
        // hop that has no link is normal.
        //
        // Both are addressed by `LinkId`, so "absent" has to be an id the set
        // never issued. A freshly minted one is that, and a stale one is too:
        // a removed link's id stops matching, which is the property the client's
        // `LinkId`-keyed rows depend on.
        let absent = LinkId::next();
        let mut links = LinkSet::new();
        assert!(
            matches!(
                links.write(absent, FrameType::KeepAlive, &[]).await,
                Err(Error::NoLink)
            ),
            "hard send must report the missing link"
        );
        assert!(
            !links
                .write_via(absent, FrameType::KeepAlive, &[])
                .await
                .unwrap(),
            "soft send must report the drop without failing"
        );
        assert!(
            matches!(links.read_frame(absent).await, Err(Error::NoLink)),
            "the set's only read path reports a missing link too"
        );
        assert!(
            links
                .write_all([7u8; KEY_LEN], FrameType::KeepAlive, &[])
                .await
                .is_err(),
            "a per-key send to a key with no link is the same failure"
        );
        assert!(
            links.is_empty(),
            "a failed send must not create a set entry"
        );
    }

    #[tokio::test]
    async fn anyconn_records_direction() {
        // `inbound` rides onto the type-erased link from the handshake
        // templates, so `getPeers` can still report it after erasure.
        let client_sk = SigningKey::from_bytes(&[31; 32]);
        let server_sk = SigningKey::from_bytes(&[32; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let conn = accept(&listener, &server_sk, &LinkOptions::default())
                .await
                .unwrap();
            assert!(conn.inbound, "accept template marks inbound");
            let remote = conn.remote_addr.clone();
            let any = AnyConn::new(conn);
            // The accepted socket's own address rode through the erasure too,
            // which is what names an inbound row the way Go's does.
            assert_eq!(remote, any.remote_addr);
            assert!(
                any.remote_addr
                    .as_deref()
                    .is_some_and(|a| a.starts_with("127.0.0.1:")),
                "inbound link carries the peer's socket address: {:?}",
                any.remote_addr
            );
            let id = any.id;
            let links = LinkSet::single(any);
            links.stats(id).unwrap().inbound
        });
        let conn = dial(
            &format!("tcp://{addr}"),
            &client_sk,
            &LinkOptions::default(),
        )
        .await
        .unwrap();
        assert!(!conn.inbound, "dial template marks outbound");
        assert_eq!(
            conn.remote_addr, None,
            "a dialled link is named by its URI, not its socket"
        );
        let _peer = conn.remote_key;
        let any = AnyConn::new(conn);
        let id = any.id;
        let mut links = LinkSet::single(any);
        let stats = links.stats(id).unwrap();
        assert!(!stats.inbound, "erased link keeps the outbound flag");
        assert_eq!(links.len(), 1);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_bytes, 0);
        assert!(stats.up < Duration::from_secs(5));
        assert!(
            // A freshly minted id belongs to no link in this set — asking with
            // it is how a caller learns the connection it named is gone.
            links.stats(LinkId::next()).is_none(),
            "no counters for a link this set does not hold"
        );
        // Ownership round trip: `remove` hands the link back to the caller and
        // `add` takes it again, while the send clock — the keepalive state the
        // next slice's queue depends on — survives. The id survives too, because
        // it is the same connection.
        let idle_before = links.idle_for(id);
        let back = links.remove(id).unwrap();
        assert!(!back.inbound, "handed-back link keeps its direction");
        assert_eq!(back.id, id, "an id belongs to a connection, not a slot");
        assert!(links.is_empty() && links.stats(id).is_none());
        let readded = links.add(back);
        assert_eq!(readded, id, "the same connection, so the same id");
        assert_eq!(links.len(), 1);
        assert!(!links.stats(id).unwrap().inbound);
        assert!(
            links.idle_for(id) >= idle_before,
            "re-adding must not reset the send clock"
        );
        assert!(server.await.unwrap(), "erased inbound link reports inbound");
    }

    #[tokio::test]
    async fn two_links_to_one_key_both_stay_live() {
        // The set holds one entry per **link**, not one slot per node key
        // (ironwood's `peers map[publicKey]map[*peer]struct{}`, `peers.go:32`).
        // A second connection to the same node is therefore not a displacement:
        // it is a second peer, and both must keep reporting their own counters.
        //
        // This used to be the crossed-peering bug — one slot per key meant the
        // second link displaced the first and the node dropped the one that came
        // back, so two nodes that dialled each other traded closures forever.
        let a_sk = SigningKey::from_bytes(&[51; 32]);
        let b_sk = SigningKey::from_bytes(&[52; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let first = accept(&listener, &b_sk, &LinkOptions::default())
                .await
                .unwrap();
            let second = accept(&listener, &b_sk, &LinkOptions::default())
                .await
                .unwrap();
            (first.remote_key, second.remote_key)
        });
        let dial_one = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer = dial_one.remote_key;
        let mut links = LinkSet::single(AnyConn::new(dial_one));
        let old_id = links.ids()[0];
        // A second connection to the same node key joins the set.
        let dial_two = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let new_id = links.add(AnyConn::new(dial_two));
        assert_ne!(new_id, old_id, "each connection mints its own id");
        assert_eq!(links.len(), 2, "two links, one entry each");
        assert_eq!(
            links.peers(),
            vec![peer],
            "but one node key: the per-key view is not duplicated"
        );
        assert_eq!(
            links.links_to(&peer),
            vec![old_id, new_id],
            "both links answer to the key, in insertion order"
        );
        assert!(
            links.stats(old_id).is_some() && links.stats(new_id).is_some(),
            "both connections report, and each reports its own counters"
        );
        assert!(links.has_peer(&peer));

        // Dropping one leaves the other, and the dropped one's id stops
        // matching — which is what a `getPeers` row keyed by id depends on.
        assert!(links.remove(old_id).is_some());
        assert!(
            links.stats(old_id).is_none(),
            "a removed link's id must stop matching"
        );
        assert!(
            links.stats(new_id).is_some(),
            "the surviving link is untouched"
        );
        assert!(links.has_peer(&peer), "the key still has a live link");
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_removed_links_id_stops_matching_the_key() {
        // The other half of the same contract: `has_peer` is the liveness
        // question a `getPeers` row must not ask, because it answers for the
        // *node*. Once the only link to a key is gone, the key is gone too.
        let a_sk = SigningKey::from_bytes(&[56; 32]);
        let b_sk = SigningKey::from_bytes(&[57; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // One accept per connection the client will make, each held open
            // long enough for the client to finish with it.
            for _ in 0..2 {
                let conn = accept(&listener, &b_sk, &LinkOptions::default())
                    .await
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                drop(conn);
            }
        });
        // Two real connections to the same node, so the key has two links.
        let first = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer = first.remote_key;
        let mut links = LinkSet::single(AnyConn::new(first));
        let second = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let second_id = links.add(AnyConn::new(second));
        assert!(links.has_peer(&peer), "the key has two live links");
        assert!(links.remove(second_id).is_some(), "one of the two goes");
        assert!(
            links.has_peer(&peer),
            "and the key still has the other, so asking about the key is not \
             the same question as asking about a row's link"
        );
        assert!(
            links.stats(second_id).is_none(),
            "its counters are gone too"
        );
        let live = links.ids()[0];
        assert!(links.remove(live).is_some());
        assert!(!links.has_peer(&peer), "now the key has none");
        let _ = server.await;
    }

    #[tokio::test]
    async fn rates_are_the_bytes_since_the_last_sample() {
        // Go differences the counters on one 1 s timer shared by every link
        // (`link.go:106-129`): a rate is the bytes since that tick, so a link
        // that came up mid-window reports everything it has moved so far, and a
        // quiet link reports exactly zero rather than a small average.
        let a_sk = SigningKey::from_bytes(&[61; 32]);
        let b_sk = SigningKey::from_bytes(&[62; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = tokio::spawn(async move {
            let conn = accept(&listener, &b_sk, &LinkOptions::default())
                .await
                .unwrap();
            let _peer = conn.remote_key;
            let any = AnyConn::new(conn);
            let id = any.id;
            let mut links = LinkSet::single(any);
            for _ in 0..4 {
                links.read_frame(id).await.unwrap();
            }
            links.update_rates();
            links.stats(id).unwrap().rx_rate
        });
        let conn = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let _peer = conn.remote_key;
        let any = AnyConn::new(conn);
        let id = any.id;
        let mut links = LinkSet::single(any);
        // Four frames of three bytes: five wire bytes each, twenty in total.
        for _ in 0..4 {
            links.write(id, FrameType::SigReq, &[0; 3]).await.unwrap();
        }
        links.update_rates();
        let first = links.stats(id).unwrap();
        assert_eq!(
            (first.tx_bytes, first.tx_rate),
            (20, 20),
            "the first sample reports the whole life of the link, as Go's does"
        );
        links.update_rates();
        assert_eq!(
            links.stats(id).unwrap().tx_rate,
            20,
            "a second call inside the window is not a new sample"
        );
        tokio::time::sleep(RATE_WINDOW + Duration::from_millis(100)).await;
        links.update_rates();
        let idle = links.stats(id).unwrap();
        assert_eq!(idle.tx_rate, 0, "an idle link reports zero, not an average");
        assert_eq!(idle.tx_bytes, 20, "the totals are untouched by sampling");
        drop(links);
        // The far end saw the same twenty bytes in its own first window.
        assert_eq!(reader.await.unwrap(), 20);
    }

    #[tokio::test]
    async fn link_stats_counts_frame_bytes() {
        // rx/tx are wire bytes, not payload bytes: Go adds every socket byte
        // it reads or writes (`yggdrasil-go/src/core/link.go:784-793`), and a
        // frame costs `uvarint(1+len) + type + payload` on the wire. The
        // counters start at the first frame, so the handshake bytes are the
        // known gap versus Go's totals — frame traffic is what diverges.
        let a_sk = SigningKey::from_bytes(&[41; 32]);
        let b_sk = SigningKey::from_bytes(&[42; 32]);
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let conn = accept(&listener, &b_sk, &LinkOptions::default())
                .await
                .unwrap();
            let _peer = conn.remote_key;
            let any = AnyConn::new(conn);
            let id = any.id;
            let mut links = LinkSet::single(any);
            let (ftype, _payload) = links.read_frame(id).await.unwrap();
            (ftype, links.stats(id).unwrap().rx_bytes)
        });
        let conn = dial(&format!("tcp://{addr}"), &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let _peer = conn.remote_key;
        let any = AnyConn::new(conn);
        let id = any.id;
        let mut links = LinkSet::single(any);
        links
            .write(id, FrameType::SigReq, &[1, 2, 3])
            .await
            .unwrap();
        let sent = links.stats(id).unwrap().tx_bytes;
        assert_eq!(sent, 5, "1 prefix + 1 type byte + 3 payload bytes");
        let (ftype, got) = server.await.unwrap();
        assert_eq!(ftype, FrameType::SigReq);
        assert_eq!(got, sent, "both ends counted the same bytes");
    }

    #[tokio::test]
    async fn frame_exchange_over_loopback() {
        let a_sk = SigningKey::from_bytes(&[21; 32]);
        let b_sk = SigningKey::from_bytes(&[22; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let _ = run_handshake(&mut sock, &b_sk, &opts, true).await.unwrap();
            // Server: read one SigReq, reply keepalive manually.
            let mut tmp = PeerConn::<Tcp> {
                remote_key: [0; KEY_LEN],
                priority: 0,
                kind: crate::peer::PeerKind::Go,
                inbound: true,
                remote_addr: None,
                stream: sock,
            };
            let (ftype, payload) = tmp.read_frame().await.unwrap();
            assert_eq!(ftype, FrameType::SigReq);
            assert_eq!(payload, vec![1, 2, 3]);
            tmp.write_frame(FrameType::KeepAlive, &[]).await.unwrap();
        });
        let uri = format!("tcp://{addr}");
        let mut conn = dial(&uri, &a_sk, &LinkOptions::default()).await.unwrap();
        conn.write_frame(FrameType::SigReq, &[1, 2, 3])
            .await
            .unwrap();
        let (ftype, payload) = conn.read_frame().await.unwrap();
        assert_eq!(ftype, FrameType::KeepAlive);
        assert!(payload.is_empty());
        server.await.unwrap();
    }

    /// In-memory transport, so a test can hand the set a link whose writes
    /// are certain to fail (a `duplex` pair with the far half dropped)
    /// instead of racing a real socket's reset timing.
    #[derive(Clone)]
    struct Mem;

    impl Transport for Mem {
        type Stream = tokio::io::DuplexStream;

        async fn dial(_addr: &str, _timeout: Duration) -> Result<Self::Stream, Error> {
            unreachable!("test links are assembled by hand")
        }
    }

    #[tokio::test]
    async fn a_failed_write_retires_the_link() {
        // The multi-link serve only survives a dying link because the set
        // retires it where the failure is noticed: a link that refuses a
        // frame leaves the map instead of staying to poison every later send.
        // (Go gets this for free — each peer has its own reader goroutine,
        // `peers.go:228`, and write errors are discarded outright.)
        let key = [3u8; KEY_LEN];
        let (mine, theirs) = tokio::io::duplex(64);
        drop(theirs);
        let conn = AnyConn::new(PeerConn::<Mem> {
            remote_key: key,
            priority: 0,
            kind: crate::peer::PeerKind::Go,
            inbound: false,
            remote_addr: None,
            stream: mine,
        });
        let id = conn.id;
        let mut links = LinkSet::single(conn);
        let err = links
            .write(id, FrameType::KeepAlive, &[7u8; 512])
            .await
            .expect_err("a write to a closed link must report the io error");
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        assert!(links.is_empty(), "the failing link is retired, not kept");
        assert!(
            matches!(
                links.write(id, FrameType::KeepAlive, &[]).await,
                Err(Error::NoLink)
            ),
            "the key is gone, so a later send reports it as missing"
        );
    }
}
