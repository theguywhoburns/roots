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
use crate::frame::{self, FrameType, MAX_MESSAGE_SIZE};
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
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
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

/// Type-erased authenticated peer connection: same shape as
/// [`PeerConn`], but the stream is boxed, so links of different
/// transports share one concrete type.
pub struct AnyConn {
    pub remote_key: [u8; KEY_LEN],
    pub priority: u8,
    pub kind: crate::peer::PeerKind,
    pub stream: Box<dyn LinkStream>,
}

impl AnyConn {
    pub fn new<T: Transport>(conn: PeerConn<T>) -> Self
    where
        T::Stream: 'static,
    {
        Self {
            remote_key: conn.remote_key,
            priority: conn.priority,
            kind: conn.kind,
            stream: Box::new(conn.stream),
        }
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

/// The multi-peer connection map (Slice 10b): one entry per link keyed
/// by the peer's node key. All router I/O goes through the set, so mixed
/// transports share one code path; a target with no entry is silently
/// skipped (a next hop we hold no link for). Single-link callers
/// (`serve`, `resolve`) wrap their one link and delegate.
#[derive(Default)]
pub struct LinkSet<'a> {
    entries: Vec<([u8; KEY_LEN], &'a mut dyn Link)>,
    last_write: std::collections::HashMap<[u8; KEY_LEN], std::time::Instant>,
}

impl<'a> LinkSet<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap a single link (single-peer callers).
    pub fn single(peer: [u8; KEY_LEN], link: &'a mut dyn Link) -> Self {
        let mut set = Self::default();
        set.add(peer, link);
        set
    }

    pub fn add(&mut self, peer: [u8; KEY_LEN], link: &'a mut dyn Link) {
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == peer) {
            slot.1 = link;
        } else {
            self.entries.push((peer, link));
        }
        self.last_write
            .entry(peer)
            .or_insert_with(std::time::Instant::now);
    }

    /// Peer keys currently in the set (for per-link maintain loops).
    pub fn peers(&self) -> Vec<[u8; KEY_LEN]> {
        self.entries.iter().map(|(k, _)| *k).collect()
    }

    /// Reborrowing access to one link's framed I/O.
    pub fn get(&mut self, peer: &[u8; KEY_LEN]) -> Option<&mut dyn Link> {
        for (k, l) in self.entries.iter_mut() {
            if k == peer {
                return Some(&mut **l);
            }
        }
        None
    }

    /// Drop a link from the set (dead links; the caller owns the conn).
    /// Send clocks for remaining links are untouched.
    pub fn remove(&mut self, peer: &[u8; KEY_LEN]) {
        self.entries.retain(|(k, _)| k != peer);
    }

    /// True when no links remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Write one frame to the link for `target` (no entry = drop).
    /// Stamps the send time, which drives Go-style lazy keepalives:
    /// a keepalive goes out only after a full idle tick with no sends.
    pub async fn write(
        &mut self,
        target: [u8; KEY_LEN],
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<(), Error> {
        if let Some(link) = self.get(&target) {
            link.write_frame(ftype, payload).await?;
            self.last_write.insert(target, std::time::Instant::now());
        }
        Ok(())
    }

    /// Time since the last frame sent to `peer` (zero for unknown links).
    pub fn idle_for(&self, peer: &[u8; KEY_LEN]) -> Duration {
        self.last_write
            .get(peer)
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
        return Err(Error::BadUri(uri.to_string()));
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
            "password" => out.password = v.as_bytes().to_vec(),
            "priority" => {
                out.priority = v
                    .parse::<u8>()
                    .map_err(|_| Error::BadUri(uri.to_string()))?;
            }
            "key" => {
                let raw = hex::decode(v).map_err(|_| Error::BadUri(uri.to_string()))?;
                if raw.len() != KEY_LEN {
                    return Err(Error::BadUri(uri.to_string()));
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&raw);
                out.pinned_key = Some(key);
            }
            "sni" => out.sni = Some(v.to_string()),
            "maxbackoff" => {
                let d = parse_go_duration(v)?;
                if d < MIN_MAX_BACKOFF {
                    return Err(Error::BadUri(uri.to_string()));
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
    let (stream, _) = listener.accept().await.map_err(Error::Io)?;
    complete_accept(stream, local, opts).await
}

/// Per-type frame counters from a [`PeerConn::run`] session.
#[derive(Debug, Default)]
pub struct RunStats {
    pub frames: [u64; 10],
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
        stream,
    })
}

/// Transport template: finish an accept from an accepted stream. Shared
/// tail for all `*_accept`.
pub async fn complete_accept<T: Transport>(
    stream: T::Stream,
    local: &SigningKey,
    opts: &LinkOptions,
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
        stream,
    })
}

/// Dial any scheme and type-erase to [`AnyConn`]: one `match` on [`Scheme`]
/// instead of per-callsite `if starts_with` chains (`main.rs`, `admin.rs`,
/// `proto_probe.rs`).
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
}
