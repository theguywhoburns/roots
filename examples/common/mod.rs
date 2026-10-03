//! Shared smoltcp bridge for the mesh examples (dev-dependencies only).
//!
//! The `roots` lib never sees smoltcp: each example owns one Yggdrasil
//! session whose payloads are raw IPv6 packets, and this device shuttles
//! them between `Router::inbox`/outbox and a smoltcp `Interface`.
//!
//! Import with `mod common;` (shared sibling module, not an example
//! target — it lives at `examples/common/mod.rs` so Cargo doesn't try
//! to build it standalone).

// Each example compiles this module whole and uses a different part of it:
// `ping6` wants the ICMPv6 builders and no sockets, `mesh_tcp` wants sockets and
// no ICMPv6. A file-level allow is the honest expression of that, where a dozen
// per-item ones would be a lie about which items are live.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::Instant;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// smoltcp device bridged to one Yggdrasil session: ingress = inbound
/// session payloads, egress = packets to send to the peer key.
pub struct MeshPhy {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
}

impl MeshPhy {
    pub fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

impl Default for MeshPhy {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MeshRx {
    pkt: Vec<u8>,
}

pub struct MeshTx<'a> {
    out: &'a mut VecDeque<Vec<u8>>,
}

impl Device for MeshPhy {
    type RxToken<'a> = MeshRx;
    type TxToken<'a> = MeshTx<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(|pkt| {
            let tx = MeshTx { out: &mut self.tx };
            (MeshRx { pkt }, tx)
        })
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(MeshTx { out: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}

impl RxToken for MeshRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.pkt)
    }
}

impl TxToken for MeshTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.out.push_back(buf);
        r
    }
}

pub fn smol_now(start: Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

/// Interface bound to `our_ip` with a default IPv6 route into the mesh
/// device. `phy` is only borrowed during construction (smoltcp 0.14
/// `Interface` owns its state; each `poll` takes the device anew).
pub fn new_iface(phy: &mut MeshPhy, our_ip: std::net::Ipv6Addr, start: Instant) -> Interface {
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), phy, smol_now(start));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv6(our_ip), 128))
            .unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv6_route(std::net::Ipv6Addr::UNSPECIFIED)
        .unwrap();
    iface
}

/// Fresh TCP socket with 64 KiB buffers (mesh RTTs are high; small
/// buffers stall throughput).
pub fn new_tcp_socket(sockets: &mut SocketSet<'_>) -> smoltcp::iface::SocketHandle {
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 65535]),
        tcp::SocketBuffer::new(vec![0; 65535]),
    );
    sockets.add(socket)
}

// ---------------------------------------------------------------- ICMPv6 ----
//
// Shared by `ping6.rs` and `tests/mesh_ping.rs`, which were byte-identical
// copies of the checksum and near-identical copies of the echo builder. Two
// copies of a checksum is two copies of a bug: a demo that computes it wrong
// looks exactly like a node that drops traffic, and the live test is the one
// whose answer is trusted. So there is one, here.
//
// These build *raw* packets on purpose. The TUN bridge in `client/src/tun.rs`
// exists to avoid exactly this, but it needs `CAP_NET_ADMIN` and a real
// interface, and neither an example nor a loopback test can have that.

/// The ICMPv6 checksum over `src ‖ dst ‖ len ‖ 58 ‖ icmp` (RFC 4443 §2.3), with
/// the one's-complement fold and the odd-byte tail.
pub fn icmp6_checksum(src: &[u8; 16], dst: &[u8; 16], len: u16, icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in src.chunks(2).chain(dst.chunks(2)) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    sum += len as u32;
    sum += 58u32;
    let mut i = 0;
    while i + 1 < icmp.len() {
        sum += u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp.len() {
        sum += (icmp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An ICMPv6 echo request or reply, checksummed.
///
/// `kind` is 128 for a request and 129 for a reply. The checksum is computed
/// over the finished ICMP body and written back into the packet, so the
/// returned bytes are the bytes to send — no second step, and no way to forget
/// it.
pub fn icmp6_echo(
    kind: u8,
    src: &[u8; 16],
    dst: &[u8; 16],
    ident: u16,
    seq: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + 8 + data.len()];
    pkt[0] = 0x60;
    let icmp_len = (8 + data.len()) as u16;
    pkt[4..6].copy_from_slice(&icmp_len.to_be_bytes());
    pkt[6] = 58; // ICMPv6
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(src);
    pkt[24..40].copy_from_slice(dst);
    pkt[40] = kind;
    pkt[42..44].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt[44..46].copy_from_slice(&ident.to_be_bytes());
    pkt[46..48].copy_from_slice(&seq.to_be_bytes());
    pkt[48..].copy_from_slice(data);
    let csum = icmp6_checksum(src, dst, icmp_len, &pkt[40..]);
    pkt[42..44].copy_from_slice(&csum.to_be_bytes());
    pkt
}

/// Is this an ICMPv6 echo reply we should answer, and if so with what?
///
/// Returns the reply to send, with the addresses swapped, the kind flipped and
/// the checksum recomputed. A received checksum is verified first: a packet
/// whose checksum is wrong is dropped by every stack and must be dropped here
/// too, or a demo will happily report a reply that never existed.
pub fn icmp6_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 48 || request[0] >> 4 != 6 || request[6] != 58 || request[40] != 128 {
        return None;
    }
    let len = u16::from_be_bytes([request[4], request[5]]);
    let src: [u8; 16] = request[8..24].try_into().ok()?;
    let dst: [u8; 16] = request[24..40].try_into().ok()?;
    let body = &request[40..40 + len as usize];
    let want = u16::from_be_bytes([request[42], request[43]]);
    if icmp6_checksum(&src, &dst, len, body) != want {
        return None;
    }
    let mut reply = icmp6_echo(
        129,
        &dst,
        &src,
        u16::from_be_bytes([request[44], request[45]]),
        u16::from_be_bytes([request[46], request[47]]),
        &request[48..40 + len as usize],
    );
    reply[6] = 58;
    Some(reply)
}

// ------------------------------------------------------- link plumbing ----
//
// Seven copies of "dial, wrap, register, make a one-link set" and six of
// "serve until the tree has a parent". Both were rewritten by hand at least once
// and drifted: the converge budgets are 30 s in some examples and 60 s in
// others, one loop is spelled "convergence timed out" and another "mesh
// convergence timed out", and `mesh_tcp.rs` does not call `serve` at all — it
// has its own `drive`.
//
// These are example code on purpose. A `converge()` on `Router` would be node
// policy in the library, which is the one thing the library must not have.

/// Dial one peer and bring it up as a single-link set.
pub async fn join_one(
    key: &ed25519_dalek::SigningKey,
    opts: &roots::LinkOptions,
    uri: &str,
) -> Result<(roots::Router, roots::LinkSet, roots::LinkId), roots::Error> {
    join(roots::link::dial(uri, key, opts).await?, key).await
}

/// Register a finished handshake and put it in a one-link set.
///
/// Split from [`join_one`] because `proto_probe.rs` dials through every
/// transport in turn and already holds a `PeerConn<T>` by the time it gets
/// here; making it dial again would have thrown away the point of that example.
///
/// `register` runs before the connection joins the set, exactly as a caller that
/// registers once per link must — the bloom and the signature request go out
/// through the connection itself.
///
/// The `LinkId` comes back too because `Router::resolve` takes one: it is a
/// liveness handle, and a caller that held the connection but not its id would
/// have to fish it out of the set afterwards.
pub async fn join<T: roots::Transport>(
    conn: roots::PeerConn<T>,
    key: &ed25519_dalek::SigningKey,
) -> Result<(roots::Router, roots::LinkSet, roots::LinkId), roots::Error> {
    let peer = conn.remote_key;
    let mut conn = roots::link::AnyConn::new(conn);
    let id = conn.id;
    let mut router = roots::Router::new(key.clone());
    router.register(&mut conn, peer, id).await?;
    // One set for the whole run: per-link send clocks must survive slices, or
    // lazy keepalives stop firing and the peer reads the link out at ~4 s.
    Ok((router, roots::LinkSet::single(conn), id))
}

/// Serve slices until the router has a parent, or `budget` runs out.
///
/// Returns whether it converged, so the caller decides the message: a demo wants
/// a panic and a probe wants a line. The outbox is this function's own — nothing
/// application-level is being sent while the tree settles.
///
/// A dropped link is a non-convergence, not a hang: the loop would otherwise
/// spin out its whole budget against a dead socket, which is the shape of a demo
/// that appears to wait a minute for a network that is not there.
pub async fn converge(
    router: &mut roots::Router,
    links: &mut roots::LinkSet,
    budget: std::time::Duration,
) -> bool {
    let end = std::time::Instant::now() + budget;
    let mut no_out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    while router.parent().is_none() && std::time::Instant::now() < end {
        if router
            .serve(
                links,
                Some(std::time::Duration::from_millis(250)),
                &mut no_out,
            )
            .await
            .is_err()
        {
            return false;
        }
    }
    router.parent().is_some()
}
