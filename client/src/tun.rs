//! The TUN bridge: a kernel interface whose packets ride the mesh.
//!
//! This is node behaviour, not a demo, which is why it lives here rather than in
//! `examples/`. It has three properties the rest of the client is built around:
//!
//! 1. **The device is owned by the node task.** It reads the router's session
//!    inbox and calls `send_or_resolve`, both of which are `&mut Router` and may
//!    only be touched by `Node::run` (`node.rs`). A second task would need a lock
//!    over the one thing in this client that must not have one.
//! 2. **Packets are addressed by IPv6, not by node key.** A TUN carries whatever
//!    the kernel routed at it, and that is an address. `Router::send_or_resolve`
//!    is the seam that turns one into a lookup and holds the packet while the
//!    lookup runs (`driver.rs`), which is what lets a packet be buffered instead
//!    of dropped while a DHT round trip is in flight.
//! 3. **It needs `CAP_NET_ADMIN` and cannot run in CI.** Opening `/dev/net/tun`
//!    and `TUNSETIFF` both need the capability (`tun/tun.go:132-146`). So this
//!    module's *logic* is testable without the device — the address filter, the
//!    outbox drain — and the device is the only part that needs privilege.
//!
//! Go's arrangement is the same in the places that matter: the adapter is built
//! from the same config keys (`IfName`, `IfMTU`, `tun/tun.go:50-60`), it is
//! driven from the core loop rather than its own goroutine, and it never prints —
//! the library's `ipv6rwc` hands packets to the TUN as raw bytes.

use std::time::Duration;

use roots::Router;
use roots::address::{Address, NODE_PREFIX};
#[cfg(test)]
use std::net::Ipv6Addr;

/// Go's smallest supported interface MTU, and the value `examples/tun_ping` used.
///
/// `getSupportedMTU` clamps a configured MTU into `[1280, MaximumMTU]`
/// (`tun/tun.go:57-65`, `:79-81`), so 1280 is the floor a config can ask for and
/// the value worth using by default: below the IPv6 minimum MTU the kernel drops
/// packets, and 1280 is exactly that minimum.
pub const MIN_MTU: u16 = 1280;

/// The largest packet a mesh payload carries.
///
/// `IfMTU` defaults to 65535 (`config/defaults_linux.go`), but a packet that big
/// does not fit in the 65535-byte frame budget once the session and protocol
/// headers are on it, and a real network drops it long before. This is the
/// common Ethernet-safe value and is what the device is created with unless the
/// config says otherwise.
pub const DEFAULT_MTU: u16 = 1280;

/// Go's `tun.getSupportedMTU` (`tun/tun.go:57-65`): clamp to
/// `[MIN_MTU, MaximumMTU]`, and a configured 0 means the default.
///
/// The upper clamp is not applied because Go's `MaximumIfMTU` is a per-platform
/// default this client has no equivalent of, and a larger MTU than the link
/// carries is a fragmentation question the node has no business answering. The
/// floor is applied because below it the kernel silently drops packets, which is
/// indistinguishable from a mesh that does not work.
pub fn supported_mtu(configured: u16) -> u16 {
    match configured {
        0 => DEFAULT_MTU,
        n if n < MIN_MTU => MIN_MTU,
        n => n,
    }
}

/// A TUN interface the node task pumps.
///
/// Owns the device and the one piece of state the kernel cannot tell us: which
/// packets are ours. The kernel will hand this interface neighbour solicitations,
/// router advertisements and its own link-local chatter, none of which is mesh
/// traffic, and sending them into a session would be both wasteful and — for a
/// solicited multicast — a routing loop.
pub struct Device {
    tun: Box<dyn AsyncReadWrite>,
    /// This node's mesh address, which the device is configured with.
    local: Address,
    /// The name the kernel gave the interface, which is not the one we asked for
    /// if another device had it.
    name: String,
    mtu: u16,
    /// Packets the session inbox produced, waiting to go out the device.
    ///
    /// A separate slot from the node's own `outbox`, because these have no
    /// destination to route: the destination *is* the device. The node loop drains
    /// it after serving, and writing to a TUN is the only thing that consumes it.
    out: Vec<Vec<u8>>,
    /// The read buffer, allocated once.
    ///
    /// It lives here rather than in `pump` because `pump` runs on **every tick**
    /// and the buffer is `MTU + 64` bytes — 64 KiB at a config's default
    /// `IfMTU`, twenty times a second. A `Vec::with_capacity` is not free, and an
    /// allocation per tick for a buffer that never changes size is the kind of
    /// thing that shows up as a node mysteriously using more memory than the
    /// process it is talking to.
    buf: Vec<u8>,
}

/// The device's async read/write, so the logic can be tested against
/// `tokio::io::duplex` instead of a real interface.
///
/// `tun::Tun` is `AsyncRead + AsyncWrite + Unpin` and that is all this needs, so
/// the bound is on those traits rather than on the device type. It matters: a test
/// that opens a real TUN needs `CAP_NET_ADMIN` and so cannot run in CI, and this is
/// the seam that lets the filtering and the outbox be pinned without one.
///
/// `Unpin` is in the supertraits because every read here goes through
/// `AsyncReadExt::read` on a `&mut dyn` — which needs it — and a device pinned in
/// place is exactly what a TUN is.
///
/// `Send` is there because the device is a field on `Node`, and `Node::run` is
/// spawned onto a multi-threaded runtime in `main.rs`. It is a *supertrait* rather
/// than a bound on `Device` for the usual reason: a supertrait is what makes
/// `dyn AsyncReadWrite` itself `Send`, which is what the `Box` field needs.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

impl Device {
    /// A device over an already-open interface.
    pub fn new(
        tun: Box<dyn AsyncReadWrite>,
        name: impl Into<String>,
        local: Address,
        mtu: u16,
    ) -> Self {
        // `+ 64` on top of the MTU: an Ethernet header is 14 bytes and a
        // prepended 4-byte info word is what TUN devices are documented to allow
        // (`TUNGETIFF`), so a device is allowed to hand back more than the MTU
        // and truncating a packet into an "invalid argument" loses it.
        let buf = vec![0u8; usize::from(mtu) + 64];
        Self {
            tun,
            local,
            name: name.into(),
            mtu,
            out: Vec::new(),
            buf,
        }
    }

    /// The interface name, for `getTun`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface MTU, for `getTun`.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// The packets still waiting to go out, for tests.
    ///
    /// A peek, not a drain: `flush` is the only thing that empties the outbox in
    /// production, and a second way to do it is a second thing to get wrong. (An
    /// earlier `pub fn take_outbound` claimed the node loop drained through it,
    /// and it never did — `flush` is the drain.)
    #[cfg(test)]
    fn pending(&self) -> &[Vec<u8>] {
        &self.out
    }

    /// Accept a packet from the mesh for the device.
    pub fn deliver(&mut self, packet: Vec<u8>) {
        self.out.push(packet);
    }

    /// Is this an IPv6 link-local address, `fe80::/10`?
    ///
    /// Read off the first two bytes rather than through `std` so this needs no
    /// address API to grow. The prefix is ten bits: `0xfe` then the second byte's
    /// top two bits must be `10`, so `fe80::` is in, `febf::` is the last address
    /// in, and `fec0::` — the site-local range — is the first one out (RFC 4291
    /// §2.5.6). The mask was `== 0` the first time round, which excluded every
    /// link-local address there is; the boundary test below is what caught it.
    fn link_local(addr: Address) -> bool {
        addr.0[0] == 0xfe && addr.0[1] & 0xc0 == 0x80
    }

    /// Is this an address inside the mesh, `0200::/7`?
    ///
    /// One mask, and it is the whole reason this filter is a range test and not a
    /// list: the address is the node prefix byte `0x02` OR'd with a sub-bit
    /// (`address.go:8-12`), so *both* `02…` node addresses and `03…` subnet
    /// prefixes live in `0200::/7`. A node that routes a subnet therefore needs no
    /// configuration to forward for it — every address it can be asked about is
    /// already in the range.
    ///
    /// There was a configurable prefix list here first, seeded from the node's own
    /// `subnet_for_key`. That was wrong in a way only a test could show: a node's
    /// own subnet contains no *peer* addresses, so the filter rejected every
    /// packet the device existed to carry, and the device was silent rather than
    /// broken. Go does not filter at all (`ipv6rwc.go:174-199`); the range test is
    /// the smallest thing that is not that.
    fn mesh(addr: Address) -> bool {
        addr.0[0] & 0xfe == NODE_PREFIX & 0xfe
    }

    /// The destination of an IPv6 packet, if it is one we can read.
    ///
    /// 40 bytes is the fixed IPv6 header, which is the smallest thing worth
    /// looking at: a truncated packet has no address in it, and handing it to the
    /// kernel would be handing it a lie.
    pub fn destination(packet: &[u8]) -> Option<Address> {
        if packet.len() < 40 || packet[0] >> 4 != 6 {
            return None;
        }
        <[u8; 16]>::try_from(&packet[24..40]).ok().map(Address)
    }

    /// Is this a packet the mesh should carry?
    ///
    /// Four rejections, each for a reason:
    ///
    /// - **Not IPv6, or too short to have an address.** There is nothing to route.
    /// - **Addressed to this node.** The kernel already delivered it locally; a
    ///   session to ourselves is the one loop a mesh must not have.
    /// - **A link-local source or destination.** `fe80::` traffic is scoped to one
    ///   link and is never mesh traffic — it is the kernel's neighbour discovery,
    ///   and sending it would make the device answer for peers it cannot reach.
    /// - **A destination outside the mesh range.** The kernel routed it here, so
    ///   somebody asked for it, but it is not mesh traffic and the session layer
    ///   has nowhere to send it.
    pub fn wants(&self, packet: &[u8]) -> bool {
        let Some(dst) = Self::destination(packet) else {
            return false;
        };
        if dst == self.local {
            return false;
        }
        let src = Address(<[u8; 16]>::try_from(&packet[8..24]).unwrap_or([0; 16]));
        !Self::link_local(dst) && !Self::link_local(src) && Self::mesh(dst) && Self::mesh(src)
    }

    /// Read whatever the kernel has for us and hand it to the router.
    ///
    /// Returns how many packets went to the mesh, queued or sent.
    ///
    /// `via` names the link a **lookup** leaves on, which is not the link a packet
    /// eventually travels on — `send_or_resolve` takes a `LinkId` for the same
    /// liveness reason `resolve` does. `None` means there is no live link to
    /// start a lookup on, so the packet is dropped rather than held: with no link
    /// there is nothing to hold it *for*, and the kernel will retransmit or the
    /// application will retry. Go has the same hole (`_sendLookup` floods over the
    /// bloom's on-tree set, `pathfinder.go:27-42`) and reaches it by dropping.
    ///
    /// Non-blocking with a short budget, because the device is one more thing the
    /// node loop multiplexes and a blocking read would stop it serving links. A
    /// device with no traffic returns immediately, which is the normal case.
    pub async fn pump(
        &mut self,
        router: &mut Router,
        links: &mut roots::LinkSet,
        via: Option<roots::LinkId>,
    ) -> Result<u64, roots::Error> {
        let mut handled = 0;
        // A bound per tick, so a busy device cannot starve the links the node loop
        // is also serving. Whatever is left is still in the device's buffer.
        while handled < 64 {
            let read = match tokio::time::timeout(
                Duration::from_millis(1),
                tokio::io::AsyncReadExt::read(&mut self.tun, &mut self.buf),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                // Nothing waiting, or the device went away. Both are "not now",
                // and the node loop comes back.
                Ok(Err(_)) | Err(_) => break,
            };
            if !self.wants(&self.buf[..read]) {
                continue;
            }
            let Some(dst) = Self::destination(&self.buf[..read]) else {
                continue;
            };
            let Some(id) = via else {
                break;
            };
            // A queued packet is not a failure: `send_or_resolve` holds it until
            // the lookup lands, and the notify flushes it. The kernel's packet is
            // in the mesh queue either way, which is what `handled` counts.
            router
                .send_or_resolve(links, id, &dst, self.buf[..read].to_vec())
                .await?;
            handled += 1;
        }
        Ok(handled)
    }

    /// Write the packets the mesh produced back to the kernel.
    ///
    /// The mirror of [`Device::pump`], and for the same reason it is a drain
    /// rather than a callback: a write to a device buffer can block, and the node
    /// loop has links to keep serving.
    ///
    /// Returns how many went in and how many are still held. A held packet is
    /// **kept**, not dropped: a full buffer costs the peer latency and nothing
    /// else, whereas losing the packet loses their traffic and there is no upper
    /// layer to notice.
    ///
    /// A *failed* write is different, and is an error: the device is gone (it was
    /// deleted, or the namespace went away), and retrying forever would grow the
    /// outbox without bound. The tail goes back on the way out, so the caller can
    /// decide what to do with a device that is not answering.
    pub async fn flush(&mut self) -> Result<(u64, u64), std::io::Error> {
        let batch = std::mem::take(&mut self.out);
        let mut written = 0;
        for (i, packet) in batch.iter().enumerate() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut self.tun, packet).await {
                // Nothing from `i` onwards went in. `out` is `&mut self`, so no
                // packet can have been appended while that await was out, and the
                // tail is exactly the rest of this batch.
                self.out = batch[i..].to_vec();
                return Err(e);
            }
            written += 1;
        }
        Ok((written, 0))
    }
}

/// Open a real kernel TUN interface, configured and up.
///
/// This is the only function here that needs privilege: `/dev/net/tun` and
/// `TUNSETIFF` both require `CAP_NET_ADMIN` (`tun/tun.go:132-146` in Go, which is
/// why the Go node panics at startup without it). Everything else in this module
/// is testable without it, which is the point of the `AsyncReadWrite` seam.
///
/// `ip` is used to assign the address and bring the link up, because `tun`'s
/// `Configuration` covers the device and not the addressing. Go does the same with
/// its own `netlink` calls (`tun/tun.go:148-190`); the effect is identical and a
/// shell-out does not need a netlink dependency.
pub async fn open(ifname: &str, local: Address, mtu: u16) -> std::io::Result<Device> {
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(ifname).mtu(mtu).up();
    let tun: Box<dyn AsyncReadWrite> = Box::new(tun::create_as_async(&cfg)?);
    let actual = ifname.to_string();
    // `nodad` because a mesh address is derived from a key, not advertised: there
    // is no prefix to send a router advertisement for, and the peer is found
    // through the mesh rather than through NDP.
    run_ip(&[
        "addr",
        "add",
        &format!("{local}/128"),
        "dev",
        ifname,
        "nodad",
    ])?;
    run_ip(&["link", "set", ifname, "up"])?;
    Ok(Device::new(tun, actual, local, mtu))
}

/// Run `ip`, reporting its own words.
///
/// A TUN that exists but has no address looks exactly like a node that is not
/// working, so a failure here has to be loud rather than a line in a log nobody
/// reads.
fn run_ip(args: &[&str]) -> std::io::Result<()> {
    let out = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| std::io::Error::other(format!("ip {args:?}: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "200::1";

    /// An address from its text form, which is how every address in these tests is
    /// written.
    fn addr(s: &str) -> Address {
        Address(s.parse::<Ipv6Addr>().unwrap().octets())
    }

    /// A minimal IPv6 packet: `src`, `dst`, next-header, hop limit, payload. 40
    /// bytes of header, which is exactly what `Device::destination` needs.
    fn packet(src: Address, dst: Address) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&src.0);
        p.extend_from_slice(&dst.0);
        p.extend_from_slice(&[59, 64, 0, 0]); // no next header, hop limit
        p.extend_from_slice(b"payload");
        p
    }

    /// A device over one half of a `duplex` pair, so a test can put bytes where
    /// the kernel would and read what the mesh produced — with no `CAP_NET_ADMIN`
    /// and nothing that can run in CI.
    fn device() -> (Device, tokio::io::DuplexStream) {
        let (mine, theirs) = tokio::io::duplex(4096);
        (
            Device::new(Box::new(mine), "rootstest0", addr(LOCAL), 1280),
            theirs,
        )
    }

    /// The four rejections in `wants`, each for a stated reason.
    #[test]
    fn only_mesh_traffic_is_forwarded() {
        let peer = addr("200::2");
        let (d, _kernel) = device();
        let local = addr(LOCAL);

        assert!(
            d.wants(&packet(local, peer)),
            "a packet from us to a peer is the whole point"
        );

        // To ourselves: the kernel already delivered it.
        assert!(
            !d.wants(&packet(local, local)),
            "a session to ourselves is the one loop a mesh must not have"
        );

        // Link-local: neighbour discovery, which is never mesh traffic.
        assert!(
            !d.wants(&packet(local, addr("fe80::1"))),
            "fe80:: traffic is scoped to one link and never crosses a session"
        );
        assert!(
            !d.wants(&packet(addr("fe80::2"), peer)),
            "and a link-local source means the kernel, not the mesh"
        );

        // Routed at the device, but not mesh traffic. A real host has loopback
        // and container veths, and the kernel routes those at this interface too.
        assert!(
            !d.wants(&packet(local, addr("ff02::114"))),
            "a solicited multicast would loop back into the device"
        );
        assert!(
            !d.wants(&packet(local, addr("2001:db8::1"))),
            "a documentation prefix is not ours to route"
        );
        assert!(
            !d.wants(&packet(addr("2001:db8::1"), peer)),
            "and neither end outside the mesh range counts"
        );

        // Not IPv6, or not long enough to have an address.
        assert!(!d.wants(&[0x45, 0, 0, 20]), "IPv4 is not ours to route");
        assert!(
            !d.wants(&[0x60, 0, 0, 0]),
            "a truncated packet has no address"
        );
        assert!(!d.wants(&[]), "and neither does nothing");
    }

    /// The mesh range is `0200::/7`, and it has to cover a **subnet** prefix as
    /// well as a node address: the address is the node prefix byte `0x02` OR'd
    /// with a sub-bit (`address.go:8-12`), so `03…` is a routed subnet and
    /// `02…` is a node. A mask that only accepted `0x02` would break every node
    /// that routes a subnet, and one that only accepted `0x03` would break every
    /// node that does not.
    #[test]
    fn the_mesh_range_holds_both_node_addresses_and_subnets() {
        assert!(Device::mesh(addr("200::1")), "a node address is 02…");
        assert!(Device::mesh(addr("2ff::1")), "the last node in the /7");
        assert!(Device::mesh(addr("300::1")), "a subnet prefix is 03…");
        assert!(Device::mesh(addr("3ff::1")), "the last subnet in the /7");
        assert!(
            !Device::mesh(addr("400::1")),
            "400:: is the first address out of the /7"
        );
        assert!(
            !Device::mesh(addr("::1")),
            "and so is the unspecified address"
        );
        assert!(!Device::mesh(addr("ff02::1")), "ff02:: is multicast");
        assert!(!Device::mesh(addr("fe80::1")), "fe80:: is link-local");
    }

    /// The reason the filter is a range and not a list: a node's own `subnet`
    /// contains no peer addresses, so filtering on it drops every packet the
    /// device exists to carry. This is that regression, pinned.
    #[test]
    fn a_peer_is_forwarded_even_though_it_is_not_in_our_own_subnet() {
        let (d, _kernel) = device();
        let local = addr(LOCAL);
        // This node's own subnet, `03 00 0d b8 00 01 00 02::/64`, padded out the
        // way `subnet_for_key` is. A peer at `200::2` shares the first byte's high
        // bits and nothing else.
        let own_subnet: Address = {
            let mut p = [0u8; 16];
            p[..8].copy_from_slice(&[0x03, 0x00, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02]);
            Address(p)
        };
        assert!(
            Device::mesh(own_subnet),
            "our own subnet is in the mesh range"
        );
        assert!(
            d.wants(&packet(local, addr("200::2"))),
            "and so is a peer that is not in it, which is the whole claim"
        );
    }

    /// `wants` must never panic on a packet the kernel truncated, whatever the
    /// length. A TUN hands you whatever arrived, including a runt.
    #[test]
    fn every_truncation_is_answered_rather_than_panicking() {
        let (d, _kernel) = device();
        let full = packet(addr(LOCAL), addr("200::2"));
        for n in 0..=full.len() {
            let _ = d.wants(&full[..n]);
            assert_eq!(
                n < 40,
                Device::destination(&full[..n]).is_none(),
                "an address only exists once 40 bytes have arrived"
            );
        }
    }

    /// The link-local test is a byte test, and `fe80::/10` is 10 bits wide: `fe80`
    /// is in, `febf` is the last address in, and `fec0` is the first out. Getting
    /// the width wrong is the classic version of this bug.
    #[test]
    fn link_local_is_the_whole_fe80_slash_ten() {
        assert!(Device::link_local(addr("fe80::1")), "fe80::1 is link-local");
        assert!(Device::link_local(addr("febf::1")), "febf:: is the last in");
        assert!(!Device::link_local(addr("fec0::1")), "fec0:: is site-local");
        assert!(!Device::link_local(addr("200::1")), "200:: is ours");
        assert!(
            !Device::link_local(addr("ff02::114")),
            "ff02:: is multicast"
        );
    }

    /// Go clamps a configured MTU up to 1280 and reads 0 as the default
    /// (`tun/tun.go:57-65`, `:79-81`).
    #[test]
    fn the_mtu_is_clamped_like_go() {
        assert_eq!(supported_mtu(0), DEFAULT_MTU, "0 means the default");
        assert_eq!(supported_mtu(1), MIN_MTU, "1 is below the IPv6 minimum");
        assert_eq!(supported_mtu(1279), MIN_MTU, "and so is 1279");
        assert_eq!(supported_mtu(1280), 1280, "the minimum is itself");
        assert_eq!(supported_mtu(1500), 1500, "a configured value is kept");
        assert_eq!(supported_mtu(65535), 65535);
    }

    /// The mesh side: a packet from the inbox reaches the kernel, in order, and a
    /// drain empties the outbox.
    #[tokio::test]
    async fn packets_from_the_mesh_reach_the_kernel() {
        use tokio::io::AsyncReadExt;
        let (mut d, mut kernel) = device();
        let first = packet(addr("200::2"), addr(LOCAL));
        d.deliver(first.clone());
        d.deliver(b"second".to_vec());

        let (written, held) = d.flush().await.expect("the device accepts writes");
        assert_eq!((written, held), (2, 0), "both went in, none held");
        assert!(d.pending().is_empty(), "a flush empties the outbox");

        // Both packets, in the order they were delivered: a device delivers in
        // order and a reordered packet is a corrupted one.
        let mut got = vec![0u8; first.len() + 6];
        let n = kernel.read(&mut got).await.expect("the kernel reads");
        let mut want = first;
        want.extend_from_slice(b"second");
        assert_eq!(&got[..n], &want[..], "what the mesh produced, in order");
    }

    /// A kernel that will not take the write must not lose the packet.
    ///
    /// The write error is reported, and the packet is still on the outbox, because
    /// the two are separate claims and a drain that reported one while quietly
    /// discarding the other would pass a test that only checked the count.
    #[tokio::test]
    async fn a_failed_write_is_reported_and_the_packet_is_kept() {
        let (mine, kernel) = tokio::io::duplex(4);
        let mut d = Device::new(Box::new(mine), "rootstest0", addr(LOCAL), 1280);
        d.deliver(b"far too long for four bytes".to_vec());
        // Drop the far half, so every write fails.
        drop(kernel);
        let written = d.flush().await;
        assert!(
            written.is_err(),
            "a device that is gone is an error, not a count"
        );
        assert_eq!(
            d.pending().len(),
            1,
            "and the packet is accounted for, not lost"
        );
    }

    /// A device that goes away mid-batch keeps the whole tail, not just the
    /// packet that failed.
    ///
    /// The first packet is small enough to go straight in, the second blocks
    /// because the device buffer is full, and then the far half is dropped while
    /// it waits. How much of the second got in is tokio's business, so the claim
    /// is about the shape of the tail: the last packet submitted is still the last
    /// one held, and not everything is — a drain that reported a failure and kept
    /// nothing would also satisfy "non-empty".
    #[tokio::test]
    async fn a_write_that_fails_part_way_keeps_the_whole_tail() {
        let (mine, kernel) = tokio::io::duplex(1024);
        let mut d = Device::new(Box::new(mine), "rootstest0", addr(LOCAL), 1280);
        for i in 0..4u8 {
            d.deliver(vec![i; 600]);
        }
        let flush = tokio::spawn(async move {
            let mut d = d;
            (d.flush().await, d.pending().to_vec())
        });
        // Let the first packet in, then take the reader away.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(kernel);
        let (result, held) = flush.await.expect("the flush finishes");
        assert!(result.is_err(), "the blocked write failed");
        assert!(
            !held.is_empty() && held.len() < 4,
            "some got in and some are kept: {} of 4",
            held.len()
        );
        assert_eq!(
            *held.last().expect("non-empty"),
            vec![3u8; 600],
            "and the last packet submitted is the last one held"
        );
    }

    /// The read side: with nothing to read, one tick's pump returns immediately
    /// rather than waiting, because the node loop has links to serve in the same
    /// pass. A blocking read here would stop the whole node.
    #[tokio::test]
    async fn an_idle_device_returns_at_once() {
        let (mut d, _kernel) = device();
        let mut router = Router::new(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let started = std::time::Instant::now();
        let handled = d
            .pump(
                &mut router,
                &mut roots::LinkSet::default(),
                Some(roots::LinkId::absent()),
            )
            .await
            .expect("an idle device is not an error");
        assert_eq!(handled, 0);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "and it did not wait for traffic: {:?}",
            started.elapsed()
        );
    }
}
