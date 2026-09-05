//! Shared smoltcp bridge for the mesh examples (dev-dependencies only).
//!
//! The `roots` lib never sees smoltcp: each example owns one Yggdrasil
//! session whose payloads are raw IPv6 packets, and this device shuttles
//! them between `Router::inbox`/outbox and a smoltcp `Interface`.
//!
//! Import with `mod common;` (shared sibling module, not an example
//! target — it lives at `examples/common/mod.rs` so Cargo doesn't try
//! to build it standalone).

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
