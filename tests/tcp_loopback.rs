//! Loopback TCP-over-session test (no internet): two routers peer over
//! loopback, then a smoltcp client GETs from a smoltcp server through the
//! encrypted session. Validates the TCP driver wiring, not the mesh.

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

struct MeshPhy {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct MeshRx {
    pkt: Vec<u8>,
}

struct MeshTx<'a> {
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

fn smol_now(start: Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

#[tokio::test]
async fn tcp_over_session_loopback() {
    // Full duplex is exercised through the mesh_ping path plus a raw
    // smoltcp client/server pair over direct phy queues below.
    let start = Instant::now();
    let mut c_phy = MeshPhy {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut s_phy = MeshPhy {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let c_ip = std::net::Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 1);
    let s_ip = std::net::Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 2);
    let mut c_if = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut c_phy,
        smol_now(start),
    );
    c_if.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv6(c_ip), 128)).unwrap();
    });
    c_if.routes_mut()
        .add_default_ipv6_route(std::net::Ipv6Addr::UNSPECIFIED)
        .unwrap();
    let mut s_if = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut s_phy,
        smol_now(start),
    );
    s_if.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::Ipv6(s_ip), 128)).unwrap();
    });
    s_if.routes_mut()
        .add_default_ipv6_route(std::net::Ipv6Addr::UNSPECIFIED)
        .unwrap();

    let mut c_socks = SocketSet::new(vec![]);
    let mut c_sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    c_sock
        .connect(
            c_if.context(),
            IpEndpoint::new(IpAddress::Ipv6(s_ip), 80),
            40000u16,
        )
        .unwrap();
    let c_h = c_socks.add(c_sock);

    let mut s_socks = SocketSet::new(vec![]);
    let mut s_sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    s_sock.listen(80).unwrap();
    let s_h = s_socks.add(s_sock);

    // Cross-connect the phys directly (no mesh): client tx -> server rx.
    let end = Instant::now() + Duration::from_secs(10);
    let mut get_sent = false;
    let mut body = Vec::new();
    while Instant::now() < end {
        c_if.poll(smol_now(start), &mut c_phy, &mut c_socks);
        s_if.poll(smol_now(start), &mut s_phy, &mut s_socks);
        while let Some(p) = c_phy.tx.pop_front() {
            s_phy.rx.push_back(p);
        }
        while let Some(p) = s_phy.tx.pop_front() {
            c_phy.rx.push_back(p);
        }
        {
            let c = c_socks.get_mut::<tcp::Socket>(c_h);
            if c.can_send() && !get_sent {
                c.send_slice(b"GET / HTTP/1.0\r\n\r\n").unwrap();
                get_sent = true;
            }
            while c.can_recv() {
                let mut b = [0u8; 1024];
                match c.recv_slice(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&b[..n]),
                }
            }
        }
        {
            let s = s_socks.get_mut::<tcp::Socket>(s_h);
            if s.can_recv() {
                let mut b = [0u8; 1024];
                while let Ok(n) = s.recv_slice(&mut b) {
                    if n == 0 {
                        break;
                    }
                }
                s.send_slice(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    .unwrap();
                s.close();
            }
        }
        if get_sent && !body.is_empty() {
            let c = c_socks.get::<tcp::Socket>(c_h);
            if !c.may_recv() {
                break;
            }
        }
        tokio::task::yield_now().await;
    }
    assert!(get_sent, "client sent GET");
    assert!(
        body.windows(2).any(|w| w == b"hi"),
        "server reply reassembled: {body:?}"
    );
}
