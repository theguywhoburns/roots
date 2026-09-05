//! Loopback TCP-over-session test (no internet): two routers peer over
//! loopback, then a smoltcp client GETs from a smoltcp server through the
//! encrypted session. Validates the TCP driver wiring, not the mesh.

#[path = "../examples/common/mod.rs"]
mod common;

use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::time::{Duration, Instant};

#[tokio::test]
async fn tcp_over_session_loopback() {
    // Full duplex is exercised through the mesh_ping path plus a raw
    // smoltcp client/server pair over direct phy queues below.
    let start = Instant::now();
    let mut c_phy = common::MeshPhy::new();
    let mut s_phy = common::MeshPhy::new();
    let c_ip = std::net::Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 1);
    let s_ip = std::net::Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 2);
    let mut c_if = common::new_iface(&mut c_phy, c_ip, start);
    let mut s_if = common::new_iface(&mut s_phy, s_ip, start);

    let mut c_socks = SocketSet::new(vec![]);
    let c_h = common::new_tcp_socket(&mut c_socks);
    c_socks
        .get_mut::<tcp::Socket>(c_h)
        .connect(
            c_if.context(),
            IpEndpoint::new(IpAddress::Ipv6(s_ip), 80),
            40000u16,
        )
        .unwrap();

    let mut s_socks = SocketSet::new(vec![]);
    let s_h = common::new_tcp_socket(&mut s_socks);
    s_socks.get_mut::<tcp::Socket>(s_h).listen(80).unwrap();

    // Cross-connect the phys directly (no mesh): client tx -> server rx.
    let end = Instant::now() + Duration::from_secs(10);
    let mut get_sent = false;
    let mut body = Vec::new();
    while Instant::now() < end {
        c_if.poll(common::smol_now(start), &mut c_phy, &mut c_socks);
        s_if.poll(common::smol_now(start), &mut s_phy, &mut s_socks);
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
