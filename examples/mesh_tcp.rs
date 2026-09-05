//! Bilateral TCP over the public mesh (needs internet): node A fetches HTTP
//! from node B's smoltcp server, both peered via public Go nodes. If this
//! works while a foreign target stays silent, the far end is filtering us.
//!
//! Run: `cargo run -q --example mesh_tcp -- tcp://bode.theender.net:42069`

mod common;

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use roots::{Client, Router};

async fn drive(
    router: &mut Router,
    conn: &mut roots::PeerConn<roots::Tcp>,
    peer: [u8; 32],
    outbox: &mut Vec<([u8; 32], Vec<u8>)>,
) -> bool {
    router
        .serve(conn, peer, Some(Duration::from_millis(250)), outbox)
        .await
        .is_ok()
}

#[tokio::main]
async fn main() {
    let peer_uri = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let a_sk = SigningKey::from_bytes(&[0xA5; 32]);
    let b_sk = SigningKey::from_bytes(&[0xB6; 32]);
    let (a_pub, b_pub) = (
        a_sk.verifying_key().to_bytes(),
        b_sk.verifying_key().to_bytes(),
    );
    let (a_ip, b_ip) = (
        std::net::Ipv6Addr::from(roots::addr_for_key(&a_pub).0),
        std::net::Ipv6Addr::from(roots::addr_for_key(&b_pub).0),
    );
    println!("A {a_ip}\nB {b_ip}");

    // Both nodes converge first (sequential dials avoid burst limits).
    let ca = Client::new(a_sk);
    let mut a_conn = ca.connect(&peer_uri).await.expect("A dial");
    let a_peer = a_conn.remote_key;
    let mut ra = Router::new(ca.key);
    ra.register(&mut a_conn, a_peer).await.expect("A register");
    let mut no_out = Vec::new();
    let end = Instant::now() + Duration::from_secs(60);
    while ra.parent().is_none() && Instant::now() < end {
        if !drive(&mut ra, &mut a_conn, a_peer, &mut no_out).await {
            eprintln!("A link dropped");
            std::process::exit(1);
        }
    }
    assert!(ra.parent().is_some(), "A converge timeout");
    let cb = Client::new(b_sk);
    let mut b_conn = cb.connect(&peer_uri).await.expect("B dial");
    let b_peer = b_conn.remote_key;
    let mut rb = Router::new(cb.key);
    rb.register(&mut b_conn, b_peer).await.expect("B register");
    let end = Instant::now() + Duration::from_secs(60);
    while rb.parent().is_none() && Instant::now() < end {
        if !drive(&mut rb, &mut b_conn, b_peer, &mut no_out).await {
            eprintln!("B link dropped");
            std::process::exit(1);
        }
    }
    assert!(rb.parent().is_some(), "B converge timeout");
    println!("both converged");

    // Stacks: A client -> B server port 80.
    let start = Instant::now();
    let mut a_phy = common::MeshPhy::new();
    let mut b_phy = common::MeshPhy::new();
    let mut a_if = common::new_iface(&mut a_phy, a_ip, start);
    let mut b_if = common::new_iface(&mut b_phy, b_ip, start);

    let mut a_socks = SocketSet::new(vec![]);
    let c_h = common::new_tcp_socket(&mut a_socks);
    a_socks
        .get_mut::<tcp::Socket>(c_h)
        .connect(
            a_if.context(),
            IpEndpoint::new(IpAddress::Ipv6(b_ip), 80),
            40000u16,
        )
        .unwrap();
    let mut b_socks = SocketSet::new(vec![]);
    let s_h = common::new_tcp_socket(&mut b_socks);
    b_socks.get_mut::<tcp::Socket>(s_h).listen(80).unwrap();

    let mut a_out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut b_out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut get_sent = false;
    let mut body = Vec::new();
    let end = Instant::now() + Duration::from_secs(150);
    let ok = loop {
        if !drive(&mut ra, &mut a_conn, a_peer, &mut a_out).await {
            eprintln!("A link dropped");
            break false;
        }
        if !drive(&mut rb, &mut b_conn, b_peer, &mut b_out).await {
            eprintln!("B link dropped");
            break false;
        }
        for (_, p) in ra.inbox.drain(..) {
            a_phy.rx.push_back(p);
        }
        for (_, p) in rb.inbox.drain(..) {
            b_phy.rx.push_back(p);
        }
        a_if.poll(common::smol_now(start), &mut a_phy, &mut a_socks);
        b_if.poll(common::smol_now(start), &mut b_phy, &mut b_socks);
        while let Some(p) = a_phy.tx.pop_front() {
            a_out.push((b_pub, p));
        }
        while let Some(p) = b_phy.tx.pop_front() {
            b_out.push((a_pub, p));
        }
        {
            let c = a_socks.get_mut::<tcp::Socket>(c_h);
            if c.can_send() && !get_sent {
                c.send_slice(b"GET / HTTP/1.0\r\n\r\n").unwrap();
                get_sent = true;
                println!("GET sent");
            }
            while c.can_recv() {
                let mut b = [0u8; 4096];
                match c.recv_slice(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&b[..n]),
                }
            }
            if get_sent && !body.is_empty() && !c.may_recv() {
                break true;
            }
        }
        {
            let s = b_socks.get_mut::<tcp::Socket>(s_h);
            if s.can_recv() {
                let mut b = [0u8; 4096];
                while let Ok(n) = s.recv_slice(&mut b) {
                    if n == 0 {
                        break;
                    }
                }
                s.send_slice(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .unwrap();
                s.close();
            }
        }
        if Instant::now() > end {
            eprintln!("mesh tcp timed out");
            break false;
        }
    };
    println!(
        "client got {} bytes: {:?}",
        body.len(),
        String::from_utf8_lossy(&body)
    );
    if !ok {
        std::process::exit(1);
    }
}
