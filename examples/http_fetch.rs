//! Fetch http://<ygg-ipv6>/ over the mesh: resolve the address to a node
//! key, open an E2E session, and run TCP (via smoltcp) through it.
//!
//! Run: `cargo run --example http_fetch -- [21e:a51c:885b:7db0:166e:927:98cd:d186]`
//!
//! smoltcp is a dev-dependency only — the `roots` lib never sees it.

mod common;

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use roots::{Client, Router};

#[tokio::main]
async fn main() {
    let target: Ipv6Addr = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("21e:a51c:885b:7db0:166e:927:98cd:d186")
        .parse()
        .expect("target IPv6");
    let peer = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let page_path = std::env::args().nth(3).unwrap_or_else(|| "/".to_string());
    let target_bytes: [u8; 16] = target.octets();
    let target_addr = roots::address::Address(target_bytes);

    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!("local  addr {}", client.address());
    let our_ip = Ipv6Addr::from(client.address().0);
    let mut conn = client.connect(&peer).await.expect("dial public peer");
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    // One set for the whole run: per-link send clocks must survive
    // slices, or lazy keepalives never fire and the peer times us out.
    let mut links = roots::LinkSet::single(peer_key, &mut conn);
    let mut no_out = Vec::new();

    // Converge: short serve slices until we have a parent.
    let end = Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && Instant::now() < end {
        router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
            .expect("link up");
    }
    assert!(router.parent().is_some(), "mesh convergence timed out");
    println!("converged, resolving {target} ...");

    // Address -> full node key over the DHT.
    let key = router
        .resolve(&mut links, peer_key, &target_addr, Duration::from_secs(60))
        .await
        .expect("resolve target");
    println!("target key {}", hex::encode(key));

    // smoltcp stack with our address, default route into the mesh device.
    let start = Instant::now();
    let mut phy = common::MeshPhy::new();
    let mut iface = common::new_iface(&mut phy, our_ip, start);
    let mut sockets = SocketSet::new(vec![]);
    let handle = common::new_tcp_socket(&mut sockets);
    let remote = IpEndpoint::new(IpAddress::Ipv6(target), 80);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(iface.context(), remote, 40000)
        .expect("tcp connect");
    let mut outbox: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut get_sent = false;

    let end = Instant::now() + Duration::from_secs(120);
    let page = loop {
        // Drive the mesh link briefly.
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut outbox)
            .await
        {
            eprintln!("link dropped: {e}");
            break None;
        }
        // Session payloads -> stack ingress.
        for (_, pkt) in router.inbox.drain(..) {
            phy.rx.push_back(pkt);
        }
        // Poll TCP.
        iface.poll(common::smol_now(start), &mut phy, &mut sockets);
        // Stack egress -> mesh outbox.
        while let Some(pkt) = phy.tx.pop_front() {
            outbox.push((key, pkt));
        }
        {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            if sock.can_send() && !get_sent {
                sock.send_slice(
                    format!("GET {page_path} HTTP/1.0\r\nHost: ygg\r\nUser-Agent: roots-demo\r\nAccept: */*\r\n\r\n").as_bytes(),
                )
                .expect("send GET");
                get_sent = true;
                println!("GET sent");
            }
            while sock.can_recv() {
                let mut buf = [0u8; 4096];
                let n = sock.recv_slice(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            if get_sent && !sock.may_recv() && !sock.can_recv() {
                break Some(body.clone());
            }
            if sock.state() == tcp::State::Closed {
                break Some(body.clone());
            }
        }
        if Instant::now() > end {
            eprintln!("fetch timed out");
            break None;
        }
    };

    match page {
        Some(body) => {
            println!("--- {} bytes ---", body.len());
            println!("{}", String::from_utf8_lossy(&body));
        }
        None => std::process::exit(1),
    }
}
