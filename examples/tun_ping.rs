//! TUN plumbing over the mesh (demo-client layer): node A owns a real
//! kernel TUN interface with its mesh address; node B (smoltcp ICMP)
//! pings that address through an E2E session over a direct loopback
//! link. The kernel answers the echo, proving TUN→session→mesh→
//! session→TUN in both directions with the OS network stack as peer.
//!
//! Needs `ip` (iproute2) + permission to create TUN interfaces
//! (`/dev/net/tun`, CAP_NET_ADMIN). Run:
//! `cargo run -q --example tun_ping`
//!
//! NOTE: restricted sandboxes (no TUNSETIFF) can only build this;
//! end-to-end verified on a host with TUN privileges.
//!
//! smoltcp and tun are dev-dependencies only — the `roots` lib never
//! sees them; packets cross the boundary as raw bytes via `inbox` and
//! the serve outbox.
//!
//! NOTE: only packets addressed to the peer ride the session (kernel
//! link-local chatter stays local). Besides being correct, this keeps a
//! single session initiator: crossed simultaneous session opens from
//! both ends currently stall (known limitation, see AGENTS.md).

mod common;

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use smoltcp::iface::SocketSet;
use smoltcp::socket::icmp;
use smoltcp::storage::{PacketBuffer, PacketMetadata};
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use roots::{Client, Router};

fn sh(prog: &str, args: &[&str]) {
    let st = std::process::Command::new(prog)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("run {prog} {args:?}: {e}"));
    assert!(st.success(), "{prog} {args:?} failed");
}

#[tokio::main]
async fn main() {
    // Fixed keys => stable addresses, like mesh_tcp.
    let a_sk = SigningKey::from_bytes(&[0xA5; 32]);
    let b_sk = SigningKey::from_bytes(&[0xB6; 32]);
    let (a_pub, b_pub) = (
        a_sk.verifying_key().to_bytes(),
        b_sk.verifying_key().to_bytes(),
    );
    let (a_ip, b_ip) = (
        Ipv6Addr::from(roots::addr_for_key(&a_pub).0),
        Ipv6Addr::from(roots::addr_for_key(&b_pub).0),
    );
    println!("A {a_ip}\nB {b_ip}");

    // Direct loopback link: acceptor only handshakes, both routers live
    // in this task (same shape as mesh_tcp, no internet needed).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = tokio::spawn({
        let b_sk = b_sk.clone();
        async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = roots::LinkOptions::default();
            let (key, _) = roots::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            (sock, key)
        }
    });
    let ca = Client::new(a_sk);
    let uri = format!("tcp://{addr}");
    let mut a_conn = ca.connect(&uri).await.expect("A dial");
    let a_peer = a_conn.remote_key;
    let mut ra = Router::new(ca.key);
    ra.register(&mut a_conn, a_peer).await.expect("A register");
    let mut a_links = roots::LinkSet::single(a_peer, &mut a_conn);
    let (b_sock, b_peer) = accepted.await.unwrap();
    let cb = Client::new(b_sk);
    let mut b_conn = roots::PeerConn::<roots::Tcp> {
        remote_key: b_peer,
        priority: 0,
        stream: b_sock,
    };
    let mut rb = Router::new(cb.key);
    rb.register(&mut b_conn, b_peer).await.expect("B register");
    let mut b_links = roots::LinkSet::single(b_peer, &mut b_conn);

    // A side: real TUN with A's mesh address + route back to B.
    let ifname = format!("roots{}", std::process::id() % 100000);
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(&ifname).mtu(1280).up();
    let mut tun = tun::create_as_async(&cfg).expect("create TUN");
    sh(
        "ip",
        &[
            "addr",
            "add",
            &format!("{a_ip}/128"),
            "dev",
            &ifname,
            "nodad",
        ],
    );
    sh("ip", &["link", "set", &ifname, "up"]);
    sh(
        "ip",
        &["route", "add", &format!("{b_ip}/128"), "dev", &ifname],
    );
    println!("TUN {ifname} up with {a_ip}");

    // B side: smoltcp ICMP pinging A's address.
    let start = Instant::now();
    let mut b_phy = common::MeshPhy::new();
    let mut b_if = common::new_iface(&mut b_phy, b_ip, start);
    let mut b_socks = SocketSet::new(vec![]);
    let b_h = b_socks.add(icmp::Socket::new(
        PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 2048]),
        PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 2048]),
    ));
    b_socks
        .get_mut::<icmp::Socket>(b_h)
        .bind(icmp::Endpoint::Ident(0xbeef))
        .unwrap();
    // Complete ICMPv6 Echo Request (checksum zero: smoltcp fills it on
    // emit; the kernel validates on receipt).
    let mut echo = vec![128, 0, 0, 0];
    echo.extend_from_slice(&0xbeefu16.to_be_bytes());
    echo.extend_from_slice(&1u16.to_be_bytes());
    echo.extend_from_slice(b"roots-tun");

    let mut a_out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut b_out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut ping_sent = false;
    let mut got_reply = false;
    let t0 = Instant::now();
    let end = Instant::now() + Duration::from_secs(45);
    let mut tun_buf = vec![0u8; 1500];
    while Instant::now() < end {
        // Drive both mesh ends.
        if let Err(e) = ra
            .serve(&mut a_links, Some(Duration::from_millis(100)), &mut a_out)
            .await
        {
            eprintln!("A link dropped: {e}");
            break;
        }
        if let Err(e) = rb
            .serve(&mut b_links, Some(Duration::from_millis(100)), &mut b_out)
            .await
        {
            eprintln!("B link dropped: {e}");
            break;
        }
        // A: session payloads -> TUN.
        for (_, pkt) in ra.inbox.drain(..) {
            if std::env::var("TUN_DBG").is_ok() && pkt.len() >= 40 {
                eprintln!(
                    "A->TUN {} -> {} proto={}",
                    Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap()),
                    Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap()),
                    pkt[6]
                );
            }
            if let Err(e) = tun.write_all(&pkt).await {
                eprintln!("TUN write: {e}");
                break;
            }
        }
        // A: TUN -> session (IPv6 only).
        match tokio::time::timeout(Duration::from_millis(20), tun.read(&mut tun_buf)).await {
            Ok(Ok(n)) if n >= 40 && tun_buf[0] >> 4 == 6 => {
                // Only packets for B ride the session (kernel chatter
                // like Router Solicitations stays local).
                let dst = <[u8; 16]>::try_from(&tun_buf[24..40]).unwrap();
                if dst != b_ip.octets() {
                    continue;
                }
                if std::env::var("TUN_DBG").is_ok() {
                    eprintln!(
                        "TUN->A {} -> {} proto={}",
                        Ipv6Addr::from(<[u8; 16]>::try_from(&tun_buf[8..24]).unwrap()),
                        Ipv6Addr::from(dst),
                        tun_buf[6]
                    );
                }
                a_out.push((b_pub, tun_buf[..n].to_vec()));
            }
            _ => {}
        }
        // B: session payloads -> smoltcp ingress.
        for (_, pkt) in rb.inbox.drain(..) {
            b_phy.rx.push_back(pkt);
        }
        b_if.poll(common::smol_now(start), &mut b_phy, &mut b_socks);
        // B: smoltcp egress -> session to A.
        while let Some(pkt) = b_phy.tx.pop_front() {
            b_out.push((a_pub, pkt));
        }
        let sock = b_socks.get_mut::<icmp::Socket>(b_h);
        if sock.can_send() && !ping_sent {
            sock.send_slice(&echo, IpAddress::Ipv6(a_ip)).unwrap();
            ping_sent = true;
            println!("ping sent");
        }
        while sock.can_recv() {
            let mut b = [0u8; 1024];
            match sock.recv_slice(&mut b) {
                Ok((0, _)) | Err(_) => break,
                // Echo Reply (129), code 0, our ident.
                Ok((n, from)) => {
                    println!("reply {n} bytes from {from}");
                    if n >= 8 && b[0] == 129 && b[1] == 0 && b[4..6] == [0xbe, 0xef] {
                        got_reply = true;
                    }
                }
            }
        }
        if got_reply {
            break;
        }
        tokio::task::yield_now().await;
    }

    sh("ip", &["link", "del", &ifname]);
    println!("TUN {ifname} removed");
    assert!(ping_sent, "echo request left B");
    assert!(got_reply, "kernel echo reply arrived via TUN+mesh");
    println!("RTT ~= {:?} (mesh round trip incl. kernel)", t0.elapsed());
}
