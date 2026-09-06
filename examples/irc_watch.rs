//! IRC over the mesh: resolve a server address, open an E2E session, run
//! TCP (via smoltcp), register, LIST channels, join the busiest one, and
//! print users + messages.
//!
//! Run: `cargo run -q --example irc_watch -- [324:71e:281a:9ed3::41] [peer]`
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
        .unwrap_or("324:71e:281a:9ed3::41")
        .parse()
        .expect("target IPv6");
    let target_bytes: [u8; 16] = target.octets();
    let target_addr = roots::address::Address(target_bytes);
    let peer = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let join_arg = std::env::args().nth(3).unwrap_or_default();
    let nick = format!("roots{:04x}", rand::random::<u16>());

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
    // One set for the whole run (see http_fetch).
    let mut links = roots::LinkSet::single(peer_key, &mut conn);
    let mut no_out = Vec::new();
    let end = Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && Instant::now() < end {
        router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
            .expect("link up");
    }
    assert!(router.parent().is_some(), "mesh convergence timed out");

    let key = router
        .resolve(&mut links, peer_key, &target_addr, Duration::from_secs(60))
        .await
        .expect("resolve target");
    println!("target key {} as {nick}", hex::encode(key));

    let start = Instant::now();
    let mut phy = common::MeshPhy::new();
    let mut iface = common::new_iface(&mut phy, our_ip, start);
    let mut sockets = SocketSet::new(vec![]);
    let handle = common::new_tcp_socket(&mut sockets);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            IpEndpoint::new(IpAddress::Ipv6(target), 6667),
            40001u16,
        )
        .expect("tcp connect");
    let mut outbox: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    let mut line_buf: Vec<u8> = Vec::new();
    let mut registered = false;
    let mut listed = false;
    // (channel, users) from LIST replies.
    let mut channels: Vec<(String, u64)> = Vec::new();
    let mut end_list_seen = false;
    let end = Instant::now() + Duration::from_secs(600);

    loop {
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut outbox)
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
        for (_, pkt) in router.inbox.drain(..) {
            phy.rx.push_back(pkt);
        }
        iface.poll(common::smol_now(start), &mut phy, &mut sockets);
        while let Some(pkt) = phy.tx.pop_front() {
            outbox.push((key, pkt));
        }
        {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            if sock.can_send() && !registered {
                sock.send_slice(
                    format!("NICK {nick}\r\nUSER {nick} 0 * :roots demo\r\n").as_bytes(),
                )
                .expect("send register");
                registered = true;
                println!("registered as {nick}");
            }
            while sock.can_recv() {
                let mut buf = [0u8; 4096];
                let n = sock.recv_slice(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                line_buf.extend_from_slice(&buf[..n]);
            }
        }
        // Process complete lines.
        while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = line_buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            println!("S: {line}");
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            // PING/PONG keepalive.
            if parts.first() == Some(&"PING") {
                let token = parts.get(1).copied().unwrap_or("");
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if sock.can_send() {
                    let _ = sock.send_slice(format!("PONG {token}\r\n").as_bytes());
                }
                continue;
            }
            // Numeric replies: <server> <code> <nick> ...
            if parts.len() >= 2 {
                match parts[1] {
                    // End of MOTD (or no MOTD): time to LIST.
                    "376" | "422" if !listed => {
                        listed = true;
                        let sock = sockets.get_mut::<tcp::Socket>(handle);
                        if sock.can_send() {
                            let _ = sock.send_slice(b"LIST\r\n");
                            println!("C: LIST");
                        }
                    }
                    // LIST entry: <#chan> <users> :<topic>
                    "322" if parts.len() >= 4 => {
                        let rest = parts[3..].join(" ");
                        let mut it = rest.splitn(2, ' ');
                        if let (Some(chan), Some(count)) = (it.next(), it.next())
                            && let Ok(n) = count.split(' ').next().unwrap_or("0").parse::<u64>()
                        {
                            channels.push((chan.to_string(), n));
                        }
                    }
                    // End of LIST: join the requested or busiest channel.
                    "323" if !end_list_seen => {
                        end_list_seen = true;
                        channels.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
                        println!("channels (top 10):");
                        for (c, n) in channels.iter().take(10) {
                            println!("  {c} ({n} users)");
                        }
                        let best = if join_arg.is_empty() {
                            channels.first().map(|(c, _)| c.clone())
                        } else {
                            Some(join_arg.clone())
                        };
                        if let Some(best) = best {
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            if sock.can_send() {
                                let _ = sock.send_slice(format!("JOIN {best}\r\n").as_bytes());
                                println!("C: JOIN {best}");
                            }
                        }
                    }
                    // NAMES reply: show users.
                    "353" => {
                        if let Some(names) = line.split(" :").nth(1) {
                            let users: Vec<&str> = names.split(' ').collect();
                            println!("users ({}): {}", users.len(), users.join(" "));
                        } else {
                            println!("names: {}", parts.get(3).copied().unwrap_or(""));
                        }
                    }
                    _ => {}
                }
            }
        }
        if Instant::now() > end {
            println!("watch window over");
            break;
        }
    }
}
