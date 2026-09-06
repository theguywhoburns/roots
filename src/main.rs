//! Demo client: connect to one peer, converge, optionally resolve an
//! address and fetch its nodeinfo, hold the link, report status.
//!
//! Run: `cargo run -- [peer-uri] [hold_secs] [resolve-ipv6]`

use std::time::Duration;

use roots::{Client, Router, addr_for_key};

fn show(tag: &str, key: &[u8; 32]) {
    println!("{tag:<8} {} {}", hex::encode(key), addr_for_key(key));
}

fn report(router: &Router) {
    match router.parent() {
        Some(p) => show("parent", &p),
        None => println!("parent   <none>"),
    }
    match router.root_and_depth() {
        Some((r, d)) => {
            show("root", &r);
            println!("depth    {d}");
        }
        None => println!("root     <unknown>"),
    }
    println!(
        "known    {} nodes, announces sent {}/{}, frames {:?}",
        router.known_nodes(),
        router.announces_sent,
        router.announces_recv,
        router.frames
    );
    if std::env::var("ROOTS_DBG_DUMP").is_ok() {
        print!("{}", router.dump());
    }
}

async fn run<T: roots::Transport>(
    client: Client,
    mut conn: roots::PeerConn<T>,
    hold: Option<std::time::Duration>,
    resolve: Option<roots::address::Address>,
) {
    show("remote", &conn.remote_key);
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    let mut no_out = Vec::new();
    if let Err(e) = router.register(&mut conn, peer_key).await {
        eprintln!("register failed: {e}");
        std::process::exit(1);
    }
    let mut links = roots::LinkSet::single(peer_key, &mut conn);
    // Converge first so resolve/session have a tree to work with.
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && std::time::Instant::now() < end {
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
    }
    if router.parent().is_none() {
        eprintln!("mesh convergence timed out");
        std::process::exit(1);
    }
    if let Some(addr) = resolve {
        match router
            .resolve(&mut links, peer_key, &addr, Duration::from_secs(60))
            .await
        {
            Ok(key) => {
                show("target", &key);
                if let Err(e) = router.request_nodeinfo(&mut links, peer_key, key).await {
                    eprintln!("nodeinfo request failed: {e}");
                } else {
                    // Pump briefly for the reply.
                    let end = std::time::Instant::now() + Duration::from_secs(15);
                    while std::time::Instant::now() < end {
                        if router.proto_inbox.iter().any(|(k, p)| {
                            *k == key && p.first() == Some(&roots::proto::PROTO_NODEINFO_RES)
                        }) {
                            break;
                        }
                        if let Err(e) = router
                            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
                            .await
                        {
                            eprintln!("link dropped: {e}");
                            std::process::exit(1);
                        }
                    }
                    for (k, p) in router.proto_inbox.drain(..).filter(|(k, _)| *k == key) {
                        println!(
                            "nodeinfo {}: {}",
                            hex::encode(k),
                            String::from_utf8_lossy(&p[1..])
                        );
                    }
                }
            }
            Err(e) => eprintln!("resolve failed: {e}"),
        }
    }
    if let Err(e) = router.serve(&mut links, hold, &mut no_out).await {
        eprintln!("link dropped: {e}");
        std::process::exit(1);
    }
    report(&router);
}

#[tokio::main]
async fn main() {
    let uri = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let hold_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(45);
    let hold = Some(std::time::Duration::from_secs(hold_secs));
    let resolve = std::env::args().nth(3).and_then(|s| {
        s.parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| roots::address::Address(ip.octets()))
    });
    let mut rng = rand::thread_rng();
    let key = ed25519_dalek::SigningKey::generate(&mut rng);
    let client = Client::new(key);
    println!("local  addr {}", client.address());
    if uri.starts_with("tls://") {
        match client.connect_tls(&uri).await {
            Ok(conn) => run(client, conn, hold, resolve).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if uri.starts_with("ws://") {
        match client.connect_ws(&uri).await {
            Ok(conn) => run(client, conn, hold, resolve).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if uri.starts_with("wss://") {
        match client.connect_wss(&uri).await {
            Ok(conn) => run(client, conn, hold, resolve).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if uri.starts_with("quic://") {
        match client.connect_quic(&uri).await {
            Ok(conn) => run(client, conn, hold, resolve).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    match client.connect(&uri).await {
        Ok(conn) => run(client, conn, hold, resolve).await,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(1);
        }
    }
}
