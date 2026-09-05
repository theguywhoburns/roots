//! Session-proto probe: peer a (local or public) Go node, exchange
//! nodeinfo + debug getSelf/getPeers/getTree with it, and print both
//! directions. Proves our `src/proto.rs` responders satisfy stock Go
//! (`getNodeInfo` / `debug_remoteGet*` admin handlers) and our requesters
//! parse theirs.
//!
//! Run: `cargo run -q --example proto_probe -- [peer-uri]`
//! Then, while it pumps, query the Go side for OUR nodeinfo, e.g.
//! `yggdrasilctl -endpoint=tcp://127.0.0.1:19001 getNodeInfo key=<our key>`.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::{Client, Router, proto::*};

#[tokio::main]
async fn main() {
    let peer = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://127.0.0.1:18233".to_string());
    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!(
        "our key {}",
        hex::encode(client.key.verifying_key().to_bytes())
    );
    println!("local addr {}", client.address());
    // Scheme-aware dial so one probe covers every transport.
    if peer.starts_with("ws://") {
        let conn = client.connect_ws(&peer).await.expect("dial ws peer");
        run_probe(client, conn).await;
        return;
    }
    if peer.starts_with("tls://") {
        let conn = client.connect_tls(&peer).await.expect("dial tls peer");
        run_probe(client, conn).await;
        return;
    }
    let conn = client.connect(&peer).await.expect("dial peer");
    run_probe(client, conn).await;
}

async fn run_probe<T: roots::Transport>(client: Client, mut conn: roots::PeerConn<T>) {
    let peer_key = conn.remote_key;
    println!("peer key {}", hex::encode(peer_key));
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    let mut no_out = Vec::new();
    let end = Instant::now() + Duration::from_secs(30);
    while router.parent().is_none() && Instant::now() < end {
        router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(250)),
                &mut no_out,
            )
            .await
            .expect("link up");
    }
    assert!(router.parent().is_some(), "mesh convergence timed out");
    println!("converged");

    router
        .set_nodeinfo(br#"{"roots":"proto-probe"}"#.to_vec())
        .expect("nodeinfo fits");
    // The first request opens the session (buffered behind the init
    // handshake, like Go's single-slot sessionBuffer — which is also
    // why the rest wait for the session: last write wins the buffer).
    router
        .request_nodeinfo(&mut conn, peer_key, peer_key)
        .await
        .expect("nodeinfo req");
    let mut outbox: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let end = Instant::now() + Duration::from_secs(15);
    while !router.has_session(&peer_key) && Instant::now() < end {
        router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(250)),
                &mut outbox,
            )
            .await
            .expect("link up");
    }
    assert!(router.has_session(&peer_key), "session never opened");
    for what in [DEBUG_GETSELF_REQ, DEBUG_GETPEERS_REQ, DEBUG_GETTREE_REQ] {
        router
            .request_debug(&mut conn, peer_key, peer_key, what)
            .await
            .expect("debug req");
    }
    println!("requests sent — pump 30s (query our nodeinfo from the Go side now)");

    let end = Instant::now() + Duration::from_secs(30);
    let mut seen = 0;
    while Instant::now() < end {
        if let Err(e) = router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(250)),
                &mut outbox,
            )
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
        for (k, p) in router.proto_inbox.drain(..) {
            seen += 1;
            let from = hex::encode(k);
            match p.first() {
                Some(&PROTO_NODEINFO_RES) => {
                    println!("NODEINFO from {from}: {}", String::from_utf8_lossy(&p[1..]));
                }
                Some(&PROTO_DEBUG) => match p.get(1) {
                    Some(&DEBUG_GETSELF_RES) => {
                        println!("GETSELF from {from}: {}", String::from_utf8_lossy(&p[2..]));
                    }
                    Some(&DEBUG_GETPEERS_RES) => {
                        println!("GETPEERS from {from}: {} keys", p[2..].len() / 32);
                        for k in p[2..].as_chunks::<32>().0 {
                            println!("  peer {}", hex::encode(k));
                        }
                    }
                    Some(&DEBUG_GETTREE_RES) => {
                        println!("GETTREE from {from}: {} keys", p[2..].len() / 32);
                    }
                    other => println!("DEBUG/?{other:?} from {from} ({} bytes)", p.len()),
                },
                other => println!("PROTO/?{other:?} from {from} ({} bytes)", p.len()),
            }
        }
        if seen >= 4 {
            break;
        }
    }
    println!("seen {seen} proto replies");
    // Optional extra hold (seconds) so the Go side can be asked for OUR
    // nodeinfo/debug while we are still up:
    // `cargo run -q --example proto_probe -- <peer> 60`
    let hold: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let end = Instant::now() + Duration::from_secs(hold);
    while Instant::now() < end {
        if let Err(e) = router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(250)),
                &mut outbox,
            )
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
        for (k, p) in router.proto_inbox.drain(..) {
            println!("late PROTO from {} ({} bytes)", hex::encode(k), p.len());
        }
    }
}
