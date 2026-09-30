//! Live mesh test (needs internet): two Rust nodes peer with the same public
//! Go node, then exchange IPv6 ICMPv6 echo request/reply end-to-end.
//!
//! Run: `cargo test --test mesh_ping -- --ignored --nocapture`
//!
//! Proves: spanning-tree convergence, DHT lookup, E2E box sessions, and
//! traffic forwarding interoperate with the real network in both directions.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use roots::{Client, Router, addr_for_key};

const PEER: &str = "tcp://bode.theender.net:42069";
const HOLD: Duration = Duration::from_secs(75);

async fn dial_retry(peer: &str, client: &Client) -> roots::PeerConn<roots::Tcp> {
    let mut last = String::new();
    for _ in 0..4 {
        match client.connect(peer).await {
            Ok(c) => return c,
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    panic!("dial {peer}: {last}");
}
#[path = "../examples/common/mod.rs"]
mod common;

async fn run_node(key: SigningKey, outgoing: Vec<([u8; 32], Vec<u8>)>) -> Router {
    let client = Client::new(key);
    let conn = dial_retry(PEER, &client).await;
    let peer_key = conn.remote_key;
    let mut conn = roots::link::AnyConn::new(conn);
    let id = conn.id;
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key, id)
        .await
        .expect("register");
    let mut outgoing = outgoing;
    let mut links = roots::LinkSet::single(conn);
    router
        .serve(&mut links, Some(HOLD), &mut outgoing)
        .await
        .expect("serve link");
    router
}

#[tokio::test]
#[ignore]
async fn mesh_ping_through_public_peer() {
    let a_sk = SigningKey::from_bytes(&[0xA5; 32]);
    let b_sk = SigningKey::from_bytes(&[0xB6; 32]);
    let a_pub = a_sk.verifying_key().to_bytes();
    let b_pub = b_sk.verifying_key().to_bytes();
    let a_addr = addr_for_key(&a_pub).0;
    let b_addr = addr_for_key(&b_pub).0;
    println!("A {}", addr_for_key(&a_pub));
    println!("B {}", addr_for_key(&b_pub));

    // Phase 1: A -> B echo request (staggered dials avoid burst limits).
    let echo = common::icmp6_echo(128, &a_addr, &b_addr, 0x1234, 1, b"mesh-ping-0");
    let b_task = tokio::spawn(run_node(b_sk.clone(), vec![]));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let a_task = tokio::spawn(run_node(a_sk.clone(), vec![(b_pub, echo.clone())]));
    let (a_r, b_r) = tokio::join!(a_task, b_task);
    let (a_r, b_r) = (a_r.unwrap(), b_r.unwrap());
    println!(
        "A: parent={} known={} frames={:?}",
        a_r.parent().map(hex::encode).unwrap_or_default(),
        a_r.known_nodes(),
        a_r.frames
    );
    println!(
        "B: parent={} known={} frames={:?}",
        b_r.parent().map(hex::encode).unwrap_or_default(),
        b_r.known_nodes(),
        b_r.frames
    );
    let got = b_r
        .inbox
        .iter()
        .find(|(from, _)| *from == a_pub)
        .expect("B received A's session payload");
    assert_eq!(got.1, echo, "echo request bytes intact");

    // Phase 2: B -> A echo reply (fresh links, same keys).
    let reply = common::icmp6_echo_reply(&got.1).expect("valid echo request");
    let b_task = tokio::spawn(run_node(b_sk, vec![(a_pub, reply.clone())]));
    let a_task = tokio::spawn(run_node(a_sk, vec![]));
    let (a_r, _) = tokio::join!(a_task, b_task);
    let a_r = a_r.unwrap();
    let got_back = a_r
        .inbox
        .iter()
        .find(|(from, _)| *from == b_pub)
        .expect("A received B's echo reply");
    assert_eq!(got_back.1, reply, "echo reply bytes intact");
    assert_eq!(got_back.1[40], 129, "reply type");
    println!("mesh ping OK both directions");
}
