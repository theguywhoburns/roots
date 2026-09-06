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

fn ipv6_echo(src: &[u8; 16], dst: &[u8; 16], ident: u16, seqno: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + 8 + data.len()];
    pkt[0] = 0x60;
    let icmp_len = (8 + data.len()) as u16;
    pkt[4..6].copy_from_slice(&icmp_len.to_be_bytes());
    pkt[6] = 58; // ICMPv6
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(src);
    pkt[24..40].copy_from_slice(dst);
    pkt[40] = 128; // echo request
    pkt[42..44].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt[44..46].copy_from_slice(&ident.to_be_bytes());
    pkt[46..48].copy_from_slice(&seqno.to_be_bytes());
    pkt[48..].copy_from_slice(data);
    let csum = checksum(src, dst, icmp_len, &pkt[40..]);
    pkt[42..44].copy_from_slice(&csum.to_be_bytes());
    pkt
}

fn echo_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 48 || req[6] != 58 || req[40] != 128 {
        return None;
    }
    let mut rep = req.to_vec();
    rep[8..24].copy_from_slice(&req[24..40]); // src = old dst
    rep[24..40].copy_from_slice(&req[8..24]); // dst = old src
    rep[40] = 129; // echo reply
    rep[42..44].copy_from_slice(&[0, 0]);
    let src: [u8; 16] = rep[8..24].try_into().ok()?;
    let dst: [u8; 16] = rep[24..40].try_into().ok()?;
    let len = u16::from_be_bytes([rep[4], rep[5]]);
    let csum = checksum(&src, &dst, len, &rep[40..]);
    rep[42..44].copy_from_slice(&csum.to_be_bytes());
    Some(rep)
}

fn checksum(src: &[u8; 16], dst: &[u8; 16], len: u16, icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in src.chunks(2).chain(dst.chunks(2)) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    sum += len as u32;
    sum += 58u32;
    let mut i = 0;
    while i + 1 < icmp.len() {
        sum += u16::from_be_bytes([icmp[i], icmp[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp.len() {
        sum += (icmp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn run_node(key: SigningKey, outgoing: Vec<([u8; 32], Vec<u8>)>) -> Router {
    let client = Client::new(key);
    let mut conn = dial_retry(PEER, &client).await;
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    let mut outgoing = outgoing;
    let mut links = roots::LinkSet::single(peer_key, &mut conn);
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
    let echo = ipv6_echo(&a_addr, &b_addr, 0x1234, 1, b"mesh-ping-0");
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
    let reply = echo_reply(&got.1).expect("valid echo request");
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
