//! Ping a mesh address with ICMPv6 echo through an E2E session.
//! Decides whether a target is reachable at all (vs TCP specifically).
//!
//! Run: `cargo run -q --example ping6 -- 21e:a51c:885b:7db0:166e:927:98cd:d186`

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use roots::{Client, Router};

mod common;

#[tokio::main]
async fn main() {
    let target: Ipv6Addr = std::env::args()
        .nth(1)
        .expect("usage: ping6 <ipv6>")
        .parse()
        .expect("target IPv6");
    let target_bytes: [u8; 16] = target.octets();
    let target_addr = roots::address::Address(target_bytes);

    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!("local  addr {}", client.address());
    let our_bytes: [u8; 16] = client.address().0;
    let peer_uri = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let conn = client.connect(&peer_uri).await.expect("dial public peer");
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    let mut conn = roots::link::AnyConn::new(conn);
    let link = conn.id;
    router
        .register(&mut conn, peer_key, link)
        .await
        .expect("register");
    // One set for the whole run: per-link send clocks must survive slices.
    let mut links = roots::LinkSet::single(conn);
    let mut no_out = Vec::new();

    let end = Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && Instant::now() < end {
        router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
            .expect("link up");
    }
    assert!(router.parent().is_some(), "convergence timed out");

    let key = router
        .resolve(&mut links, link, &target_addr, Duration::from_secs(60))
        .await
        .expect("resolve target");
    println!("target key {}", hex::encode(key));

    // ICMPv6 echo request, id/seq fixed for matching.
    let ident = 0xbeefu16;
    let seqno = 1u16;
    let data = b"roots-ping";
    let echo_request = || common::icmp6_echo(128, &our_bytes, &target_bytes, ident, seqno, data);

    let mut outbox = vec![(key, echo_request())];
    let end = Instant::now() + Duration::from_secs(90);
    let mut got = 0;
    while Instant::now() < end {
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut outbox)
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
        for (from, p) in router.inbox.drain(..) {
            if from == key
                && p.len() >= 48
                && p[6] == 58
                && p[40] == 129
                && p[44..46] == ident.to_be_bytes()
                && p[46..48] == seqno.to_be_bytes()
                && p[48..] == data[..]
            {
                got += 1;
                println!("echo reply #{got} from {target}");
                if got >= 2 {
                    println!("target IS reachable; TCP/80 specifically is unanswered");
                    return;
                }
                outbox.push((key, echo_request()));
            }
        }
    }
    if got == 0 {
        println!("NO echo reply: target unreachable at session level (not just TCP)");
        std::process::exit(1);
    }
}
