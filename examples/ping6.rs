//! Ping a mesh address with ICMPv6 echo through an E2E session.
//! Decides whether a target is reachable at all (vs TCP specifically).
//!
//! Run: `cargo run -q --example ping6 -- 21e:a51c:885b:7db0:166e:927:98cd:d186`

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use roots::{Client, Router};

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
    let mut conn = client.connect(&peer_uri).await.expect("dial public peer");
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    let mut no_out = Vec::new();

    let end = Instant::now() + Duration::from_secs(60);
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
    assert!(router.parent().is_some(), "convergence timed out");

    let key = router
        .resolve(&mut conn, peer_key, &target_addr, Duration::from_secs(60))
        .await
        .expect("resolve target");
    println!("target key {}", hex::encode(key));

    // ICMPv6 echo request, id/seq fixed for matching.
    let ident = 0xbeefu16;
    let seqno = 1u16;
    let data = b"roots-ping";
    let echo_request = || {
        let mut pkt = vec![0u8; 40 + 8 + data.len()];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        pkt[6] = 58;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&our_bytes);
        pkt[24..40].copy_from_slice(&target_bytes);
        pkt[40] = 128;
        pkt[44..46].copy_from_slice(&ident.to_be_bytes());
        pkt[46..48].copy_from_slice(&seqno.to_be_bytes());
        pkt[48..].copy_from_slice(data);
        let csum = checksum(&our_bytes, &target_bytes, 8 + data.len() as u16, &pkt[40..]);
        pkt[42..44].copy_from_slice(&csum.to_be_bytes());
        pkt
    };

    let mut outbox = vec![(key, echo_request())];
    let end = Instant::now() + Duration::from_secs(90);
    let mut got = 0;
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
