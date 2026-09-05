//! Oracle probe: peer a local Go node, send one session payload to its key,
//! hold so the operator can inspect `getSessions`/`getPeers` on the Go side.
//!
//! Run: `cargo run -q --example oracle_probe -- tcp://127.0.0.1:18233 <go-key-hex>`

use std::time::Duration;

use ed25519_dalek::SigningKey;

use roots::Client;

#[tokio::main]
async fn main() {
    let uri = std::env::args().nth(1).expect("peer uri");
    let go_key_hex = std::env::args().nth(2).expect("go key hex");
    let go_key: [u8; 32] = hex::decode(go_key_hex)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!("local  addr {}", client.address());
    let mut conn = client.connect(&uri).await.expect("dial");
    let peer_key = conn.remote_key;
    let mut router = roots::Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    let mut outbox = vec![(go_key, b"hello-oracle".to_vec())];
    for i in 0..120 {
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
        if i % 40 == 0 {
            eprintln!(
                "tick {i}: path={} sess={} inbox={}",
                router.has_path(&go_key),
                router.has_session(&go_key),
                router.inbox.len()
            );
        }
    }
    println!(
        "done: sess={} inbox={:?}",
        router.has_session(&go_key),
        router
            .inbox
            .iter()
            .map(|(f, m)| (hex::encode(f), String::from_utf8_lossy(m).into_owned()))
            .collect::<Vec<_>>()
    );
}
