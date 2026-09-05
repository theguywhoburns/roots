//! Long-hold listener: peer, converge, then serve indefinitely printing
//! every inbox delivery. For cross-testing delivery FROM other nodes
//! (e.g. ping from the host via the system Go node).
//!
//! Run: `cargo run -q --example listen_ping -- tcp://bode.theender.net:42069`

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use roots::{Client, Router};

#[tokio::main]
async fn main() {
    let uri = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!("local  addr {}", client.address());
    let mut conn = client.connect(&uri).await.expect("dial");
    let peer_key = conn.remote_key;
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
    println!("converged, listening (Ctrl-C to stop)");
    loop {
        if let Err(e) = router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(250)),
                &mut no_out,
            )
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
        for (from, pkt) in router.inbox.drain(..) {
            println!(
                "got {}B from {} type={}",
                pkt.len(),
                hex::encode(from),
                pkt.first().copied().unwrap_or(255)
            );
        }
    }
}
