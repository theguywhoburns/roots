//! Long-hold listener: peer, converge, then serve indefinitely printing
//! every inbox delivery. For cross-testing delivery FROM other nodes
//! (e.g. ping from the host via the system Go node).
//!
//! Run: `cargo run -q --example listen_ping -- tcp://bode.theender.net:42069`

use std::time::Duration;

use ed25519_dalek::SigningKey;

mod common;
use roots::Client;

#[tokio::main]
async fn main() {
    let uri = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    println!("local  addr {}", client.address());
    let (mut router, mut links, _link) = common::join_one(&client.key, &client.opts, &uri)
        .await
        .expect("dial");
    assert!(
        common::converge(&mut router, &mut links, Duration::from_secs(30)).await,
        "convergence timed out"
    );
    println!("converged, listening (Ctrl-C to stop)");
    let mut no_out = Vec::new();
    loop {
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
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
