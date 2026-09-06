//! Demo probe: connect to one peer, run the spanning-tree router, and
//! report convergence (parent / root / depth / known nodes).

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
) {
    show("remote", &conn.remote_key);
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    let mut no_out = Vec::new();
    if let Err(e) = router.register(&mut conn, peer_key).await {
        eprintln!("register failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = router.serve(&mut conn, peer_key, hold, &mut no_out).await {
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
    let mut rng = rand::thread_rng();
    let key = ed25519_dalek::SigningKey::generate(&mut rng);
    let client = Client::new(key);
    println!("local  addr {}", client.address());
    if uri.starts_with("tls://") {
        match client.connect_tls(&uri).await {
            Ok(conn) => run(client, conn, hold).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if uri.starts_with("ws://") {
        match client.connect_ws(&uri).await {
            Ok(conn) => run(client, conn, hold).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if uri.starts_with("wss://") {
        match client.connect_wss(&uri).await {
            Ok(conn) => run(client, conn, hold).await,
            Err(e) => {
                eprintln!("connect failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    match client.connect(&uri).await {
        Ok(conn) => run(client, conn, hold).await,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(1);
        }
    }
}
