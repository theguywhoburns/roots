//! Bidirectional logging TCP proxy for 1:1 wire comparison.
//! Sits between our node and a peer, tee-ing raw bytes per direction.
//!
//! Run: `cargo run -q --example tcp_proxy -- 127.0.0.1:18333 127.0.0.1:18233 /tmp/opencode/cap`
//! Produces `/tmp/opencode/cap.c2s` and `/tmp/opencode/cap.s2c` (hex, one
//! read-chunk per line). Feed either file to Go's TestZZReplay harness.
//! Then point the roots node at 127.0.0.1:18333 instead of the real peer.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    tag: &str,
    log: Arc<Mutex<std::fs::File>>,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut buf = vec![0u8; 65536];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        {
            let mut f = log.lock().unwrap();
            writeln!(f, "{tag} {}", hex::encode(&buf[..n])).unwrap();
        }
        to.write_all(&buf[..n]).await?;
    }
}

#[tokio::main]
async fn main() {
    let listen = std::env::args().nth(1).expect("listen addr");
    let target = std::env::args().nth(2).expect("target addr");
    let prefix = std::env::args().nth(3).expect("log prefix");
    let c2s = Arc::new(Mutex::new(
        std::fs::File::create(format!("{prefix}.c2s")).expect("c2s log"),
    ));
    let s2c = Arc::new(Mutex::new(
        std::fs::File::create(format!("{prefix}.s2c")).expect("s2c log"),
    ));
    let listener = TcpListener::bind(&listen).await.expect("bind");
    println!("proxy {listen} -> {target}");
    loop {
        let (down, _) = listener.accept().await.expect("accept");
        let up = TcpStream::connect(&target).await.expect("dial target");
        let (dr, dw) = down.into_split();
        let (ur, uw) = up.into_split();
        let c2s = c2s.clone();
        let s2c = s2c.clone();
        tokio::spawn(async move {
            let a = pipe(dr, uw, "C", c2s);
            let b = pipe(ur, dw, "S", s2c);
            let _ = tokio::join!(a, b);
        });
    }
}
