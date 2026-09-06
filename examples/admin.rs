//! yggdrasilctl-compatible admin adapter (demo-client layer).
//!
//! Speaks the stock Go admin socket protocol (streaming JSON
//! `{"request","arguments","keepalive"}` → `{"status","request",
//! "response"}`), mapped thinly over lib query snapshots. Subset:
//! `list`, `getSelf`, `getPeers`, `getTree`, `getPaths`, `getSessions`.
//! Everything else answers `unknown action` exactly like Go.
//!
//! The lib never sees this: no serde, no sockets there. Verified with
//! the real `yggdrasilctl` binary against a live mesh peer.
//!
//! Run: `cargo run -q --example admin -- [peer-uri] [admin-listen]`
//! e.g. `/tmp/opencode/ygg-go-build/yggdrasilctl -endpoint=tcp://127.0.0.1:19019 getPeers`

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use roots::{Client, Router};

/// One admin handler: description + arg names (for `list`) + responder.
struct Handler {
    desc: &'static str,
    args: Vec<&'static str>,
    run: fn(&Router, &[u8; 32], &Value) -> Result<Value, String>,
}

fn handlers() -> Vec<(&'static str, Handler)> {
    vec![
        (
            "getself",
            Handler {
                desc: "Show local node info",
                args: vec![],
                run: |r, key, _| {
                    let mut snet = [0u8; 16];
                    snet[..8].copy_from_slice(&roots::subnet_for_key(key).0);
                    let subnet = std::net::Ipv6Addr::from(snet);
                    Ok(json!({
                        "build_name": "roots",
                        "build_version": env!("CARGO_PKG_VERSION"),
                        "key": hex::encode(key),
                        "address": roots::addr_for_key(key).to_string(),
                        "routing_entries": r.known_nodes() as u64,
                        "subnet": format!("{subnet}/64"),
                    }))
                },
            },
        ),
        (
            "getpeers",
            Handler {
                desc: "Show directly connected peers",
                args: vec![],
                run: |r, _, _| {
                    let peers: Vec<Value> = r
                        .link_peers()
                        .iter()
                        .map(|(key, port, prio, up, lag_ms)| {
                            // Go's peer cost is millisecond-scale like our
                            // lag estimate (unknown links price at u32::MAX).
                            let ms = (*lag_ms).min(u64::MAX as u128) as u64;
                            json!({
                                "key": hex::encode(key),
                                "address": roots::addr_for_key(key).to_string(),
                                "port": port,
                                "priority": prio,
                                "up": up,
                                "inbound": false,
                                "cost": ms,
                                "latency": ms.saturating_mul(1_000_000),
                            })
                        })
                        .collect();
                    Ok(json!({ "peers": peers }))
                },
            },
        ),
        (
            "gettree",
            Handler {
                desc: "Show spanning-tree entries",
                args: vec![],
                run: |r, _, _| {
                    let tree: Vec<Value> = r
                        .tree_entries()
                        .iter()
                        .map(|(key, parent, seq)| {
                            json!({
                                "key": hex::encode(key),
                                "address": roots::addr_for_key(key).to_string(),
                                "parent": hex::encode(parent),
                                "sequence": seq,
                            })
                        })
                        .collect();
                    Ok(json!({ "tree": tree }))
                },
            },
        ),
        (
            "getpaths",
            Handler {
                desc: "Show learned source routes",
                args: vec![],
                run: |r, _, _| {
                    let paths: Vec<Value> = r
                        .get_paths()
                        .iter()
                        .map(|(key, path, seq)| {
                            json!({
                                "key": hex::encode(key),
                                "address": roots::addr_for_key(key).to_string(),
                                "path": path,
                                "sequence": seq,
                            })
                        })
                        .collect();
                    Ok(json!({ "paths": paths }))
                },
            },
        ),
        (
            "getsessions",
            Handler {
                desc: "Show open E2E sessions",
                args: vec![],
                run: |r, _, _| {
                    let sessions: Vec<Value> = r
                        .get_sessions()
                        .iter()
                        .map(|key| {
                            json!({
                                "key": hex::encode(key),
                                "address": roots::addr_for_key(key).to_string(),
                            })
                        })
                        .collect();
                    Ok(json!({ "sessions": sessions }))
                },
            },
        ),
    ]
}

/// Answer one admin connection (one request, or several with keepalive).
async fn handle_admin(
    mut sock: tokio::net::TcpStream,
    router: &Router,
    our_key: &[u8; 32],
) -> Result<(), String> {
    let table = handlers();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        // Incrementally parse one JSON value out of the stream (Go reads
        // with a streaming decoder the same way).
        let (req, consumed): (Value, usize) = loop {
            let mut stream = serde_json::Deserializer::from_slice(&buf).into_iter::<Value>();
            if let Some(Ok(v)) = stream.next() {
                break (v, stream.byte_offset());
            }
            let n = sock
                .read(&mut tmp)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                if buf.is_empty() {
                    return Ok(());
                }
                return Err("truncated request".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        buf.drain(..consumed.min(buf.len()));
        let name = req
            .get("request")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let args = req.get("arguments").cloned().unwrap_or(Value::Null);
        let keepalive = req
            .get("keepalive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let echo = json!({
            "request": req.get("request").cloned().unwrap_or(Value::Null),
            "arguments": args,
        });
        let (status, error, response) = if name.is_empty() {
            ("error", "no request specified".to_string(), Value::Null)
        } else if name == "list" {
            let list: Vec<Value> = table
                .iter()
                .map(|(cmd, h)| json!({"command": cmd, "description": h.desc, "fields": h.args}))
                .collect();
            ("success", String::new(), json!({ "list": list }))
        } else if let Some((_, h)) = table.iter().find(|(cmd, _)| *cmd == name) {
            match (h.run)(router, our_key, &args) {
                Ok(v) => ("success", String::new(), v),
                Err(e) => ("error", e, Value::Null),
            }
        } else {
            (
                "error",
                format!("unknown action '{name}', try 'list' for help"),
                Value::Null,
            )
        };
        let mut out = if error.is_empty() {
            json!({ "status": status, "request": echo, "response": response })
        } else {
            json!({ "status": status, "error": error, "request": echo, "response": response })
        };
        // yggdrasilctl unmarshals strictly-typed structs; keep numbers
        // numeric (latency ns, uptime s) exactly like Go's shapes.
        let _ = &mut out;
        let mut bytes = serde_json::to_vec_pretty(&out).map_err(|e| format!("encode: {e}"))?;
        bytes.push(b'\n');
        sock.write_all(&bytes)
            .await
            .map_err(|e| format!("write: {e}"))?;
        if !keepalive {
            break;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let peer = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let admin_addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:19019".to_string());
    let mut rng = rand::thread_rng();
    let client = Client::new(SigningKey::generate(&mut rng));
    let our_key = client.key.verifying_key().to_bytes();
    println!("local  addr {}", client.address());
    let mut conn = client.connect(&peer).await.expect("dial public peer");
    let peer_key = conn.remote_key;
    let mut router = Router::new(client.key);
    router
        .register(&mut conn, peer_key)
        .await
        .expect("register");
    let mut no_out = Vec::new();
    // One set for the whole run (see main loop below).
    let mut links = roots::LinkSet::single(peer_key, &mut conn);
    let end = Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && Instant::now() < end {
        router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
            .expect("link up");
    }
    assert!(router.parent().is_some(), "mesh convergence timed out");
    let listener = tokio::net::TcpListener::bind(&admin_addr)
        .await
        .expect("admin listen");
    println!("admin on tcp://{admin_addr} (Ctrl-C to stop)");
    // Reuse the same set: per-link send clocks must survive slices.
    let mut outbox: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    loop {
        tokio::select! {
            r = router.serve(&mut links, Some(Duration::from_millis(250)), &mut outbox) => {
                if let Err(e) = r {
                    eprintln!("link dropped: {e}");
                    std::process::exit(1);
                }
            }
            a = listener.accept() => {
                match a {
                    Ok((sock, _)) => {
                        // Answer inline; keep admin sessions short (no
                        // keepalive hangs) so the mesh never starves.
                        tokio::time::timeout(Duration::from_secs(10), handle_admin(sock, &router, &our_key)).await.ok();
                    }
                    Err(e) => eprintln!("admin accept: {e}"),
                }
            }
        }
    }
}
