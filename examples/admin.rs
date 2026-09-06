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

/// Remote (mesh round-trip) admin commands: name + description.
/// Like Go (`getNodeInfo`, `debug_remoteGetSelf/Peers/Tree`), each takes
/// `{"key": "<hex>"}` and answers from the live mesh; served by the main
/// loop's pending queue, not inline.
const REMOTE_COMMANDS: [(&str, &str); 4] = [
    (
        "getnodeinfo",
        "Request nodeinfo from a remote node by its public key",
    ),
    ("debug_remotegetself", "Debug use only"),
    ("debug_remotegetpeers", "Debug use only"),
    ("debug_remotegettree", "Debug use only"),
];

/// How long a remote admin query waits for the mesh reply. Go uses 6s;
/// ours is more generous for slow links.
const REMOTE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoteKind {
    NodeInfo,
    DebugSelf,
    DebugPeers,
    DebugTree,
}

struct PendingRemote {
    sock: tokio::net::TcpStream,
    echo: Value,
    key: [u8; 32],
    kind: RemoteKind,
    sent: bool,
    deadline: Instant,
}

/// Parse a `{"key": "<hex>"}` argument like Go's debug handlers.
fn parse_key_arg(args: &Value) -> Result<[u8; 32], String> {
    let hexs = args
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid public key length".to_string())?;
    let raw = hex::decode(hexs).map_err(|e| format!("failed to decode public key: {e}"))?;
    if raw.len() != 32 {
        return Err("invalid public key length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(key)
}

fn kind_matches(kind: RemoteKind, payload: &[u8]) -> bool {
    use roots::proto::*;
    match kind {
        RemoteKind::NodeInfo => payload.first() == Some(&PROTO_NODEINFO_RES),
        RemoteKind::DebugSelf => {
            payload.first() == Some(&PROTO_DEBUG) && payload.get(1) == Some(&DEBUG_GETSELF_RES)
        }
        RemoteKind::DebugPeers => {
            payload.first() == Some(&PROTO_DEBUG) && payload.get(1) == Some(&DEBUG_GETPEERS_RES)
        }
        RemoteKind::DebugTree => {
            payload.first() == Some(&PROTO_DEBUG) && payload.get(1) == Some(&DEBUG_GETTREE_RES)
        }
    }
}

/// Build the Go-shaped admin response for a mesh reply.
fn remote_answer(kind: RemoteKind, from: &[u8; 32], payload: &[u8]) -> Result<Value, String> {
    let ip = roots::addr_for_key(from).to_string();
    match kind {
        RemoteKind::NodeInfo => {
            let info: Value = serde_json::from_slice(&payload[1..])
                .map_err(|e| format!("invalid nodeinfo: {e}"))?;
            Ok(json!({ hex::encode(from): info }))
        }
        RemoteKind::DebugSelf => {
            let msg: Value = serde_json::from_slice(&payload[2..])
                .map_err(|e| format!("invalid response: {e}"))?;
            Ok(json!({ ip: msg }))
        }
        RemoteKind::DebugPeers | RemoteKind::DebugTree => {
            let keys: Vec<String> = payload[2..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(hex::encode)
                .collect();
            Ok(json!({ ip: { "keys": keys } }))
        }
    }
}

async fn write_admin_response(
    mut sock: tokio::net::TcpStream,
    echo: &Value,
    status: &str,
    error: &str,
    response: Value,
) {
    let out = if error.is_empty() {
        json!({ "status": status, "request": echo, "response": response })
    } else {
        json!({ "status": status, "error": error, "request": echo, "response": response })
    };
    if let Ok(mut bytes) = serde_json::to_vec_pretty(&out) {
        bytes.push(b'\n');
        let _ = sock.write_all(&bytes).await;
    }
}

/// Read one admin request value (Go reads with a streaming decoder the
/// same way). Bounded so a hanging client can't stall the mesh loop.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Result<(String, Value, Value), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let req: Value = loop {
        let mut stream = serde_json::Deserializer::from_slice(&buf).into_iter::<Value>();
        if let Some(Ok(v)) = stream.next() {
            break v;
        }
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut tmp))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let name = req
        .get("request")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let args = req.get("arguments").cloned().unwrap_or(Value::Null);
    let echo = json!({
        "request": req.get("request").cloned().unwrap_or(Value::Null),
        "arguments": args.clone(),
    });
    Ok((name, args, echo))
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
    let table = handlers();
    let mut pending: Vec<PendingRemote> = Vec::new();
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
                    Ok((mut sock, _)) => {
                        match read_request(&mut sock).await {
                            Ok((name, args, echo)) => {
                                if name.is_empty() {
                                    write_admin_response(sock, &echo, "error", "no request specified", Value::Null).await;
                                } else if name == "list" {
                                    let mut list: Vec<Value> = table.iter().map(|(cmd, h)| {
                                        json!({"command": cmd, "description": h.desc, "fields": h.args})
                                    }).collect();
                                    for (cmd, desc) in REMOTE_COMMANDS {
                                        list.push(json!({"command": cmd, "description": desc, "fields": ["key"]}));
                                    }
                                    write_admin_response(sock, &echo, "success", "", json!({ "list": list })).await;
                                } else if let Some((_, h)) = table.iter().find(|(cmd, _)| *cmd == name) {
                                    match (h.run)(&router, &our_key, &args) {
                                        Ok(v) => write_admin_response(sock, &echo, "success", "", v).await,
                                        Err(e) => write_admin_response(sock, &echo, "error", &e, Value::Null).await,
                                    }
                                } else if let Some(kind) = remote_kind(&name) {
                                    match parse_key_arg(&args) {
                                        Ok(key) => pending.push(PendingRemote {
                                            sock,
                                            echo,
                                            key,
                                            kind,
                                            sent: false,
                                            deadline: Instant::now() + REMOTE_TIMEOUT,
                                        }),
                                        Err(e) => write_admin_response(sock, &echo, "error", &e, Value::Null).await,
                                    }
                                } else {
                                    write_admin_response(sock, &echo, "error", &format!("unknown action '{name}', try 'list' for help"), Value::Null).await;
                                }
                            }
                            Err(e) => eprintln!("admin read: {e}"),
                        }
                    }
                    Err(e) => eprintln!("admin accept: {e}"),
                }
            }
        }
        service_pending(&mut router, &mut links, peer_key, &mut pending).await;
    }
}

fn remote_kind(name: &str) -> Option<RemoteKind> {
    match name {
        "getnodeinfo" => Some(RemoteKind::NodeInfo),
        "debug_remotegetself" => Some(RemoteKind::DebugSelf),
        "debug_remotegetpeers" => Some(RemoteKind::DebugPeers),
        "debug_remotegettree" => Some(RemoteKind::DebugTree),
        _ => None,
    }
}

/// Drive one round of remote admin queries: dispatch unsent requests,
/// match fresh mesh replies to waiters, time out the stale.
async fn service_pending(
    router: &mut Router,
    links: &mut roots::LinkSet<'_>,
    peer_key: [u8; 32],
    pending: &mut Vec<PendingRemote>,
) {
    use roots::proto::*;
    for p in pending.iter_mut().filter(|p| !p.sent) {
        let r = match p.kind {
            RemoteKind::NodeInfo => router.request_nodeinfo(links, peer_key, p.key).await,
            RemoteKind::DebugSelf => {
                router
                    .request_debug(links, peer_key, p.key, DEBUG_GETSELF_REQ)
                    .await
            }
            RemoteKind::DebugPeers => {
                router
                    .request_debug(links, peer_key, p.key, DEBUG_GETPEERS_REQ)
                    .await
            }
            RemoteKind::DebugTree => {
                router
                    .request_debug(links, peer_key, p.key, DEBUG_GETTREE_REQ)
                    .await
            }
        };
        if r.is_ok() {
            p.sent = true;
        }
    }
    let now = Instant::now();
    let mut i = 0;
    while i < pending.len() {
        if pending[i].deadline <= now {
            let p = pending.remove(i);
            let err = match p.kind {
                RemoteKind::NodeInfo => "timed out waiting for response",
                _ => "timeout",
            };
            write_admin_response(p.sock, &p.echo, "error", err, Value::Null).await;
            continue;
        }
        i += 1;
    }
    let mut i = 0;
    while i < router.proto_inbox.len() {
        let (from, payload) = router.proto_inbox[i].clone();
        if let Some(pos) = pending
            .iter()
            .position(|p| p.key == from && kind_matches(p.kind, &payload))
        {
            let p = pending.remove(pos);
            match remote_answer(p.kind, &from, &payload) {
                Ok(v) => write_admin_response(p.sock, &p.echo, "success", "", v).await,
                Err(e) => write_admin_response(p.sock, &p.echo, "error", &e, Value::Null).await,
            }
            router.proto_inbox.remove(i);
            continue;
        }
        i += 1;
    }
}
