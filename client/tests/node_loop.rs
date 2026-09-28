//! The node loop, proven the way every later client feature will use it: one
//! task, one `Router`, two peers, commands in over `Cmd`.
//!
//! Three claims, all loopback and all of them Go's:
//! 1. a duplicate dial is deduped by `link_id` (URI minus query), so the far
//!    side sees one connection, not two;
//! 2. `Drop` is Go's `removePeer`: it stops the redial **and closes the
//!    connection** (`core/link.go:433-438`), so the row leaves `getPeers` with
//!    the link. Slice 5 asserted the opposite, on the strength of the comment at
//!    `core/api.go:207-211`, which describes nothing that happens;
//! 3. when one peer's link dies, the node survives it and the other peer keeps
//!    carrying traffic — the single-task loop does not stop.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::{AnyConn, Client, LinkSet, Router};
use roots_client::node::{Cmd, Node};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// What a peer task publishes for the test to watch. The test may lock; the
/// node may not, which is the whole point of the command queue.
#[derive(Clone, Default, Debug)]
struct PeerState {
    accepted: usize,
    links: usize,
    inbox: Vec<([u8; 32], Vec<u8>)>,
}

fn snapshot(p: &Arc<Mutex<PeerState>>) -> PeerState {
    p.lock().unwrap().clone()
}

/// One ordinary Yggdrasil peer, built out of the library the way a node is:
/// accept, register, serve. It closes its own links when told to, which is a
/// remote close from the node's point of view, and goes on accepting so that a
/// redial would be counted.
async fn serve_peer(
    sk: SigningKey,
    listener: TcpListener,
    state: Arc<Mutex<PeerState>>,
    mut close_links: mpsc::Receiver<()>,
    stop: Instant,
) {
    let client = Client::new(sk.clone());
    let mut router = Router::new(sk);
    let (tx, mut incoming) = mpsc::unbounded_channel::<AnyConn>();
    // Accepting gets its own task for the same reason the node gives dialling
    // one: the handshake must not park the serve loop.
    tokio::spawn(async move {
        loop {
            match client.accept(&listener).await {
                Ok(conn) => {
                    if tx.send(AnyConn::new(conn)).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    let mut links = LinkSet::default();
    let mut out = Vec::new();
    let mut accepted = 0usize;
    while Instant::now() < stop {
        while let Ok(mut conn) = incoming.try_recv() {
            let (peer, id) = (conn.remote_key, conn.id);
            if router.register(&mut conn, peer, id).await.is_ok() {
                links.add(conn);
                accepted += 1;
            }
        }
        while close_links.try_recv().is_ok() {
            for id in links.ids() {
                let _ = links.remove(id);
            }
        }
        let _ = router
            .serve(&mut links, Some(Duration::from_millis(20)), &mut out)
            .await;
        let mut s = state.lock().unwrap();
        s.accepted = accepted;
        s.links = links.len();
        s.inbox = router.inbox.clone();
    }
}

async fn wait_for<F: FnMut() -> bool>(what: &str, mut pred: F, budget: Duration) {
    let end = Instant::now() + budget;
    while Instant::now() < end {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out after {budget:?} waiting for {what}");
}

#[tokio::test]
async fn node_loop_two_peers_dedup_drop_and_survival() {
    // Keys sorted so the node is the smallest: it becomes the star's root and
    // both peers parent onto it, which is the topology `Drop` is interesting in.
    let mut keys: Vec<SigningKey> = [0xA1u8, 0xB2, 0xC3]
        .iter()
        .map(|b| SigningKey::from_bytes(&[*b; 32]))
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let (a, b, c) = (keys.remove(0), keys.remove(0), keys.remove(0));
    let (a_pub, b_pub, c_pub) = (
        a.verifying_key().to_bytes(),
        b.verifying_key().to_bytes(),
        c.verifying_key().to_bytes(),
    );

    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lc = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (uri_b, uri_c) = (
        format!("tcp://{}", lb.local_addr().unwrap()),
        format!("tcp://{}", lc.local_addr().unwrap()),
    );
    let stop = Instant::now() + Duration::from_secs(30);
    let (_db_tx, db_rx) = mpsc::channel(4);
    let (dc_tx, dc_rx) = mpsc::channel(4);
    let sb = Arc::new(Mutex::new(PeerState::default()));
    let sc = Arc::new(Mutex::new(PeerState::default()));
    tokio::spawn(serve_peer(b, lb, sb.clone(), db_rx, stop));
    tokio::spawn(serve_peer(c, lc, sc.clone(), dc_rx, stop));

    let (mut node, tx) = Node::new(a);
    let handle = tokio::spawn(async move { node.run().await });

    // Two peers, and a duplicate of the first one with a different query — Go's
    // `link_id` makes those the same link.
    tx.send(Cmd::Dial {
        uri: uri_b.clone(),
        sintf: String::new(),
        persistent: true,
        respond: None,
    })
    .unwrap();
    tx.send(Cmd::Dial {
        uri: uri_c.clone(),
        sintf: String::new(),
        persistent: true,
        respond: None,
    })
    .unwrap();
    tx.send(Cmd::Dial {
        uri: format!("{uri_b}?priority=1"),
        sintf: String::new(),
        persistent: true,
        respond: None,
    })
    .unwrap();

    wait_for(
        "both peers accepted one link each",
        || {
            let (x, y) = (snapshot(&sb), snapshot(&sc));
            x.links == 1 && y.links == 1
        },
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        snapshot(&sb).accepted,
        1,
        "the duplicate dial never connected"
    );

    // Sessions to both, through the one task.
    tx.send(Cmd::Send {
        dest: b_pub,
        bytes: b"first-b".to_vec(),
    })
    .unwrap();
    tx.send(Cmd::Send {
        dest: c_pub,
        bytes: b"first-c".to_vec(),
    })
    .unwrap();
    let got = |p: &Arc<Mutex<PeerState>>, msg: &[u8]| {
        snapshot(p)
            .inbox
            .iter()
            .any(|(from, bytes)| *from == a_pub && bytes == msg)
    };
    wait_for(
        "both peers delivered the node's payloads",
        || got(&sb, b"first-b") && got(&sc, b"first-c"),
        Duration::from_secs(15),
    )
    .await;

    // Go's `removePeer`: stop redialling **and close the connection**.
    //
    // This block used to assert the opposite — that the link kept carrying
    // traffic after the drop — on the strength of the comment at
    // `core/api.go:207-211` ("the peer is not disconnected immediately"). Reading
    // Go rather than its comment showed `link.go:438` is a `conn.Close()`, so
    // Slice 9 took Go's behaviour. The new claim is that the payload sent after
    // the drop does **not** arrive, and that the peer sees the link go: a drop
    // that quietly left the socket open would be a divergence, not a feature.
    tx.send(Cmd::Drop {
        uri: uri_b.clone(),
        sintf: String::new(),
        respond: None,
    })
    .unwrap();
    wait_for(
        "the peer's link is closed by the drop",
        || snapshot(&sb).links == 0,
        Duration::from_secs(10),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    tx.send(Cmd::Send {
        dest: b_pub,
        bytes: b"after-drop".to_vec(),
    })
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !got(&sb, b"after-drop"),
        "the socket is closed, so a payload sent after removePeer does not arrive"
    );

    // Longer than the first backoff step (1s), so a redial would have arrived.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(
        snapshot(&sb).accepted,
        1,
        "a removed peer must not be dialled again"
    );

    // The surviving peer is untouched: closing one row's link is not
    // "disconnect everything", which is the failure mode this ordering would
    // have if `removePeer` cleared the set instead of one entry.
    tx.send(Cmd::Send {
        dest: c_pub,
        bytes: b"survivor".to_vec(),
    })
    .unwrap();
    wait_for(
        "the surviving peer still carries traffic",
        || got(&sc, b"survivor"),
        Duration::from_secs(15),
    )
    .await;
    dc_tx.try_send(()).unwrap();
    tx.send(Cmd::Quit).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the loop exits on Quit")
        .expect("no panic in the node task")
        .expect("the node loop ends cleanly");
}
