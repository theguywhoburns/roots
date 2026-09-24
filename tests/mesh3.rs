//! Three-node loopback mesh (the Slice 1 safety net): A—B—C over TCP, where A
//! and C never share a link. Proves the things every single-link test so far
//! has assumed — that a DHT lookup crosses a hop, that an intermediate forwards
//! traffic it cannot consume itself, and that a dead link is evicted while the
//! surviving leg keeps serving.
//!
//! Deliberately passes against code written before the go-client-parity
//! refactor: it exists to catch a bad Slice 4, not to describe new behaviour.
//! Both of its distinctive claims were checked by mutation — deleting the
//! dead-link eviction in `serve_links` fails phase 4, and deleting the transit
//! write in `traffic.rs` fails phase 3 — so neither assertion passes by
//! accident.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use roots::address::{KEY_LEN, addr_for_key};
use roots::{Address, FrameType, LinkOptions, LinkSet, Router};

/// One serve slice per node. Three nodes take turns on the runtime, so each
/// link is serviced every ~3 slices — well inside the ~4 s peer read timeout.
const TICK: Duration = Duration::from_millis(100);
const CONVERGE: Duration = Duration::from_secs(40);
const DELIVER: Duration = Duration::from_secs(40);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Status {
    root: Option<[u8; KEY_LEN]>,
    known: usize,
    links: usize,
    traffic: u64,
}

enum Cmd {
    Status(Sender<Status>),
    Inbox(Sender<Vec<([u8; KEY_LEN], Vec<u8>)>>),
    Resolve {
        addr: Address,
        reply: Sender<Option<[u8; KEY_LEN]>>,
    },
    Send {
        dest: [u8; KEY_LEN],
        payload: Vec<u8>,
    },
}

fn status_of(router: &Router, links: &LinkSet) -> Status {
    Status {
        root: router.root_and_depth().map(|(r, _)| r),
        known: router.known_nodes(),
        links: links.peers().len(),
        traffic: router.frames[FrameType::Traffic as usize],
    }
}

/// Poll a reply that the node task will only produce while this future is
/// parked at an await point (single-threaded runtime: no preemption).
async fn await_reply<T>(rx: Receiver<T>, what: &str, budget: Duration) -> T {
    let end = tokio::time::Instant::now() + budget;
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        assert!(tokio::time::Instant::now() < end, "no reply for {what}");
        tokio::time::sleep(TICK).await;
    }
}

async fn round_trip<T: Send + 'static>(
    tx: &Sender<Cmd>,
    make: impl FnOnce(Sender<T>) -> Cmd,
    what: &str,
) -> T {
    let (rtx, rrx): (Sender<T>, Receiver<T>) = channel();
    tx.send(make(rtx)).unwrap();
    await_reply(rrx, what, DELIVER).await
}

async fn status(tx: &Sender<Cmd>) -> Status {
    round_trip(tx, Cmd::Status, "status").await
}

async fn inbox(tx: &Sender<Cmd>) -> Vec<([u8; KEY_LEN], Vec<u8>)> {
    round_trip(tx, Cmd::Inbox, "inbox").await
}

/// One node: drain commands, then serve a slice, until asked to stop. Returns
/// whatever `report` says about the final state (B reports its live peers).
async fn drive<E, F>(
    mut router: Router,
    mut links: LinkSet,
    rx: Receiver<Cmd>,
    stop: Arc<AtomicBool>,
    report: F,
) -> E
where
    F: FnOnce(&Router, &LinkSet) -> E,
{
    let mut out: Vec<([u8; KEY_LEN], Vec<u8>)> = Vec::new();
    loop {
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Cmd::Status(tx) => {
                    let _ = tx.send(status_of(&router, &links));
                }
                Cmd::Inbox(tx) => {
                    let _ = tx.send(router.inbox.clone());
                }
                Cmd::Send { dest, payload } => out.push((dest, payload)),
                Cmd::Resolve { addr, reply } => {
                    // A resolve owns the link until it answers, like an app
                    // request would; the first link stands in for "our peer".
                    let Some(peer) = links.peers().first().copied() else {
                        let _ = reply.send(None);
                        continue;
                    };
                    let got = router
                        .resolve(&mut links, peer, &addr, Duration::from_secs(30))
                        .await
                        .ok();
                    let _ = reply.send(got);
                }
            }
        }
        if stop.load(Ordering::SeqCst) {
            return report(&router, &links);
        }
        let _ = router.serve_links(&mut links, Some(TICK), &mut out).await;
    }
}

#[tokio::test]
async fn three_node_mesh_routes_resolves_and_survives_a_dead_link() {
    let a_sk = SigningKey::from_bytes(&[0xA3; 32]);
    let b_sk = SigningKey::from_bytes(&[0xB1; 32]);
    let c_sk = SigningKey::from_bytes(&[0xC7; 32]);
    let a_pub = a_sk.verifying_key().to_bytes();
    let b_pub = b_sk.verifying_key().to_bytes();
    let c_pub = c_sk.verifying_key().to_bytes();
    let opts = LinkOptions::default();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("tcp://{}", listener.local_addr().unwrap());

    let (a_tx, a_rx) = channel::<Cmd>();
    let (b_tx, b_rx) = channel::<Cmd>();
    let (c_tx, c_rx) = channel::<Cmd>();
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::new(AtomicBool::new(false));

    // B is the only node with two links, so the only one that can forward
    // rather than consume. It reports its final link peers on exit.
    let b_task = {
        let (sk, opts, rx, stop) = (b_sk.clone(), opts.clone(), b_rx, stop_b.clone());
        tokio::spawn(async move {
            let mut ab = roots::link::accept(&listener, &sk, &opts)
                .await
                .expect("B accepts A");
            let a_peer = ab.remote_key;
            let mut cb = roots::link::accept(&listener, &sk, &opts)
                .await
                .expect("B accepts C");
            let c_peer = cb.remote_key;
            let mut router = Router::new(sk);
            router.register(&mut ab, a_peer).await.expect("B A");
            router.register(&mut cb, c_peer).await.expect("B C");
            let mut links = LinkSet::single(roots::link::AnyConn::new(ab));
            links.add(roots::link::AnyConn::new(cb));
            drive(router, links, rx, stop, |_, l| l.peers()).await
        })
    };

    let a_task = {
        let (sk, opts, uri, rx, stop) = (
            a_sk.clone(),
            opts.clone(),
            uri.clone(),
            a_rx,
            stop_a.clone(),
        );
        tokio::spawn(async move {
            let mut conn = roots::link::dial(&uri, &sk, &opts)
                .await
                .expect("A dials B");
            let peer = conn.remote_key;
            let mut router = Router::new(sk);
            router.register(&mut conn, peer).await.expect("A reg");
            drive(
                router,
                LinkSet::single(roots::link::AnyConn::new(conn)),
                rx,
                stop,
                |_, _| (),
            )
            .await
        })
    };

    let c_task = {
        let (sk, opts, uri, rx, stop) = (
            c_sk.clone(),
            opts.clone(),
            uri.clone(),
            c_rx,
            stop_c.clone(),
        );
        tokio::spawn(async move {
            let mut conn = roots::link::dial(&uri, &sk, &opts)
                .await
                .expect("C dials B");
            let peer = conn.remote_key;
            let mut router = Router::new(sk);
            router.register(&mut conn, peer).await.expect("C reg");
            drive(
                router,
                LinkSet::single(roots::link::AnyConn::new(conn)),
                rx,
                stop,
                |_, _| (),
            )
            .await
        })
    };

    // 1. One tree: all three agree on the root, and the middle node has
    //    learned every info. Ends only ever learn their own line to the root
    //    — Go `_sendAnnounces` (ironwood network/router.go:321) sends the
    //    ancestry of self plus the ancestry of the peer, never the whole
    //    table — so A and C legitimately do NOT know each other. That gap is
    //    the point of the next phase: resolving A from C has to cross the
    //    hop through the DHT, not through the tree.
    let end = tokio::time::Instant::now() + CONVERGE;
    let (a0, b0, c0) = loop {
        let a = status(&a_tx).await;
        let b = status(&b_tx).await;
        let c = status(&c_tx).await;
        if a.root.is_some()
            && a.root == b.root
            && a.root == c.root
            && a.known >= 2
            && b.known == 3
            && c.known >= 2
        {
            break (a, b, c);
        }
        assert!(
            tokio::time::Instant::now() < end,
            "mesh never converged: A {a:?} B {b:?} C {c:?}"
        );
        tokio::time::sleep(TICK).await;
    };
    assert_eq!(a0.links + b0.links + c0.links, 4, "A—B—C, not a triangle");

    // 2. DHT across the hop: C asks who owns A's address, and the signed
    //    notify has to find its way back through B.
    let (rtx, rrx) = channel::<Option<[u8; KEY_LEN]>>();
    c_tx.send(Cmd::Resolve {
        addr: addr_for_key(&a_pub),
        reply: rtx,
    })
    .unwrap();
    let resolved = await_reply(rrx, "resolve", DELIVER).await;
    assert_eq!(resolved, Some(a_pub), "C resolved A's address through B");

    // 3. Transit: A sends to a node it has no link to; B must forward.
    let b_before = status(&b_tx).await.traffic;
    a_tx.send(Cmd::Send {
        dest: c_pub,
        payload: b"transit-a-to-c".to_vec(),
    })
    .unwrap();
    let end = tokio::time::Instant::now() + DELIVER;
    loop {
        let got = inbox(&c_tx)
            .await
            .iter()
            .any(|(from, msg)| *from == a_pub && msg == b"transit-a-to-c");
        if got {
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "C never got A's transit payload"
        );
        tokio::time::sleep(TICK).await;
    }
    let b_after = status(&b_tx).await.traffic;
    assert!(
        b_after > b_before,
        "B counted no forwarded traffic ({} -> {b_after})",
        b_before
    );

    // 4. A's link dies for real: its task returns, so the socket closes. B
    //    must evict that link and keep serving C.
    stop_a.store(true, Ordering::SeqCst);
    let end = tokio::time::Instant::now() + DELIVER;
    loop {
        if status(&b_tx).await.links == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "B never evicted A's dead link"
        );
        tokio::time::sleep(TICK).await;
    }

    // 5. The survivor still carries a session: C -> B, delivered after the
    //    eviction that removed B's other link.
    c_tx.send(Cmd::Send {
        dest: b_pub,
        payload: b"survivor".to_vec(),
    })
    .unwrap();
    let end = tokio::time::Instant::now() + DELIVER;
    loop {
        let got = inbox(&b_tx)
            .await
            .iter()
            .any(|(from, msg)| *from == c_pub && msg == b"survivor");
        if got {
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "B's surviving link stopped serving"
        );
        tokio::time::sleep(TICK).await;
    }

    stop_b.store(true, Ordering::SeqCst);
    stop_c.store(true, Ordering::SeqCst);
    let b_peers = b_task.await.unwrap();
    a_task.await.unwrap();
    c_task.await.unwrap();
    assert_eq!(b_peers, vec![c_pub], "only C's link is left on B");
}
