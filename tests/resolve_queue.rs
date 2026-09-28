//! Resolve-and-hold, the library half of Slice 12: `Router::send_or_resolve`
//! takes a payload, answers `Sent` or `Queued`, and never waits for a DHT
//! lookup — so a caller that is writing into a device hands the packet over and
//! moves on.
//!
//! A—B—C over loopback TCP, all three routers ours. A (the sender) and B (the
//! relay) link first; C (the destination) only dials after the payloads have
//! been held, so "the overwritten payload was never delivered" is a fact about
//! the wire rather than a race. A's link and C's link are both tapped, so the
//! test reads which payload bytes left the sender and which arrived at the
//! destination, instead of inferring delivery from a frame counter.
//!
//! Loopback only: no device, no privileges, no network.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use roots::address::{KEY_LEN, addr_for_key, subnet_for_key};
use roots::driver::Route;
use roots::link::{AnyConn, LinkId, LinkOptions, LinkSet, PeerConn};
use roots::{Address, Error, Router};

/// One serve slice per node, as in `tests/mesh3.rs`: the nodes take turns on
/// the runtime, so every link is serviced well inside the ~4 s peer read
/// timeout.
const TICK: Duration = Duration::from_millis(100);
/// Converge and deliver budget. Generous, because both tests may share a
/// loaded machine: a lookup is re-driven on a 1 s maintenance tick
/// (`MAINTENANCE_INTERVAL`) and throttled to one a second (`PATH_THROTTLE`),
/// and the bloom B advertises to A has to reach A before a lookup for C can
/// leave at all.
const BUDGET: Duration = Duration::from_secs(60);

/// Long enough that finding one in a tap log is a fact about a payload rather
/// than a coincidence inside a signature.
const FIRST: &[u8] = b"roots-resolve-queue-first-payload";
const SECOND: &[u8] = b"roots-resolve-queue-second-payload";
const THIRD: &[u8] = b"roots-resolve-queue-third-payload";

/// A link that keeps a copy of every byte crossing it.
///
/// The router frames its own reads and writes (`link.rs` `read_frame_from` /
/// `write_frame_to`), so the tap sits underneath the framing and records raw
/// bytes; the test then searches that log for a whole payload. A tap is a byte
/// stream, not a frame boundary, so the search is a byte scan: a payload is
/// long and ASCII, and nothing else on the link can hold it.
struct Tap {
    inner: TcpStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let fresh = &buf.filled()[before..];
            self.log.lock().expect("tap log").extend_from_slice(fresh);
        }
        res
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.log.lock().expect("tap log").extend_from_slice(buf);
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// True when bytes containing `needle` crossed a tapped link.
fn saw(log: &Arc<Mutex<Vec<u8>>>, needle: &[u8]) -> bool {
    let log = log.lock().expect("tap log");
    log.windows(needle.len()).any(|w| w == needle)
}

/// The routed subnet of `key` written as a full address: the eight bytes
/// `writePC` copies out of a packet before asking `sendToSubnet`
/// (`ipv6rwc.go:297-309`).
fn subnet_address(key: &[u8; KEY_LEN]) -> Address {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&subnet_for_key(key).0);
    Address(raw)
}

/// Wrap a finished handshake so the link is tapped.
///
/// `AnyConn` is a plain struct of public fields and mints its `LinkId` from the
/// same counter as every other link (`link.rs:176-203`), so building one by
/// hand is the only way to put a tap in the set.
fn tapped(conn: PeerConn, log: Arc<Mutex<Vec<u8>>>) -> AnyConn {
    AnyConn {
        remote_key: conn.remote_key,
        priority: conn.priority,
        kind: conn.kind.clone(),
        inbound: conn.inbound,
        id: LinkId::absent(),
        remote_addr: conn.remote_addr.clone(),
        stream: Box::new(Tap {
            inner: conn.stream,
            log,
        }),
    }
}

/// Register a connection and add it to the set.
///
/// `register` writes the bloom and the signature request through the
/// connection, so it runs before the connection joins the set, exactly as a
/// caller that registered once per link must.
async fn join(
    router: &mut Router,
    set: &mut LinkSet,
    conn: PeerConn,
    tap: Option<Arc<Mutex<Vec<u8>>>>,
) -> LinkId {
    let remote = conn.remote_key;
    let mut conn = match tap {
        Some(log) => tapped(conn, log),
        None => AnyConn::new(conn),
    };
    let id = conn.id;
    router
        .register(&mut conn, remote, id)
        .await
        .expect("register peer");
    set.add(conn);
    id
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Status {
    root: Option<[u8; KEY_LEN]>,
    known: usize,
    links: usize,
}

/// What the test needs to see of the sender's own state.
#[derive(Debug)]
struct State {
    pending: Vec<Address>,
    sessions: Vec<[u8; KEY_LEN]>,
    has_path: bool,
}

enum Cmd {
    Status(Sender<Status>),
    /// Hand a payload to `send_or_resolve` over the node's first live link.
    Send {
        dest: Address,
        payload: Vec<u8>,
        reply: Sender<Result<Route, Error>>,
    },
    State {
        dest_key: [u8; KEY_LEN],
        reply: Sender<State>,
    },
    /// B: accept one more inbound link, C's.
    AcceptMore,
    /// C: dial B.
    Join,
}

fn status_of(router: &Router, set: &LinkSet) -> Status {
    Status {
        root: router.root_and_depth().map(|(r, _)| r),
        known: router.known_nodes(),
        links: set.len(),
    }
}

/// Poll a reply the node task only produces while this future is parked at an
/// await point (single-threaded runtime: no preemption).
async fn await_reply<T>(rx: Receiver<T>, what: &str) -> T {
    let end = tokio::time::Instant::now() + BUDGET;
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "no reply for {what} within {BUDGET:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}

async fn round_trip<T: Send + 'static>(
    tx: &Sender<Cmd>,
    make: impl FnOnce(Sender<T>) -> Cmd,
    what: &str,
) -> T {
    let (rtx, rrx): (Sender<T>, Receiver<T>) = channel();
    tx.send(make(rtx)).expect("node task is alive");
    await_reply(rrx, what).await
}

async fn status(tx: &Sender<Cmd>) -> Status {
    round_trip(tx, Cmd::Status, "status").await
}

async fn state(tx: &Sender<Cmd>, dest_key: [u8; KEY_LEN]) -> State {
    round_trip(tx, |reply| Cmd::State { dest_key, reply }, "state").await
}

async fn send(tx: &Sender<Cmd>, dest: Address, payload: &[u8]) -> Route {
    round_trip(
        tx,
        |reply| Cmd::Send {
            dest,
            payload: payload.to_vec(),
            reply,
        },
        "send",
    )
    .await
    .expect("send_or_resolve over a live link")
}

/// How a node gets its links: A dials at once, B accepts A at once and C when
/// told, C dials when told.
enum Wiring {
    /// Dial this now; the link is tapped when a log is given.
    DialNow(String, Option<Arc<Mutex<Vec<u8>>>>),
    /// Dial this when the node is told to join.
    DialOnJoin(String, Option<Arc<Mutex<Vec<u8>>>>),
    /// Accept one link now, then one more when told.
    AcceptThenAcceptMore(tokio::net::TcpListener),
}

/// One node: drain commands, then serve a slice, until asked to stop.
///
/// A node with no links sleeps rather than serving, so a linkless set never has
/// to survive a maintenance tick over nothing.
async fn drive<E, F>(
    sk: SigningKey,
    router: Router,
    wiring: Wiring,
    rx: Receiver<Cmd>,
    stop: Arc<AtomicBool>,
    report: F,
) -> E
where
    F: FnOnce(&Router, &LinkSet) -> E,
{
    let opts = LinkOptions::default();
    let mut router = router;
    let mut set = LinkSet::new();
    let mut out: Vec<([u8; KEY_LEN], Vec<u8>)> = Vec::new();

    // What is still to arrive, once the links that come first are up.
    let (mut dial_on_join, mut accept_more) = match wiring {
        Wiring::DialNow(uri, tap) => {
            let conn = roots::link::dial(&uri, &sk, &opts).await.expect("dial");
            join(&mut router, &mut set, conn, tap).await;
            (None, None)
        }
        Wiring::DialOnJoin(uri, tap) => (Some((uri, tap)), None),
        Wiring::AcceptThenAcceptMore(listener) => {
            let conn = roots::link::accept(&listener, &sk, &opts)
                .await
                .expect("accept first link");
            join(&mut router, &mut set, conn, None).await;
            (None, Some(listener))
        }
    };

    loop {
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Cmd::Status(tx) => {
                    let _ = tx.send(status_of(&router, &set));
                }
                Cmd::Send {
                    dest,
                    payload,
                    reply,
                } => {
                    // The lookup leaves on a live link and the payload that
                    // follows the notify picks its own next hop, so the handle
                    // is a liveness check and nothing more.
                    let Some(id) = set.ids().first().copied() else {
                        let _ = reply.send(Err(Error::NoLink));
                        continue;
                    };
                    let _ = reply.send(router.send_or_resolve(&mut set, id, &dest, payload).await);
                }
                Cmd::State { dest_key, reply } => {
                    let _ = reply.send(State {
                        pending: router.pending_routes(),
                        sessions: router.get_sessions(),
                        has_path: router.has_path(&dest_key),
                    });
                }
                Cmd::Join => {
                    if let Some((uri, tap)) = dial_on_join.take() {
                        let conn = roots::link::dial(&uri, &sk, &opts).await.expect("dial");
                        join(&mut router, &mut set, conn, tap).await;
                    }
                }
                Cmd::AcceptMore => {
                    if let Some(listener) = accept_more.take() {
                        let conn = roots::link::accept(&listener, &sk, &opts)
                            .await
                            .expect("accept");
                        join(&mut router, &mut set, conn, None).await;
                    }
                }
            }
        }
        if stop.load(Ordering::SeqCst) {
            return report(&router, &set);
        }
        if set.is_empty() {
            tokio::time::sleep(TICK).await;
        } else {
            let _ = router.serve_links(&mut set, Some(TICK), &mut out).await;
        }
    }
}

/// The three-node scenario, once per address form.
///
/// `subnet` picks what the sender asks for: C's node address, or the routed
/// `/64` that resolves to the same key through the other branch of
/// `lookup_key_for_addr`.
async fn scenario(subnet: bool) {
    let a_sk = SigningKey::from_bytes(&[0xD4; 32]);
    let b_sk = SigningKey::from_bytes(&[0xB2; 32]);
    let c_sk = SigningKey::from_bytes(&[0xC9; 32]);
    let c_pub = c_sk.verifying_key().to_bytes();
    let dest = if subnet {
        subnet_address(&c_pub)
    } else {
        addr_for_key(&c_pub)
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("tcp://{}", listener.local_addr().unwrap());

    let (a_tx, a_rx) = channel::<Cmd>();
    let (b_tx, b_rx) = channel::<Cmd>();
    let (c_tx, c_rx) = channel::<Cmd>();
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::new(AtomicBool::new(false));
    // A's link: what the sender put on the wire. C's link: what the
    // destination received.
    let a_wire = Arc::new(Mutex::new(Vec::new()));
    let c_wire = Arc::new(Mutex::new(Vec::new()));

    let a_task = {
        let (sk, rx, stop, wire, uri) = (
            a_sk.clone(),
            a_rx,
            stop_a.clone(),
            a_wire.clone(),
            uri.clone(),
        );
        tokio::spawn(async move {
            drive(
                sk.clone(),
                Router::new(sk),
                Wiring::DialNow(uri, Some(wire)),
                rx,
                stop,
                |_, _| (),
            )
            .await
        })
    };
    let b_task = {
        let (sk, rx, stop) = (b_sk.clone(), b_rx, stop_b.clone());
        tokio::spawn(async move {
            drive(
                sk.clone(),
                Router::new(sk),
                Wiring::AcceptThenAcceptMore(listener),
                rx,
                stop,
                |_, _| (),
            )
            .await
        })
    };
    let c_task = {
        let (sk, rx, stop, wire) = (c_sk.clone(), c_rx, stop_c.clone(), c_wire.clone());
        tokio::spawn(async move {
            drive(
                sk.clone(),
                Router::new(sk),
                Wiring::DialOnJoin(uri, Some(wire)),
                rx,
                stop,
                |_, _| (),
            )
            .await
        })
    };

    // A and B share one tree, and B has A's link: without a common root the
    // lookup A sends carries a path nothing can route a reply back along.
    let end = tokio::time::Instant::now() + BUDGET;
    loop {
        let (a, b) = (status(&a_tx).await, status(&b_tx).await);
        if a.root.is_some() && a.root == b.root && a.known >= 2 && b.known >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "A and B never converged: A {a:?} B {b:?}"
        );
        tokio::time::sleep(TICK).await;
    }

    // 1. A destination we cannot name yet is held, not dropped, and it costs
    //    no session: the held payload is network-layer traffic.
    assert_eq!(
        send(&a_tx, dest, FIRST).await,
        Route::Queued,
        "an unknown destination must be queued, not sent"
    );
    let s = state(&a_tx, c_pub).await;
    assert!(
        s.sessions.is_empty(),
        "a held payload must not open a session: {:?}",
        s.sessions
    );
    assert!(!s.has_path, "A has no path to C yet");
    if subnet {
        // The held slot is keyed by the lossy key, so the address a caller can
        // read back is that key's node-address form, not the `/64` it asked
        // for. Which form to report is `views.rs`'s call; the slot is this
        // slice's.
        assert_eq!(s.pending.len(), 1, "one destination is held");
    } else {
        assert_eq!(
            s.pending,
            vec![dest],
            "pending_routes must name the address that is waiting"
        );
    }

    // 2. A second payload before the notify arrives replaces the first: Go's
    //    `_handleTraffic` overwrites `rumor.traffic` unconditionally
    //    (`pathfinder.go:211-222`), and one slot per destination is the whole
    //    reason this seam cannot block.
    assert_eq!(send(&a_tx, dest, SECOND).await, Route::Queued);
    let s = state(&a_tx, c_pub).await;
    assert_eq!(s.pending.len(), 1, "one slot per destination");
    // Nothing has left: C is not in the mesh, so no notify can arrive, and a
    // payload that is only held never reaches a socket.
    assert!(
        !saw(&a_wire, FIRST) && !saw(&a_wire, SECOND),
        "a held payload must not reach the wire before the notify"
    );

    // 3. The destination joins. A re-drives the lookup on its own maintenance
    //    tick, C answers, the notify comes back, and the payload goes out with
    //    no second call from this test.
    c_tx.send(Cmd::Join).expect("C task is alive");
    b_tx.send(Cmd::AcceptMore).expect("B task is alive");
    let end = tokio::time::Instant::now() + BUDGET;
    while !saw(&c_wire, SECOND) {
        assert!(
            !saw(&c_wire, FIRST) && !saw(&a_wire, FIRST),
            "the overwritten payload was sent, so the slot is a queue"
        );
        assert!(
            tokio::time::Instant::now() < end,
            "the notify never delivered the held payload"
        );
        tokio::time::sleep(TICK).await;
    }
    assert!(
        saw(&a_wire, SECOND),
        "the delivered payload never left the sender"
    );
    // 5. The queue is empty again once the payload is on its way, and A now
    //    knows the key behind the address.
    let s = state(&a_tx, c_pub).await;
    assert!(
        s.pending.is_empty(),
        "pending_routes must empty after delivery: {:?}",
        s.pending
    );
    assert!(s.has_path, "the notify must leave A holding a path to C");

    // 4. A destination we already have a path to goes out at once.
    assert_eq!(
        send(&a_tx, dest, THIRD).await,
        Route::Sent,
        "a known path must send, not queue"
    );
    let end = tokio::time::Instant::now() + BUDGET;
    while !saw(&c_wire, THIRD) {
        assert!(
            tokio::time::Instant::now() < end,
            "a payload on a known path never arrived"
        );
        tokio::time::sleep(TICK).await;
    }

    // More slices, then the same question again: "overwritten" must not have
    // meant "delayed".
    for _ in 0..10 {
        tokio::time::sleep(TICK).await;
    }
    assert!(
        !saw(&a_wire, FIRST) && !saw(&c_wire, FIRST),
        "the overwritten payload was delivered after all"
    );
    assert!(
        state(&a_tx, c_pub).await.pending.is_empty(),
        "a send must leave nothing queued"
    );

    stop_a.store(true, Ordering::SeqCst);
    stop_b.store(true, Ordering::SeqCst);
    stop_c.store(true, Ordering::SeqCst);
    a_task.await.unwrap();
    b_task.await.unwrap();
    c_task.await.unwrap();
}

/// The plan's test: a payload to an address nobody has named yet is `Queued`,
/// a second one replaces it, the notify delivers the survivor with no second
/// call from the test, and a destination we already have a path to is `Sent`.
#[tokio::test]
async fn send_or_resolve_queues_then_delivers() {
    scenario(false).await;
}

/// The routed-subnet form of the same seam. `lookup_key_for_addr` takes the
/// `key_for_subnet` branch for a `03…` address (`address.rs:111-119`, Go's
/// `sendToSubnet`), so the lookup key is lossy in a different place and the
/// notify has to rendezvous with it all the same.
#[tokio::test]
async fn send_or_resolve_queues_a_routed_subnet() {
    scenario(true).await;
}

/// A handle the set does not hold is a refusal, not a silent queue: the payload
/// would sit in a rumor slot with no link to look it up on.
#[tokio::test]
async fn send_or_resolve_refuses_a_link_the_set_does_not_hold() {
    let sk = SigningKey::from_bytes(&[0xE7; 32]);
    let peer = SigningKey::from_bytes(&[0xF3; 32])
        .verifying_key()
        .to_bytes();
    let mut router = Router::new(sk);
    let mut links = LinkSet::new();
    let err = router
        .send_or_resolve(
            &mut links,
            LinkId::absent(),
            &addr_for_key(&peer),
            FIRST.to_vec(),
        )
        .await
        .expect_err("a link that is not in the set must be refused");
    assert!(matches!(err, Error::NoLink), "got {err:?}");
    assert!(
        router.pending_routes().is_empty(),
        "a refused send must not queue anything"
    );
    assert!(
        router.get_sessions().is_empty(),
        "a refused send must not open a session"
    );
}
