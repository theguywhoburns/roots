//! Spanning-tree router facade: composes per-algorithm tables (tree, paths,
//! blooms, sessions, proto) and re-exports the driver/views seams.
//! Algorithms live in their table modules; link I/O orchestration lives in
//! `src/driver.rs`; read-only snapshots live in `src/views.rs`
//! (plus the `Snapshot` trait in `src/traits.rs`).

use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::address::KEY_LEN;
use crate::bloom::BloomState;
use crate::frame::FRAME_KINDS;
use crate::pathfind::PathState;
use crate::proto::ProtoState;
use crate::session::SessionState;
use crate::tree::TreeState;

/// Router maintenance tick (Go: 1s).
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
/// Unknown-link latency sentinel. Go's is `time.Duration(^uint32(0))`
/// (`router.go:39`) — that is 4294967295 **nanoseconds**, about 4.29 ms, which
/// `_getCost` turns into a cost of 4: a mild penalty that keeps a brand-new link
/// from winning a tie, not a wall. Reading it as milliseconds instead made the
/// penalty 10⁶ times too large.
pub const UNKNOWN_LATENCY: Duration = Duration::from_nanos(u32::MAX as u64);

/// Spanning-tree router: composes per-algorithm tables (tree, paths, blooms,
/// sessions, proto) and drives them link by link through a [`LinkSet`]
/// (`register` once per link, `serve` / `serve_links` per slice). Each table
/// owns its own state; cross-table algorithms take explicit refs instead of
/// poking a shared god-object.
pub struct Router {
    /// Where every stored timestamp comes from.
    ///
    /// A field rather than a `std::time::Instant::now()` at each site, because the
    /// whole point of `roots_core::clock` is that the core *stores* time rather
    /// than asking a global clock for it — and `LinkState.sent_at`/`srrt` are
    /// exactly that. The alternative, calling `Instant::now()` inline, would be
    /// untestable: every expiry and every latency would need a real sleep, which
    /// is why those paths have no unit tests today.
    ///
    /// `StdClock` by default and swappable, so a caller can drive the state machine
    /// from a fixed clock. Nothing does yet — `Router::with_clock` exists for that
    /// and is the seam slice 7 uses.
    pub(crate) clock: crate::clock::StdClock,
    pub(crate) key: SigningKey,
    pub(crate) pubkey: [u8; KEY_LEN],
    pub(crate) tree: TreeState,
    pub(crate) path: PathState,
    pub(crate) bloom: BloomState,
    pub(crate) sess: SessionState,
    pub(crate) proto: ProtoState,
    /// Delivered session payloads: `(from_key, bytes)`.
    pub inbox: Vec<([u8; KEY_LEN], Vec<u8>)>,
    /// Delivered session-protocol responses: `(from_key, proto_bytes)`
    /// where `proto_bytes` starts with the `PROTO_*` dispatch byte.
    pub proto_inbox: Vec<([u8; KEY_LEN], Vec<u8>)>,
    /// Frames received per type (for diagnostics).
    pub frames: [u64; FRAME_KINDS],
    /// Soft sends the set discarded because the chosen next hop has no link.
    /// Go drops these silently; a counter is what makes the drop visible.
    pub(crate) dropped_no_link: u64,
}

impl Router {
    pub fn new(key: SigningKey) -> Self {
        Self::with_clock(key, crate::clock::StdClock::default())
    }

    /// A router whose stored timestamps come from `clock`.
    ///
    /// The seam that makes expiry and rotation testable without a `sleep`. Nothing
    /// calls this yet — the state machines still take their timestamps from the
    /// injected `StdClock` above rather than from a caller-supplied `dyn Clock`,
    /// because `Router` is `Send` and a trait object would need `+ Sync` to stay
    /// so. A `StdClock` is two `u64`s and copies; a `dyn Clock` is a pointer and a
    /// vtable. When a test genuinely needs to *drive* time, this is where it goes.
    pub fn with_clock(key: SigningKey, clock: crate::clock::StdClock) -> Self {
        let pubkey = key.verifying_key().to_bytes();
        Self {
            clock,
            key,
            pubkey,
            tree: TreeState::default(),
            path: PathState::default(),
            bloom: BloomState::default(),
            sess: SessionState::default(),
            proto: ProtoState::default(),
            inbox: Vec::new(),
            proto_inbox: Vec::new(),
            frames: [0; FRAME_KINDS],
            dropped_no_link: 0,
        }
    }

    pub fn pubkey(&self) -> [u8; KEY_LEN] {
        self.pubkey
    }

    /// Next session-init sequence number: strictly increasing per router.
    /// (Go stamps `unix_now()` seconds, so crossed inits/acks inside one
    /// second collide and are dropped as stale — deadlocking fast crossed
    /// opens. Peers only ever require `seq` greater than the last seen,
    /// so a local monotonic counter is wire-compatible and strictly more
    /// robust. `Cell` because init/ack building happens while session
    /// state is already borrowed.)
    pub(crate) fn next_init_seq(&self) -> u64 {
        let n = (crate::session::unix_now() + 1).max(
            self.sess
                .init_seq
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1),
        );
        self.sess
            .init_seq
            .store(n, std::sync::atomic::Ordering::Relaxed);
        n
    }

    /// Announce counters (tree table) for diagnostics.
    pub fn announces_sent(&self) -> u64 {
        self.tree.announces_sent
    }

    /// Announce counters (tree table) for diagnostics.
    pub fn announces_recv(&self) -> u64 {
        self.tree.announces_recv
    }

    /// Forget one link's per-connection state.
    ///
    /// The driver does this on eviction (`src/driver.rs`), and a caller that
    /// takes a link out of the set on its own behalf must do it too: a
    /// `LinkState` with no connection behind it would keep feeding `fix` a
    /// lag and a next-hop candidate for a socket that is closed. The per-key
    /// books are left alone, which is the deliberate divergence documented in
    /// `docs/architecture-map.md` — Go prunes all of it in `removePeer`
    /// (`router.go:147-168`).
    pub fn forget_link(&mut self, id: crate::link::LinkId) {
        self.tree.links.remove(&id);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::frame::FrameType;
    use crate::link::{LinkId, LinkOptions, LinkSet, Tcp};
    use crate::peer::{LinkState, PeerKind, PeerState};
    use crate::tree::{Info, SigReq, SigRes};
    use ed25519_dalek::Signer;

    /// In-memory transport, so a test can mint a [`LinkId`] with no socket at
    /// all: the id is minted inside `AnyConn::new` and `LinkId` has no public
    /// constructor (`link.rs:153-162`). Same shape as the one in `link.rs`'s
    /// own tests.
    #[derive(Clone)]
    struct Mem;

    impl crate::link::Transport for Mem {
        type Stream = tokio::io::DuplexStream;

        async fn dial(
            _addr: &str,
            _timeout: Duration,
        ) -> Result<Self::Stream, crate::error::Error> {
            unreachable!("test links are assembled by hand")
        }
    }

    /// A link handle no live link is filed under: builds a link, keeps only
    /// its id, and drops the connection. The far half of the `duplex` pair is
    /// dropped with it, so nothing addressed here can carry a frame.
    fn dangling_link(key: [u8; KEY_LEN]) -> LinkId {
        let (mine, theirs) = tokio::io::duplex(8);
        drop(theirs);
        crate::link::AnyConn::new(crate::link::PeerConn::<Mem> {
            remote_key: key,
            priority: 0,
            kind: PeerKind::Go,
            inbound: false,
            remote_addr: None,
            stream: mine,
        })
        .id
    }

    #[tokio::test]
    async fn query_snapshots_read_state() {
        // get_paths/get_sessions/link_peers/tree_entries are pure views:
        // empty on a fresh router, sorted and complete once filled.
        let sk = SigningKey::from_bytes(&[0x77; 32]);
        let mut router = Router::new(sk);
        assert!(router.get_paths().is_empty());
        assert!(router.get_sessions().is_empty());
        assert!(router.link_peers().is_empty());
        assert!(router.tree_entries().is_empty());
        let ka = [0xAA; 32];
        let kb = [0xBB; 32];
        router.tree.peers.insert(
            kb,
            PeerState {
                port: 3,
                req: crate::tree::SigReq { seq: 1, nonce: 1 },
            },
        );
        // The per-connection half of that peer's state lives in its own book
        // (`tree.links`), keyed by the link rather than the node key.
        let kb_link = dangling_link(kb);
        router.tree.links.insert(
            kb_link,
            LinkState {
                peer: kb,
                responded: true,
                lag: Duration::from_millis(12),
                sent_at: None,
                srrt: None,
                prio: 0,
                order: 0,
                kind: PeerKind::Go,
            },
        );
        router.path.entries.insert(
            ka,
            crate::pathfind::PathEntry {
                path: vec![4, 2],
                seq: 9,
                deadline: Instant::now() + Duration::from_secs(60),
                broken: false,
            },
        );
        let peers = router.link_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, kb_link, "the row names the link it describes");
        assert_eq!(peers[0].key, kb);
        assert_eq!(peers[0].port, 3);
        assert!(peers[0].responded);
        let paths = router.get_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], (ka, vec![4, 2], 9));
        assert!(router.get_sessions().is_empty());
    }

    #[tokio::test]
    async fn dropped_no_link_counts_soft_sends() {
        // A soft send that finds no link is a drop, and the counter is what
        // makes it visible: Go's equivalent drop is silent (`router.go`
        // `peers[key]` lookup), which is how a broken next hop hid for slices.
        let mut router = Router::new(SigningKey::from_bytes(&[5; 32]));
        let mut links = LinkSet::new();
        let absent = dangling_link([9u8; KEY_LEN]);
        for _ in 0..2 {
            router
                .write_via(&mut links, absent, FrameType::KeepAlive, &[])
                .await
                .unwrap();
        }
        assert_eq!(router.dropped_no_link(), 2);
        // Hard sends bypass the counter entirely: `LinkSet::write` reports
        // the missing link as `Error::NoLink` (see `linkset_write_reports_missing_peer`),
        // so a drop can only ever be a soft one.
        assert!(
            matches!(
                links.write(absent, FrameType::KeepAlive, &[]).await,
                Err(crate::error::Error::Core(crate::error::CoreError::NoLink))
            ),
            "hard send must not be swallowed by the counter"
        );
        assert_eq!(router.dropped_no_link(), 2, "hard send never counts");
    }

    #[tokio::test]
    async fn only_an_empty_set_makes_a_link_error_fatal() {
        // The whole "one dead link must not kill the others" rule reduces to
        // this predicate, so it is checked directly rather than through
        // socket-death timing that a test cannot control.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let (peer, _) = listener.accept().await.unwrap();
            // Held, never read: the link below stays live for this test.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(peer);
        });
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let key = [1u8; KEY_LEN];
        let mut links = LinkSet::single(crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
            remote_key: key,
            priority: 0,
            kind: PeerKind::Go,
            inbound: false,
            remote_addr: None,
            stream: sock,
        }));
        let id = *links.ids().first().expect("the one link just added");
        let io = crate::error::Error::Io(std::io::Error::from_raw_os_error(104));
        assert!(
            !Router::fatal_link_error(&links, &io),
            "a socket error on one of several links is not fatal"
        );
        assert!(
            !Router::fatal_link_error(&links, &crate::error::Error::NoLink),
            "a missing link is not fatal while others live"
        );
        assert!(
            Router::fatal_link_error(&links, &crate::error::Error::Timeout),
            "a non-link error stays fatal"
        );
        drop(links.remove(id));
        assert!(
            Router::fatal_link_error(&links, &io),
            "an empty set is fatal: the single-link `serve` contract"
        );
    }

    #[tokio::test]
    async fn mixed_transport_links_share_one_router() {
        // Slice 10a: one Router drives a TCP link and a WS link (the WS
        // side type-erased through `AnyConn`) as `&mut dyn Link`. Tree
        // converges and a session opens over the TCP leg.
        use crate::link::AnyConn;

        let c_sk = SigningKey::from_bytes(&[0x40; 32]);
        let s1_sk = SigningKey::from_bytes(&[0x10; 32]);
        let s2_sk = SigningKey::from_bytes(&[0x20; 32]);
        let s1_pub = s1_sk.verifying_key().to_bytes();

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let srv1 = tokio::spawn(async move {
            let (sock, _) = tcp_listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &s1_sk, &opts, true)
                .await
                .unwrap();
            let conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            };
            let mut router = Router::new(s1_sk);
            let mut conn = AnyConn::new(conn);
            let id = conn.id;
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
                .await;
        });
        let ws_listener = crate::ws::ws_listen("ws://127.0.0.1:0").await.unwrap();
        let ws_addr = ws_listener.local_addr().unwrap();
        let srv2 = tokio::spawn(async move {
            let conn = crate::ws::ws_accept(&ws_listener, &s2_sk, &LinkOptions::default())
                .await
                .unwrap();
            let key = conn.remote_key;
            let mut router = Router::new(s2_sk);
            let mut conn = AnyConn::new(conn);
            let id = conn.id;
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
                .await;
        });

        let tcp_uri = format!("tcp://{tcp_addr}");
        let tcp_conn = crate::link::dial(&tcp_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let tcp_peer = tcp_conn.remote_key;
        let ws_uri = format!("ws://{ws_addr}");
        let ws_conn = crate::ws::ws_dial(&ws_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let ws_peer = ws_conn.remote_key;
        let mut tcp_conn = AnyConn::new(tcp_conn);
        let mut ws_conn = AnyConn::new(ws_conn);
        let (tcp_id, ws_id) = (tcp_conn.id, ws_conn.id);

        let mut router = Router::new(c_sk);
        router
            .register(&mut tcp_conn, tcp_peer, tcp_id)
            .await
            .unwrap();
        router.register(&mut ws_conn, ws_peer, ws_id).await.unwrap();

        // One router serves both links through a single set (the 10b
        // shape); TCP stays concrete, WS arrives type-erased.
        let mut links = LinkSet::single(tcp_conn);
        links.add(ws_conn);
        router
            .serve_links(&mut links, Some(Duration::from_secs(8)), &mut Vec::new())
            .await
            .unwrap();
        assert!(router.parent().is_some(), "converged over mixed links");
        assert!(router.known_nodes() >= 3, "learned both peers");

        // Full stack over the TCP leg through the same set interface.
        router
            .session_send(&mut links, s1_pub, vec![0])
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < end {
            if router.has_session(&s1_pub) {
                break;
            }
            router.maintain(&mut links).await.unwrap();
            for id in [tcp_id, ws_id] {
                if let Ok(Ok((ftype, payload))) =
                    tokio::time::timeout(Duration::from_millis(100), links.read_frame(id)).await
                {
                    router
                        .dispatch_frame(&mut links, id, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
        }
        assert!(router.has_session(&s1_pub), "session over dyn TCP link");
        srv1.abort();
        srv2.abort();
    }

    /// One loopback server: handshake, register, then either drop the socket
    /// after `die_after` (killing the link mid-serve) or serve for 15s.
    async fn run_server(
        listener: tokio::net::TcpListener,
        sk: SigningKey,
        die_after: Option<Duration>,
    ) {
        let (sock, _) = listener.accept().await.unwrap();
        let mut sock = sock;
        let opts = LinkOptions::default();
        let (key, _, kind) = crate::link::run_handshake(&mut sock, &sk, &opts, true)
            .await
            .unwrap();
        let conn = crate::link::PeerConn::<Tcp> {
            remote_key: key,
            priority: 0,
            kind,
            inbound: true,
            remote_addr: None,
            stream: sock,
        };
        let mut router = Router::new(sk);
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        router.register(&mut conn, key, id).await.unwrap();
        if let Some(d) = die_after {
            // Die abruptly: no FIN handshake, just drop the socket.
            tokio::time::sleep(d).await;
            return;
        }
        let mut links = LinkSet::single(conn);
        let _ = router
            .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
            .await;
    }

    /// Three identities ordered by public key: the LARGEST is the client and
    /// the two smaller ones its peers. Go's `_fix` picks the lowest root it
    /// knows, so a client that outranks both peers can never be its own root
    /// — it has to adopt one of them.
    fn client_and_peers() -> (SigningKey, SigningKey, SigningKey) {
        let mut keys: Vec<SigningKey> = [1u8, 2, 3]
            .iter()
            .map(|b| SigningKey::from_bytes(&[*b; 32]))
            .collect();
        keys.sort_by_key(|k| k.verifying_key().to_bytes());
        (keys.remove(2), keys.remove(0), keys.remove(0))
    }

    /// A client `Router` holding two loopback links, both registered and in
    /// one owned set. `dying` names the peer whose server task drops its
    /// socket 2s in (`0` keeps both alive).
    /// Re-exported for `bloom.rs`'s on-tree test, which needs the same fixture and
    /// the same convergence. `pub(crate)` rather than duplicated: two copies of
    /// a three-node fixture drift, and a fixture that drifted would make the bloom
    /// assertions pass or fail for reasons unrelated to bloom.
    pub(crate) async fn client_over_two_links_for_bloom(
        dying: u8,
    ) -> (Router, LinkSet, [u8; 32], [u8; 32]) {
        client_over_two_links(dying).await
    }

    async fn client_over_two_links(dying: u8) -> (Router, LinkSet, [u8; 32], [u8; 32]) {
        let (c_sk, s1_sk, s2_sk) = client_and_peers();
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        let die = |n: u8| {
            if dying == n {
                Some(Duration::from_secs(2))
            } else {
                None
            }
        };
        tokio::spawn(run_server(l1, s1_sk, die(1)));
        tokio::spawn(run_server(l2, s2_sk, die(2)));
        let c1 = crate::link::dial(&format!("tcp://{a1}"), &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let p1 = c1.remote_key;
        let c2 = crate::link::dial(&format!("tcp://{a2}"), &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let p2 = c2.remote_key;
        let mut router = Router::new(c_sk);
        let mut c1 = crate::link::AnyConn::new(c1);
        let mut c2 = crate::link::AnyConn::new(c2);
        let (c1_id, c2_id) = (c1.id, c2.id);
        router.register(&mut c1, p1, c1_id).await.unwrap();
        router.register(&mut c2, p2, c2_id).await.unwrap();
        let mut links = LinkSet::single(c1);
        links.add(c2);
        (router, links, p1, p2)
    }

    /// Pump short slices until the client has a parent that is one of its two
    /// links — being its own root counts as a parent, so `parent().is_some()`
    /// alone would return before the tree formed.
    pub(crate) async fn converge(
        router: &mut Router,
        links: &mut LinkSet,
        peers: ([u8; 32], [u8; 32]),
    ) {
        for _ in 0..6 {
            router
                .serve_links(links, Some(Duration::from_millis(250)), &mut Vec::new())
                .await
                .expect("converges over live links");
            if let Some(p) = router.parent()
                && (p == peers.0 || p == peers.1)
            {
                return;
            }
        }
        panic!("never parented onto a link");
    }

    #[tokio::test]
    async fn serve_links_evicts_a_dead_link() {
        // Two loopback links; p1's socket dies mid-serve. The dead link is
        // evicted and the survivor keeps serving, instead of one dead link
        // aborting the whole serve the way single-link `serve` returns an
        // error when its only link drops.
        let (mut router, mut links, p1, p2) = client_over_two_links(1).await;
        converge(&mut router, &mut links, (p1, p2)).await;
        router
            .serve_links(&mut links, Some(Duration::from_secs(4)), &mut Vec::new())
            .await
            .expect("survivor keeps serving");
        assert!(!links.peers().contains(&p1), "dead link evicted");
        assert!(links.peers().contains(&p2), "live link kept");
        assert_ne!(
            router.parent(),
            Some(p1),
            "never left parented onto a peer with no link"
        );
    }

    #[tokio::test]
    async fn a_stale_parent_is_kept_and_the_serve_survives_it() {
        // Characterization + tripwire, not Slice 4 evidence: the parent's link
        // leaves the set while `tree.peers`, `tree.infos` and `bloom.on_tree`
        // still name that key. What Slice 4 guarantees is the tolerance — no
        // send to that key aborts the serve, and the survivor keeps working.
        // What it does NOT fix is where the tree points afterwards: the client
        // keeps a parent it has no link for, because nothing prunes
        // router-state-addressed books when a link dies. Go prunes them in
        // `removePeer` (`router.go:147`), so the last assertion here must
        // change when the router-state lifecycle slice lands.
        let (mut router, mut links, p1, p2) = client_over_two_links(0).await;
        converge(&mut router, &mut links, (p1, p2)).await;
        let dead = router.parent().expect("parented onto one of the links");
        assert!(dead == p1 || dead == p2, "parent is a live link");
        let live = if dead == p1 { p2 } else { p1 };
        // One link per key here, so the parent's key names exactly one link.
        let dead_links = links.links_to(&dead);
        assert_eq!(dead_links.len(), 1, "one link to the parent");
        drop(
            links
                .remove(dead_links[0])
                .expect("parent link was in the set"),
        );
        router
            .serve_links(&mut links, Some(Duration::from_secs(2)), &mut Vec::new())
            .await
            .expect("the stale key must not abort the serve");
        assert_eq!(
            router.parent(),
            Some(dead),
            "KNOWN DIVERGENCE, tripwire for the router-state lifecycle slice: \
             nothing prunes `tree.peers`/`infos`, so the client keeps a parent \
             it has no link for. Go prunes it in `removePeer` (router.go:147)."
        );
        assert!(links.peers().contains(&live), "survivor untouched");
    }

    #[tokio::test]
    async fn router_books_can_name_a_peer_with_no_link() {
        // The stale-key window itself, driven from the books instead of from
        // socket timing: Go prunes its router books when a link dies
        // (`removePeer`, router.go:147 clears peers/responses/ancs and the
        // bloom entry), we keep them, so `tree.peers` and `bloom.on_tree` can
        // name a key that has no link. Anything addressed at those books must
        // cope — `_sendReqs` iterates the live link map (router.go:189) and
        // the bloom fan-out is a soft send (bloomfilter.go:277). Both were
        // hard sends before Slice 4, which is how a stale key aborted a serve.
        let (mut router, mut links, p1, p2) = client_over_two_links(0).await;
        converge(&mut router, &mut links, (p1, p2)).await;
        let dead = router.parent().expect("parented onto one of the links");
        // Retire the links the way the driver does on a dead one
        // (`driver.rs:480-481`): the set AND `tree.links` together, which is
        // what makes `send_all_reqs` see no live peer. `tree.peers` and
        // `bloom.on_tree` are deliberately left behind — the divergence.
        for id in links.ids() {
            drop(links.remove(id));
            router.tree.links.remove(&id);
        }
        assert!(
            router.tree.peers.contains_key(&dead),
            "the book outlives the link: that is the divergence being survived"
        );
        assert!(
            !router.tree.links.values().any(|l| l.peer == dead),
            "the per-link book does NOT outlive the link: `fix` asks it"
        );
        assert!(
            router.bloom.on_tree.contains(&dead),
            "the bloom book outlives the link too"
        );
        router
            .send_all_reqs(&mut links)
            .await
            .expect("a stale tree peer is never addressed");
        router.bloom.send.clear(); // force a pending diff to advertise
        router
            .bloom_maintenance(&mut links)
            .await
            .expect("the stale on-tree entry is a counted skip, not an error");
        assert!(
            router.dropped_no_link() >= 1,
            "the skip is visible: {p1:?} and {p2:?} left no link behind"
        );
    }

    #[tokio::test]
    async fn fix_refuses_a_parent_with_no_link() {
        // `_fix` asks the LIVE link map whether its parent is still there (Go
        // router.go:229), and the books answer for nothing: `tree.peers`
        // outlives links here, so a dead parent would stay in play. The
        // scenario is built by hand because no converged loopback star
        // produces it — our star's parent never leads to a root better than
        // self, so the guarded branch is dead code there (see
        // `a_stale_parent_is_kept_and_the_serve_survives_it`).
        let mut keys: Vec<SigningKey> = [1u8, 2, 3, 4]
            .iter()
            .map(|b| SigningKey::from_bytes(&[*b; 32]))
            .collect();
        keys.sort_by_key(|k| k.verifying_key().to_bytes());
        // Ascending pubkeys: `a` roots the tree, `live` and `dead` hang one
        // hop below it (`live` first, so it wins the candidate scan), and the
        // client outranks all three.
        let (a, live, dead, c) = (
            keys.remove(0),
            keys.remove(0),
            keys.remove(0),
            keys.remove(0),
        );
        let (a_pub, l_pub, d_pub, c_pub) = (
            a.verifying_key().to_bytes(),
            live.verifying_key().to_bytes(),
            dead.verifying_key().to_bytes(),
            c.verifying_key().to_bytes(),
        );
        let mut router = Router::new(c);
        let self_root = SigRes::seal(SigReq { seq: 1, nonce: 7 }, 0, &a_pub, &a, &a_pub);
        router.tree.infos.insert(
            a_pub,
            Info {
                parent: a_pub,
                res: self_root,
                sig: self_root.psig,
            },
        );
        // Third-party lineage. These are the records `handle_announce` would
        // have stored after verifying: `fix` only reads `parent` out of them,
        // so they are bookkeeping, not a claim we checked a signature for.
        for (pk, sk) in [(l_pub, &live), (d_pub, &dead)] {
            let under_a = SigRes::seal(SigReq { seq: 1, nonce: 8 }, 5, &pk, &a, &a_pub);
            let sig = sk.sign(&under_a.bytes_for_sig(&pk, &a_pub)).to_bytes();
            router.tree.infos.insert(
                pk,
                Info {
                    parent: a_pub,
                    res: under_a,
                    sig,
                },
            );
        }
        // Our own lineage: parented onto `dead` through the real adoption path
        // (`use_response` builds the announce, verifies it, stores it), on an
        // older request than the one both peers have now answered, so
        // `update` accepts the new one.
        let from_dead = SigRes::seal(SigReq { seq: 1, nonce: 1 }, 5, &c_pub, &dead, &d_pub);
        assert!(
            router.use_response(d_pub, &from_dead),
            "our own announce has to verify, or the fixture proves nothing"
        );
        let open = router.new_req();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let (peer, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(peer);
        });
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut links = LinkSet::single(crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
            remote_key: l_pub,
            priority: 0,
            kind: PeerKind::Go,
            inbound: false,
            remote_addr: None,
            stream: sock,
        }));
        let live_id = *links.ids().first().expect("the one live link");
        for pk in [l_pub, d_pub] {
            // The per-key book, which outlives links: both keys are named
            // here even though only `live` is reachable.
            router
                .tree
                .peers
                .insert(pk, PeerState { port: 1, req: open });
            // What `handle_response` would have kept: our own request, signed
            // by the peer that answered it.
            let signer = if pk == l_pub { &live } else { &dead };
            router
                .tree
                .responses
                .insert(pk, SigRes::seal(open, 5, &c_pub, signer, &pk));
        }
        // The per-link book, which does NOT outlive links (`driver.rs:481`
        // prunes it on eviction): only `live` has one, which is exactly what
        // `fix` asks about.
        router.tree.links.insert(
            live_id,
            LinkState {
                peer: l_pub,
                responded: true,
                lag: Duration::from_millis(10),
                sent_at: None,
                srrt: None,
                prio: 0,
                order: 0,
                kind: PeerKind::Go,
            },
        );
        assert_eq!(router.parent(), Some(d_pub), "parented onto `dead`");
        assert!(!links.peers().contains(&d_pub), "`dead` has no link");
        router
            .fix(&mut links)
            .await
            .expect("the live peer is reachable");
        assert_eq!(
            router.parent(),
            Some(l_pub),
            "a parent with no link is refused, even though the books name it"
        );
    }

    #[tokio::test]
    async fn two_routers_converge_over_loopback() {
        // A dials B; both run routers for a beat. B should adopt A as parent
        // only if A is the lesser key... here just assert both learn each
        // other and stay consistent (no panics, infos exchanged).
        let a_sk = SigningKey::from_bytes(&[0x10; 32]);
        let b_sk = SigningKey::from_bytes(&[0x20; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            });
            let id = conn.id;
            let mut router = Router::new(b_sk);
            // Either side may close first at the deadline; convergence is
            // what we assert below, not a clean shutdown.
            let mut no_out = Vec::new();
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_millis(2600)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        let mut router = Router::new(a_sk);
        let mut no_out = Vec::new();
        router.register(&mut conn, peer_key, id).await.unwrap();
        let mut links = LinkSet::single(conn);
        let _ = router
            .serve(&mut links, Some(Duration::from_millis(2600)), &mut no_out)
            .await;
        let b_router = server.await.unwrap();
        // Both sides adopted a parent (one rooted, the other attached).
        assert!(router.parent().is_some());
        assert!(b_router.parent().is_some());
        // Both agree on the root.
        assert_eq!(
            router.root_and_depth().map(|(r, _)| r),
            b_router.root_and_depth().map(|(r, _)| r)
        );
    }

    #[tokio::test]
    async fn session_payload_loopback() {
        // Full stack over loopback: lookup + session + encrypted delivery.
        let a_sk = SigningKey::from_bytes(&[0x30; 32]);
        let b_sk = SigningKey::from_bytes(&[0x40; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let a_pub = a_sk.verifying_key().to_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            });
            let id = conn.id;
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(10)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        assert_eq!(peer_key, b_pub);
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key, id).await.unwrap();
        let mut outgoing = vec![(b_pub, b"ping-0".to_vec())];
        let mut links = LinkSet::single(conn);
        let _ = router
            .serve(&mut links, Some(Duration::from_secs(10)), &mut outgoing)
            .await;
        let b_router = server.await.unwrap();
        assert!(
            b_router
                .inbox
                .iter()
                .any(|(from, msg)| *from == a_pub && msg == b"ping-0"),
            "B inbox: {:?}",
            b_router
                .inbox
                .iter()
                .map(|(f, m)| (hex::encode(f), m.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn resolve_loopback() {
        // A resolves B's IPv6 address to B's full key over a live link.
        let a_sk = SigningKey::from_bytes(&[0x60; 32]);
        let b_sk = SigningKey::from_bytes(&[0x70; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let b_addr = crate::address::addr_for_key(&b_pub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            });
            let id = conn.id;
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key, id).await.unwrap();
        // Converge first (mirrors serve slices): maintain + dispatch.
        // The set lives across converge and resolve so send clocks persist.
        let mut links = LinkSet::single(conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut links, id, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut links, id, &b_addr, Duration::from_secs(5))
            .await
            .expect("resolve B addr");
        assert_eq!(found, b_pub);
        let _ = server.await;
    }

    #[tokio::test]
    async fn resolve_subnet_loopback() {
        // A resolves an address inside B's routed /64 to B's full key.
        let a_sk = SigningKey::from_bytes(&[0x30; 32]);
        let b_sk = SigningKey::from_bytes(&[0x40; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let b_snet = crate::address::subnet_for_key(&b_pub);
        let mut target_raw = [0u8; 16];
        target_raw[..8].copy_from_slice(&b_snet.0);
        target_raw[15] = 0x41;
        let target = crate::address::Address(target_raw);
        assert!(target.is_subnet());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            });
            let id = conn.id;
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key, id).await.unwrap();
        let mut links = LinkSet::single(conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut links, id, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut links, id, &target, Duration::from_secs(10))
            .await;
        let found = found.expect("resolve B subnet addr");
        assert_eq!(found, b_pub);
        let _ = server.await;
    }

    #[tokio::test]
    async fn crossed_session_open_delivers_both_ways() {
        // Both ends send first at the same time (no session either way).
        //
        // The simultaneous FIRST flight is inherently racy (each side's
        // ack advances key expectations ahead of the other's flushed
        // payload, deterministically dropping both — same in Go, where
        // the ack is likewise sent before the buffered payload flushes).
        // What must hold: the sessions converge anyway, so the SECOND
        // flight delivers both ways with no permanent desync.
        let a_sk = SigningKey::from_bytes(&[0xC3; 32]);
        let b_sk = SigningKey::from_bytes(&[0xC4; 32]);
        let a_pub = a_sk.verifying_key().to_bytes();
        let b_pub = b_sk.verifying_key().to_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::AnyConn::new(crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                inbound: true,
                remote_addr: None,
                stream: sock,
            });
            let id = conn.id;
            let mut router = Router::new(b_sk);
            router.register(&mut conn, key, id).await.unwrap();
            let mut links = LinkSet::single(conn);
            // Converge, then send FIRST (simultaneously with A below).
            let end = tokio::time::Instant::now() + Duration::from_secs(4);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links).await.unwrap();
                if let Ok(Ok((ftype, payload))) =
                    tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
                {
                    router
                        .dispatch_frame(&mut links, id, ftype, &payload)
                        .await
                        .unwrap();
                }
                if router.parent().is_some() && router.root_path().is_some() {
                    break;
                }
            }
            router
                .session_send(&mut links, a_pub, b"from-B".to_vec())
                .await
                .unwrap();
            // First flight may drop (see test doc); pump past it, then
            // assert the second flight lands.
            let end = tokio::time::Instant::now() + Duration::from_secs(8);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links).await.unwrap();
                if let Ok(Ok((ftype, payload))) =
                    tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
                {
                    router
                        .dispatch_frame(&mut links, id, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
            router
                .session_send(&mut links, a_pub, b"from-B2".to_vec())
                .await
                .unwrap();
            let end = tokio::time::Instant::now() + Duration::from_secs(8);
            while tokio::time::Instant::now() < end {
                if router
                    .inbox
                    .iter()
                    .any(|(k, m)| *k == a_pub && m == b"from-A2")
                {
                    break;
                }
                router.maintain(&mut links).await.unwrap();
                if let Ok(Ok((ftype, payload))) =
                    tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
                {
                    router
                        .dispatch_frame(&mut links, id, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
            router
        });
        let uri = format!("tcp://{addr}");
        let conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut conn = crate::link::AnyConn::new(conn);
        let id = conn.id;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key, id).await.unwrap();
        let mut links = LinkSet::single(conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
            {
                router
                    .dispatch_frame(&mut links, id, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        // Simultaneous first send (B already sent above); it may drop
        // (see test doc) — the second flight is the real assertion.
        router
            .session_send(&mut links, b_pub, b"from-A".to_vec())
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
            {
                router
                    .dispatch_frame(&mut links, id, ftype, &payload)
                    .await
                    .unwrap();
            }
        }
        router
            .session_send(&mut links, b_pub, b"from-A2".to_vec())
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < end {
            if router
                .inbox
                .iter()
                .any(|(k, m)| *k == b_pub && m == b"from-B2")
            {
                break;
            }
            router.maintain(&mut links).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), links.read_frame(id)).await
            {
                router
                    .dispatch_frame(&mut links, id, ftype, &payload)
                    .await
                    .unwrap();
            }
        }
        assert!(
            router
                .inbox
                .iter()
                .any(|(k, m)| *k == b_pub && m == b"from-B2"),
            "A got B's second payload, inbox={:?}",
            router.inbox
        );
        let b_router = server.await.unwrap();
        assert!(
            b_router
                .inbox
                .iter()
                .any(|(k, m)| *k == a_pub && m == b"from-A2"),
            "B got A's second payload, inbox={:?}",
            b_router.inbox
        );
    }
}
