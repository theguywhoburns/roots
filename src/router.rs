//! Spanning-tree router facade: composes per-algorithm tables (tree, paths,
//! blooms, sessions, proto) and re-exports the driver/views seams.
//! Algorithms live in their table modules; link I/O orchestration lives in
//! `src/driver.rs`; read-only snapshots live in `src/views.rs`
//! (plus the `Snapshot` trait in `src/traits.rs`).

use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::address::KEY_LEN;
use crate::bloom::BloomState;
use crate::pathfind::PathState;
use crate::proto::ProtoState;
use crate::session::SessionState;
use crate::tree::TreeState;

/// Router maintenance tick (Go: 1s).
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
/// Unknown-link latency sentinel (Go: `routerUnknownLatency`).
pub const UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);

/// Spanning-tree router: composes per-algorithm tables (tree, paths, blooms,
/// sessions, proto) and drives them link by link through a [`LinkSet`]
/// (`register` once per link, `serve` / `serve_links` per slice). Each table
/// owns its own state; cross-table algorithms take explicit refs instead of
/// poking a shared god-object.
pub struct Router {
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
    pub frames: [u64; 10],
}

impl Router {
    pub fn new(key: SigningKey) -> Self {
        let pubkey = key.verifying_key().to_bytes();
        Self {
            key,
            pubkey,
            tree: TreeState::default(),
            path: PathState::default(),
            bloom: BloomState::default(),
            sess: SessionState::default(),
            proto: ProtoState::default(),
            inbox: Vec::new(),
            proto_inbox: Vec::new(),
            frames: [0; 10],
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

    /// Which implementation a link peer runs (`Go` when unknown).
    /// Gates roots-only behavior fixes; defaults to Go-exact.
    pub fn peer_kind(&self, peer: &[u8; KEY_LEN]) -> crate::peer::PeerKind {
        self.tree
            .peers
            .get(peer)
            .map(|p| p.kind.clone())
            .unwrap_or(crate::peer::PeerKind::Go)
    }

    /// True when the link peer advertised itself as roots.
    pub fn is_roots_peer(&self, peer: &[u8; KEY_LEN]) -> bool {
        self.peer_kind(peer).is_roots()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::link::{LinkOptions, LinkSet, Tcp};
    use crate::peer::{PeerKind, PeerState};

    #[test]
    fn query_snapshots_read_state() {
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
                responded: true,
                lag: Duration::from_millis(12),
                sent_at: None,
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
                req_at: None,
                deadline: Instant::now() + Duration::from_secs(60),
                broken: false,
            },
        );
        let peers = router.link_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, kb);
        assert_eq!(peers[0].1, 3);
        assert!(peers[0].3);
        let paths = router.get_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], (ka, vec![4, 2], 9));
        assert!(router.get_sessions().is_empty());
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(s1_sk);
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
                .await;
        });
        let ws_listener = crate::ws::ws_listen("ws://127.0.0.1:0").await.unwrap();
        let ws_addr = ws_listener.local_addr().unwrap();
        let srv2 = tokio::spawn(async move {
            let mut conn = crate::ws::ws_accept(&ws_listener, &s2_sk, &LinkOptions::default())
                .await
                .unwrap();
            let key = conn.remote_key;
            let mut router = Router::new(s2_sk);
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
                .await;
        });

        let tcp_uri = format!("tcp://{tcp_addr}");
        let mut tcp_conn = crate::link::dial(&tcp_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let tcp_peer = tcp_conn.remote_key;
        let ws_uri = format!("ws://{ws_addr}");
        let ws_conn = crate::ws::ws_dial(&ws_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let ws_peer = ws_conn.remote_key;
        let mut ws_conn = AnyConn::new(ws_conn);

        let mut router = Router::new(c_sk);
        router.register(&mut tcp_conn, tcp_peer).await.unwrap();
        router.register(&mut ws_conn, ws_peer).await.unwrap();

        // One router serves both links through a single set (the 10b
        // shape); TCP stays concrete, WS arrives type-erased.
        let mut links = LinkSet::single(tcp_peer, &mut tcp_conn);
        links.add(ws_peer, &mut ws_conn);
        router
            .serve_links(&mut links, Some(Duration::from_secs(8)), &mut Vec::new())
            .await
            .unwrap();
        assert!(router.parent().is_some(), "converged over mixed links");
        assert!(router.known_nodes() >= 3, "learned both peers");

        // Full stack over the TCP leg through the same set interface.
        router
            .session_send(&mut links, tcp_peer, s1_pub, vec![0])
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < end {
            if router.has_session(&s1_pub) {
                break;
            }
            router.maintain(&mut links, tcp_peer).await.unwrap();
            router.maintain(&mut links, ws_peer).await.unwrap();
            for peer in [tcp_peer, ws_peer] {
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(100),
                    links.get(&peer).unwrap().read_frame(),
                )
                .await
                {
                    router
                        .dispatch_frame(&mut links, peer, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
        }
        assert!(router.has_session(&s1_pub), "session over dyn TCP link");
        srv1.abort();
        srv2.abort();
    }

    #[tokio::test]
    async fn serve_links_evicts_dead_link() {
        // Two loopback links, one peer dies mid-serve: the dead link is
        // evicted from the set and the survivor keeps serving (instead
        // of one dead link aborting the whole serve like single-link
        // `serve` does when its only link drops).
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(sk);
            router.register(&mut conn, key).await.unwrap();
            if let Some(d) = die_after {
                // Die abruptly: no FIN handshake, just drop the socket.
                tokio::time::sleep(d).await;
                return;
            }
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(15)), &mut Vec::new())
                .await;
        }

        let c_sk = SigningKey::from_bytes(&[0x41; 32]);
        let s1_sk = SigningKey::from_bytes(&[0x11; 32]);
        let s2_sk = SigningKey::from_bytes(&[0x21; 32]);

        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        let srv1 = tokio::spawn(run_server(l1, s1_sk, None));
        let srv2 = tokio::spawn(run_server(l2, s2_sk, Some(Duration::from_secs(1))));

        let mut c1 = crate::link::dial(&format!("tcp://{a1}"), &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let p1 = c1.remote_key;
        let mut c2 = crate::link::dial(&format!("tcp://{a2}"), &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let p2 = c2.remote_key;

        let mut router = Router::new(c_sk);
        router.register(&mut c1, p1).await.unwrap();
        router.register(&mut c2, p2).await.unwrap();
        let mut links = LinkSet::single(p1, &mut c1);
        links.add(p2, &mut c2);
        // Must return Ok at hold expiry even though p2 died mid-serve.
        router
            .serve_links(&mut links, Some(Duration::from_secs(5)), &mut Vec::new())
            .await
            .expect("survivor keeps serving");
        assert!(router.parent().is_some(), "converged via survivor");
        assert!(!links.peers().contains(&p2), "dead link evicted");
        assert!(links.peers().contains(&p1), "live link kept");
        srv1.abort();
        srv2.abort();
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            // Either side may close first at the deadline; convergence is
            // what we assert below, not a clean shutdown.
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_millis(2600)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        let mut no_out = Vec::new();
        router.register(&mut conn, peer_key).await.unwrap();
        let mut links = LinkSet::single(peer_key, &mut conn);
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(10)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        assert_eq!(peer_key, b_pub);
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        let mut outgoing = vec![(b_pub, b"ping-0".to_vec())];
        let mut links = LinkSet::single(peer_key, &mut conn);
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        // Converge first (mirrors serve slices): maintain + dispatch.
        // The set lives across converge and resolve so send clocks persist.
        let mut links = LinkSet::single(peer_key, &mut conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                Duration::from_millis(300),
                links.get(&peer_key).unwrap().read_frame(),
            )
            .await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut links, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut links, peer_key, &b_addr, Duration::from_secs(5))
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
        assert!(target.0[0] == crate::address::NODE_PREFIX | crate::address::SUBNET_BIT);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _, kind) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            let _ = router
                .serve(&mut links, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        let mut links = LinkSet::single(peer_key, &mut conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                Duration::from_millis(300),
                links.get(&peer_key).unwrap().read_frame(),
            )
            .await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut links, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut links, peer_key, &target, Duration::from_secs(10))
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
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                kind,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            router.register(&mut conn, key).await.unwrap();
            let mut links = LinkSet::single(key, &mut conn);
            // Converge, then send FIRST (simultaneously with A below).
            let end = tokio::time::Instant::now() + Duration::from_secs(4);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links, key).await.unwrap();
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(300),
                    links.get(&key).unwrap().read_frame(),
                )
                .await
                {
                    router
                        .dispatch_frame(&mut links, key, ftype, &payload)
                        .await
                        .unwrap();
                }
                if router.parent().is_some() && router.root_path().is_some() {
                    break;
                }
            }
            router
                .session_send(&mut links, key, a_pub, b"from-B".to_vec())
                .await
                .unwrap();
            // First flight may drop (see test doc); pump past it, then
            // assert the second flight lands.
            let end = tokio::time::Instant::now() + Duration::from_secs(8);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links, key).await.unwrap();
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(300),
                    links.get(&key).unwrap().read_frame(),
                )
                .await
                {
                    router
                        .dispatch_frame(&mut links, key, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
            router
                .session_send(&mut links, key, a_pub, b"from-B2".to_vec())
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
                router.maintain(&mut links, key).await.unwrap();
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(300),
                    links.get(&key).unwrap().read_frame(),
                )
                .await
                {
                    router
                        .dispatch_frame(&mut links, key, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        let mut links = LinkSet::single(peer_key, &mut conn);
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                Duration::from_millis(300),
                links.get(&peer_key).unwrap().read_frame(),
            )
            .await
            {
                router
                    .dispatch_frame(&mut links, peer_key, ftype, &payload)
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
            .session_send(&mut links, peer_key, b_pub, b"from-A".to_vec())
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(8);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut links, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                Duration::from_millis(300),
                links.get(&peer_key).unwrap().read_frame(),
            )
            .await
            {
                router
                    .dispatch_frame(&mut links, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
        }
        router
            .session_send(&mut links, peer_key, b_pub, b"from-A2".to_vec())
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
            router.maintain(&mut links, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                Duration::from_millis(300),
                links.get(&peer_key).unwrap().read_frame(),
            )
            .await
            {
                router
                    .dispatch_frame(&mut links, peer_key, ftype, &payload)
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
