//! Session-protocol (nodeinfo/debug) handling. Port of
//! `yggdrasil-go/src/core/proto.go` + `nodeinfo.go` responder halves.
//!
//! Go multiplexes two payload kinds inside one E2E session, dispatched on
//! the leading byte (`Core.ReadFrom`): `1` = TUN traffic (delivered to
//! `Router::inbox`), `2` = protocol. Protocol frames start with a second
//! dispatch byte (`typeProtoNodeInfoRequest/Response`, or `255` = debug
//! with a third `typeDebug…` byte). Requests are answered from local
//! router state; responses to our own requests land in
//! `Router::proto_inbox` (raw bytes after the `2` session-proto byte),
//! mirroring the `inbox` pattern — no timer/callback registry, the app
//! drains and matches.

use crate::address::KEY_LEN;
use crate::link::{Link, LinkSet};
use crate::session::PACKET_TYPE_PROTO;

/// Protocol dispatch byte: no-op (yggdrasil-go `typeProtoDummy`).
pub const PROTO_DUMMY: u8 = 0;
/// Protocol dispatch byte: nodeinfo request (yggdrasil-go
/// `typeProtoNodeInfoRequest`).
pub const PROTO_NODEINFO_REQ: u8 = 1;
/// Protocol dispatch byte: nodeinfo response carrying raw JSON
/// (yggdrasil-go `typeProtoNodeInfoResponse`).
pub const PROTO_NODEINFO_RES: u8 = 2;
/// Protocol dispatch byte: debug sub-protocol (yggdrasil-go
/// `typeProtoDebug = 255`).
pub const PROTO_DEBUG: u8 = 255;

/// Debug subtype: no-op (yggdrasil-go `typeDebugDummy`).
pub const DEBUG_DUMMY: u8 = 0;
/// Debug subtype: getSelf request (yggdrasil-go
/// `typeDebugGetSelfRequest`).
pub const DEBUG_GETSELF_REQ: u8 = 1;
/// Debug subtype: getSelf response, JSON `{"key","routing_entries"}`
/// (yggdrasil-go `typeDebugGetSelfResponse`).
pub const DEBUG_GETSELF_RES: u8 = 2;
/// Debug subtype: getPeers request (yggdrasil-go
/// `typeDebugGetPeersRequest`).
pub const DEBUG_GETPEERS_REQ: u8 = 3;
/// Debug subtype: getPeers response, concatenated 32-byte keys
/// (yggdrasil-go `typeDebugGetPeersResponse`).
pub const DEBUG_GETPEERS_RES: u8 = 4;
/// Debug subtype: getTree request (yggdrasil-go
/// `typeDebugGetTreeRequest`).
pub const DEBUG_GETTREE_REQ: u8 = 5;
/// Debug subtype: getTree response, concatenated 32-byte keys
/// (yggdrasil-go `typeDebugGetTreeResponse`).
pub const DEBUG_GETTREE_RES: u8 = 6;

/// Nodeinfo size cap (yggdrasil-go `nodeinfo._setNodeInfo` rejects JSON
/// over 16384 bytes).
pub const NODEINFO_MAX: usize = 16384;
/// Default nodeinfo served before the app sets its own (Go serves whatever
/// was configured; unset here means an empty object, still valid JSON).
pub const NODEINFO_DEFAULT: &[u8] = b"{}";
/// Response key-list cap: Go stops appending peer/tree keys once the
/// response would exceed `Core.MTU` (link max 65535 minus overheads);
/// anything under ~64 KiB is safe on a live link.
pub const PROTO_RESPONSE_MAX: usize = 65535 - 64;

impl crate::router::Router {
    /// Replace our advertised nodeinfo (raw JSON, ≤ 16384 bytes).
    pub fn set_nodeinfo(&mut self, json: Vec<u8>) -> Result<(), crate::error::Error> {
        if json.len() > NODEINFO_MAX {
            return Err(crate::error::Error::InvalidLength);
        }
        self.nodeinfo = json;
        Ok(())
    }

    /// Send one raw protocol frame (`payload` starts with the
    /// `PROTO_*` dispatch byte) to `dest`, opening the session first if
    /// needed — same buffering as traffic sends.
    pub async fn proto_send(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
        payload: Vec<u8>,
    ) -> Result<(), crate::error::Error> {
        self.session_send_kind(links, conn_peer, dest, PACKET_TYPE_PROTO, payload)
            .await
    }

    /// Ask `dest` for its nodeinfo; the `PROTO_NODEINFO_RES` reply arrives
    /// in [`Router::proto_inbox`](crate::router::Router::proto_inbox).
    pub async fn request_nodeinfo(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
    ) -> Result<(), crate::error::Error> {
        self.proto_send(links, conn_peer, dest, vec![PROTO_NODEINFO_REQ])
            .await
    }

    /// Ask `dest` for its debug self/peers/tree snapshot; the matching
    /// `DEBUG_*_RES` reply arrives in `proto_inbox`.
    pub async fn request_debug(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
        what: u8,
    ) -> Result<(), crate::error::Error> {
        debug_assert!(
            matches!(
                what,
                DEBUG_GETSELF_REQ | DEBUG_GETPEERS_REQ | DEBUG_GETTREE_REQ
            ),
            "request_debug takes a *_REQ subtype"
        );
        self.proto_send(links, conn_peer, dest, vec![PROTO_DEBUG, what])
            .await
    }

    /// Dispatch one inbound protocol payload (bytes after the
    /// `typeSessionProto` session byte): answer requests from local state,
    /// deliver responses to `proto_inbox`, ignore dummies/unknowns — the
    /// same accept-and-ignore shape as Go `protoHandler.handleProto`.
    pub(crate) async fn handle_proto_bytes(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        from: [u8; KEY_LEN],
        payload: &[u8],
    ) -> Result<(), crate::error::Error> {
        let Some((&kind, rest)) = payload.split_first() else {
            return Ok(());
        };
        match kind {
            PROTO_DUMMY => {}
            PROTO_NODEINFO_REQ => {
                let mut out = Vec::with_capacity(self.nodeinfo.len() + 1);
                out.push(PROTO_NODEINFO_RES);
                out.extend_from_slice(&self.nodeinfo);
                self.proto_send(links, conn_peer, from, out).await?;
            }
            PROTO_NODEINFO_RES => {
                self.proto_inbox.push((from, payload.to_vec()));
            }
            PROTO_DEBUG => self.handle_debug_bytes(links, conn_peer, from, rest).await?,
            _ => {}
        }
        Ok(())
    }

    async fn handle_debug_bytes(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        from: [u8; KEY_LEN],
        payload: &[u8],
    ) -> Result<(), crate::error::Error> {
        let Some((&kind, rest)) = payload.split_first() else {
            return Ok(());
        };
        match kind {
            DEBUG_DUMMY => {}
            DEBUG_GETSELF_REQ => {
                // Go `_handleGetSelfRequest`: JSON object with our hex key
                // plus routing-entry count (their `SelfInfo`).
                let body = format!(
                    "{{\"key\":\"{}\",\"routing_entries\":\"{}\"}}",
                    hex::encode(self.pubkey),
                    self.infos.len()
                );
                let mut out = Vec::with_capacity(body.len() + 2);
                out.push(PROTO_DEBUG);
                out.push(DEBUG_GETSELF_RES);
                out.extend_from_slice(body.as_bytes());
                self.proto_send(links, conn_peer, from, out).await?;
            }
            DEBUG_GETPEERS_REQ => {
                // Go `_handleGetPeersRequest`: concatenated link-peer keys,
                // MTU-capped. Our link peers are the router peer keys.
                let mut keys: Vec<[u8; KEY_LEN]> = self.peers.keys().copied().collect();
                keys.sort();
                let out = concat_keys(PROTO_DEBUG, DEBUG_GETPEERS_RES, &keys);
                self.proto_send(links, conn_peer, from, out).await?;
            }
            DEBUG_GETTREE_REQ => {
                // Go `_handleGetTreeRequest`: concatenated known-tree keys,
                // MTU-capped.
                let mut keys: Vec<[u8; KEY_LEN]> = self.infos.keys().copied().collect();
                keys.sort();
                let out = concat_keys(PROTO_DEBUG, DEBUG_GETTREE_RES, &keys);
                self.proto_send(links, conn_peer, from, out).await?;
            }
            DEBUG_GETSELF_RES | DEBUG_GETPEERS_RES | DEBUG_GETTREE_RES => {
                let _ = rest;
                self.proto_inbox.push((from, {
                    let mut full = Vec::with_capacity(payload.len() + 1);
                    full.push(PROTO_DEBUG);
                    full.extend_from_slice(payload);
                    full
                }));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Frame `DEBUG_*_RES` bodies: two dispatch bytes plus as many sorted
/// 32-byte keys as fit under the response cap.
fn concat_keys(dispatch: u8, subtype: u8, keys: &[[u8; KEY_LEN]]) -> Vec<u8> {
    let mut out = vec![dispatch, subtype];
    for k in keys {
        if out.len() + KEY_LEN + 2 > PROTO_RESPONSE_MAX {
            break;
        }
        out.extend_from_slice(k);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{LinkOptions, Tcp};
    use crate::router::Router;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

    /// Converged A↔B loopback pair with an open A→B session. Returns
    /// `(a_router, a_conn, a_peer, b_pub, server_handle)`. B runs `serve`
    /// in the background, so B-side responders answer on their own.
    async fn live_pair(
        a_seed: u8,
        b_seed: u8,
    ) -> (
        Router,
        crate::link::PeerConn<Tcp>,
        [u8; KEY_LEN],
        [u8; KEY_LEN],
        tokio::task::JoinHandle<()>,
    ) {
        let a_sk = SigningKey::from_bytes(&[a_seed; 32]);
        let b_sk = SigningKey::from_bytes(&[b_seed; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(
                    &mut conn,
                    key,
                    Some(Duration::from_secs(30)),
                    &mut Vec::new(),
                )
                .await;
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut conn, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut conn, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
            }
        }
        assert!(router.parent().is_some(), "A converged");
        // Open the session with a throwaway traffic byte so proto
        // requests below send immediately instead of buffering.
        router
            .session_send(&mut conn, peer_key, b_pub, vec![0])
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < end {
            if router.has_session(&b_pub) {
                break;
            }
            router.maintain(&mut conn, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut conn, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
        }
        assert!(router.has_session(&b_pub), "A has session for B");
        (router, conn, peer_key, b_pub, server)
    }

    /// Pump A's link until `pred` holds over `proto_inbox`, or time out.
    async fn pump_proto(
        router: &mut Router,
        conn: &mut crate::link::PeerConn<Tcp>,
        peer_key: [u8; KEY_LEN],
        pred: impl Fn(&[([u8; KEY_LEN], Vec<u8>)]) -> bool,
    ) {
        let end = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < end {
            if pred(&router.proto_inbox) {
                return;
            }
            router.maintain(conn, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(conn, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
        }
        panic!("proto reply never arrived: {:?}", router.proto_inbox);
    }

    #[tokio::test]
    async fn nodeinfo_round_trip() {
        let (mut router, mut conn, peer_key, b_pub, server) = live_pair(0x11, 0x22).await;
        router
            .request_nodeinfo(&mut conn, peer_key, b_pub)
            .await
            .unwrap();
        pump_proto(&mut router, &mut conn, peer_key, |inbox| {
            inbox
                .iter()
                .any(|(k, p)| *k == b_pub && p.first() == Some(&PROTO_NODEINFO_RES))
        })
        .await;
        let (_, body) = router
            .proto_inbox
            .iter()
            .find(|(k, p)| *k == b_pub && p.first() == Some(&PROTO_NODEINFO_RES))
            .unwrap();
        assert_eq!(&body[1..], b"{}");
        server.abort();
    }

    #[tokio::test]
    async fn debug_round_trips() {
        let (mut router, mut conn, peer_key, b_pub, server) = live_pair(0x33, 0x44).await;
        for what in [DEBUG_GETSELF_REQ, DEBUG_GETPEERS_REQ, DEBUG_GETTREE_REQ] {
            router
                .request_debug(&mut conn, peer_key, b_pub, what)
                .await
                .unwrap();
        }
        pump_proto(&mut router, &mut conn, peer_key, |inbox| {
            inbox.iter().filter(|(k, _)| *k == b_pub).count() >= 3
        })
        .await;
        let mut kinds: Vec<u8> = router
            .proto_inbox
            .iter()
            .filter(|(k, _)| *k == b_pub)
            .map(|(_, p)| p[1])
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            vec![DEBUG_GETSELF_RES, DEBUG_GETPEERS_RES, DEBUG_GETTREE_RES]
        );
        // getSelf body names B's key with a routing-entry count.
        let self_body = router
            .proto_inbox
            .iter()
            .find(|(_, p)| p[1] == DEBUG_GETSELF_RES)
            .map(|(_, p)| String::from_utf8_lossy(&p[2..]).into_owned())
            .unwrap();
        assert!(self_body.contains(&hex::encode(b_pub)), "{self_body}");
        assert!(self_body.contains("routing_entries"), "{self_body}");
        // getPeers names A's key (B's only link peer is A).
        let peers_body = router
            .proto_inbox
            .iter()
            .find(|(_, p)| p[1] == DEBUG_GETPEERS_RES)
            .map(|(_, p)| p[2..].to_vec())
            .unwrap();
        assert_eq!(peers_body.len(), 32);
        assert_eq!(&peers_body[..], &router.pubkey());
        server.abort();
    }

    #[test]
    fn packet_type_constants_match_go() {
        // yggdrasil-go/src/core/types.go: typeSessionTraffic = 1,
        // typeSessionProto = 2.
        assert_eq!(crate::session::PACKET_TYPE_TRAFFIC, 1);
        assert_eq!(crate::session::PACKET_TYPE_PROTO, 2);
        // Protocol dispatch bytes: nodeinfo req/res = 1/2, debug = 255.
        assert_eq!(
            (PROTO_NODEINFO_REQ, PROTO_NODEINFO_RES, PROTO_DEBUG),
            (1, 2, 255)
        );
        // Debug subtypes run 0..=6 in order.
        assert_eq!(
            (
                DEBUG_DUMMY,
                DEBUG_GETSELF_REQ,
                DEBUG_GETSELF_RES,
                DEBUG_GETPEERS_REQ,
                DEBUG_GETPEERS_RES,
                DEBUG_GETTREE_REQ,
                DEBUG_GETTREE_RES
            ),
            (0, 1, 2, 3, 4, 5, 6)
        );
    }

    #[test]
    fn nodeinfo_size_cap_matches_go() {
        let mut r = Router::new(SigningKey::from_bytes(&[9; 32]));
        assert!(r.set_nodeinfo(vec![b'x'; NODEINFO_MAX]).is_ok());
        assert!(r.set_nodeinfo(vec![b'x'; NODEINFO_MAX + 1]).is_err());
    }
}
