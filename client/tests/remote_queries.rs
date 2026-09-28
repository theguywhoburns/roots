//! The four remote admin queries, and the `removePeer` decision.
//!
//! Two claims, both loopback, both about Go:
//!
//! 1. **A remote query goes out the way to that node, not the way to whichever
//!    link came up first.** Go answers these by handing the request to
//!    `PacketConn.WriteTo` (`core/proto.go:101`, `core/nodeinfo.go:114`), which
//!    routes through the pathfinder and forwards a hop when it has to. The
//!    first test builds a line A—B—C, where A has exactly one link and it goes
//!    to B, so anything A sends to C has to be forwarded to be answered at all.
//!    The second asks about a node nobody has met: the honest answer is Go's
//!    own timeout, and anything else would mean the request was delivered to
//!    whichever peer A happens to be linked to.
//!
//! 2. **`removePeer` takes the link down with the row.** Go's `links.remove`
//!    cancels the redial context *and* closes the connection
//!    (`core/link.go:433-438`), so the row leaves `getPeers`. Slice 5 kept ours
//!    open on the strength of the comment at `core/api.go:207-211`, which
//!    describes nothing that happens. This pins the corrected behaviour, and
//!    pins that removing the URI of an **inbound** row does not panic — Go's
//!    does, because an inbound link is built without a context and `remove`
//!    dereferences it (`link.go:536-543`, `:434`).

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::LinkOptions;
use roots_client::listen::spawn_listeners;
use roots_client::node::{Cmd, Node, PeerRow, RemoteQuery};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

const ANY: &str = "tcp://127.0.0.1:0";

/// Long `?maxbackoff=` so a removed or displaced row does not start another
/// round while the test reads the table. The query is blanked in the URI a row
/// reports, so this never appears in a `getPeers` answer.
fn slow(uri: &str) -> String {
    format!("{uri}?maxbackoff=600s")
}

/// One ordinary node: listeners plus the node task, built the way the client
/// builds one, so a test exercises the path an operator's node takes.
struct Peer {
    key: [u8; 32],
    served: Vec<String>,
    tx: mpsc::UnboundedSender<Cmd>,
    task: tokio::task::JoinHandle<Result<(), roots::Error>>,
}

impl Peer {
    async fn start(seed: u8, listen: &[&str]) -> Self {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let key = sk.verifying_key().to_bytes();
        let uris: Vec<String> = listen.iter().map(|u| u.to_string()).collect();
        let (mut node, tx) = Node::new(sk.clone());
        let served = spawn_listeners(&sk, &LinkOptions::default(), &uris, &tx)
            .await
            .expect("the listener binds");
        let task = tokio::spawn(async move { node.run().await });
        Self {
            key,
            served,
            tx,
            task,
        }
    }

    /// A node with no listener of its own, for the dialling side of a line.
    async fn client(seed: u8) -> Self {
        Self::start(seed, &[]).await
    }

    fn dial(&self, uri: &str) {
        self.tx
            .send(Cmd::Dial {
                uri: uri.to_string(),
                sintf: String::new(),
                persistent: true,
                respond: None,
            })
            .unwrap();
    }

    async fn report(&self) -> Vec<PeerRow> {
        let (wt, rr) = oneshot::channel();
        self.tx.send(Cmd::Report { respond: wt }).unwrap();
        rr.await.expect("the node answers").peers
    }

    async fn wait_rows<F: Fn(&[PeerRow]) -> bool>(
        &self,
        what: &str,
        budget: Duration,
        pred: F,
    ) -> Vec<PeerRow> {
        let end = Instant::now() + budget;
        loop {
            let rows = self.report().await;
            if pred(&rows) {
                return rows;
            }
            if Instant::now() >= end {
                panic!("timed out after {budget:?} waiting for {what}, saw {rows:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Ask a remote node, the way the admin socket does, and return the body its
    /// handler would wrap under the target's address.
    ///
    /// The socket's own framing is already pinned by `admin_loopback.rs`; what
    /// matters here is which link the request leaves by, and that is decided
    /// below the socket.
    async fn remote(&self, what: RemoteQuery, key: [u8; 32]) -> Result<Value, String> {
        let (wt, rr) = oneshot::channel();
        self.tx
            .send(Cmd::Remote {
                key,
                what,
                respond: wt,
            })
            .unwrap();
        let raw = rr.await.map_err(|_| "node did not answer".to_string())??;
        // The body the node hands back is the *unwrapped* answer: wrapping it
        // under the target's address is the handler's job (`proto.go:290-292`),
        // and `admin.rs` does that. Unwrapping here would take one level too
        // many and yield a string.
        serde_json::from_slice(&raw).map_err(|e| format!("{e}: {raw:?}"))
    }

    /// `removePeer`, the way the admin socket calls it.
    async fn remove(&self, uri: &str) -> Result<(), String> {
        let (wt, rr) = oneshot::channel();
        self.tx
            .send(Cmd::Drop {
                uri: uri.to_string(),
                sintf: String::new(),
                respond: Some(wt),
            })
            .unwrap();
        rr.await
            .map_err(|_| "node did not answer".to_string())?
            .map_err(|e| e.message())
    }

    async fn stop(self) {
        let _ = self.tx.send(Cmd::Quit);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

/// A—B—C in a line, with both legs up. A has exactly one link and it goes to B,
/// which is what makes "which link did the request leave by" observable.
async fn line() -> (Peer, Peer, Peer) {
    let b = Peer::start(0xB2, &[ANY]).await;
    let c = Peer::start(0xC3, &[ANY]).await;
    let a = Peer::client(0xA1).await;
    a.dial(&slow(&b.served[0]));
    b.dial(&slow(&c.served[0]));
    a.wait_rows("A is peered onto B", Duration::from_secs(20), |r| {
        r.iter().any(|row| row.up)
    })
    .await;
    b.wait_rows("B holds both legs", Duration::from_secs(20), |r| {
        r.len() == 2 && r.iter().all(|row| row.up)
    })
    .await;
    (a, b, c)
}

#[tokio::test]
async fn a_remote_query_reaches_a_node_two_hops_away() {
    let (a, b, c) = line().await;
    // Let the tree settle so the answer, if there is one, is a routing failure
    // rather than a race with convergence.
    tokio::time::sleep(Duration::from_secs(3)).await;
    match a.remote(RemoteQuery::SelfInfo, c.key).await {
        Ok(body) => {
            // The answer names the node that was asked. A first-link hop would
            // have gone to B, and B's own key is not what was asked for.
            let key = body.get("key").and_then(Value::as_str).unwrap_or_default();
            assert_eq!(
                key,
                hex::encode(c.key),
                "the answer comes from the node that was asked, not from the \
                 peer A happens to be linked to"
            );
        }
        Err(e) => assert_eq!(
            e, "timeout",
            "the only acceptable failure is Go's own timeout, got {e}"
        ),
    }
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

#[tokio::test]
async fn a_remote_query_to_an_unknown_node_times_out() {
    // A is peered to B and has never heard of the target. "Send it down whichever
    // link is first" would deliver it to B and answer as B. Go's `WriteTo` looks
    // the target up in the pathfinder, which has no route, so the request is
    // held and the handler's 6 s timer fires.
    let b = Peer::start(0xB2, &[ANY]).await;
    let a = Peer::client(0xA1).await;
    a.dial(&slow(&b.served[0]));
    a.wait_rows("A is peered onto B", Duration::from_secs(20), |r| {
        r.iter().any(|row| row.up)
    })
    .await;

    // A real key, because the session layer rejects a key that is not a valid
    // ed25519 point before the question is even asked — and we want to be
    // testing the routing, not the curve.
    let stranger = SigningKey::from_bytes(&[0x5Au8; 32])
        .verifying_key()
        .to_bytes();
    match a.remote(RemoteQuery::SelfInfo, stranger).await {
        Err(e) => assert_eq!(e, "timeout", "a node we cannot reach times out"),
        Ok(body) => panic!(
            "asked a node nobody has met and got an answer: {body} — the \
             request must not have been delivered to the peer we are linked to"
        ),
    }
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn remove_peer_closes_the_link_it_named() {
    let a = Peer::start(0xA1, &[ANY]).await;
    let b = Peer::start(0xB2, &[ANY]).await;
    let uri = slow(&b.served[0]);
    a.dial(&uri);
    a.wait_rows("the dial is up", Duration::from_secs(20), |r| {
        r.len() == 1 && r[0].up
    })
    .await;

    a.remove(&uri).await.expect("removePeer succeeds");

    // Go's row disappears with the link (`link.go:433-438`), so ours must too.
    a.wait_rows("the row is gone", Duration::from_secs(10), |r| r.is_empty())
        .await;
    // ...and the socket really is closed, which the row set alone does not show:
    // forgetting the row is enough to make `getPeers` quiet, so the far end
    // noticing the link die is what proves the connection went.
    //
    // B's row for A is an *inbound* one — A dialled B — so it is deleted with
    // the link, which is Go's own rule (`defer delete(l._links, info)`,
    // `link.go:567-571`). A configured row would instead stay and read down, as
    // `a_dead_dial_row_stays_and_reports_down` in peer_rows.rs pins.
    b.wait_rows("B sees the link die", Duration::from_secs(15), |r| {
        r.iter().all(|row| row.key != Some(a.key))
    })
    .await;
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn remove_peer_on_an_inbound_row_does_not_panic() {
    // Go panics here: an inbound link is built without a context
    // (`core/link.go:536-543`) and `remove` calls `state.cancel()` and then
    // dereferences it (`link.go:433-438`), so `yggdrasilctl` sees EOF and the
    // node dies. Reproducing that faithfully is not an option, so this pins the
    // other half: we answer, and the row goes.
    let a = Peer::start(0xA1, &[ANY]).await;
    let b = Peer::client(0xB2).await;
    b.dial(&a.served[0]);
    let rows = a
        .wait_rows("A holds an inbound row", Duration::from_secs(20), |r| {
            r.len() == 1 && r[0].inbound
        })
        .await;
    // An inbound row is named by the accepted socket, not by the listener, so
    // `removePeer` is called with that name — exactly the case that panics Go.
    let inbound_uri = rows[0].uri.clone();
    a.remove(&inbound_uri)
        .await
        .expect("removing an inbound row is allowed and the node keeps running");
    a.wait_rows("the inbound row is gone", Duration::from_secs(10), |r| {
        r.is_empty()
    })
    .await;
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn removing_one_row_closes_only_that_rows_link() {
    // Two peers, one removed: the survivor must keep carrying traffic, or
    // `removePeer` has become "disconnect everything".
    let a = Peer::start(0xA1, &[ANY, ANY]).await;
    let b = Peer::start(0xB2, &[ANY]).await;
    let c = Peer::start(0xC3, &[ANY]).await;
    a.dial(&slow(&b.served[0]));
    a.dial(&slow(&c.served[0]));
    a.wait_rows("both peers are up", Duration::from_secs(20), |r| {
        r.len() == 2 && r.iter().all(|row| row.up)
    })
    .await;
    let doomed = a
        .report()
        .await
        .into_iter()
        .find(|r| r.key == Some(b.key))
        .map(|r| r.uri)
        .expect("a row for B");

    a.remove(&doomed).await.expect("removePeer succeeds");

    let rows = a
        .wait_rows("one row left, still up", Duration::from_secs(10), |r| {
            r.len() == 1 && r[0].up
        })
        .await;
    assert_eq!(rows[0].key, Some(c.key), "the survivor is the other peer");
    a.stop().await;
    b.stop().await;
    c.stop().await;
}
