//! The `getPeers` row set, from the node's own view of its links.
//!
//! Go builds that set by iterating `links._links` and joining each row to the
//! router by `net.Conn` identity (`core/api.go:71-103`), which has three
//! consequences this file pins:
//! 1. a link we *accept* is a row of its own, named by the accepted socket's
//!    peer address (`link.go:514-524`) — not a detail of whoever dialled us;
//! 2. an inbound row is deleted when its link dies (Go's `defer delete`,
//!    `link.go:567-571`) while a configured row stays behind and reports
//!    `up: false`;
//! 3. with both directions up to one node, a row reports the direction and the
//!    counters of *its own* link, never the other one's.
//!
//! All loopback, and the last one states where we still differ from Go: the
//! library keeps one link slot per node key, so the displaced direction reads as
//! down here and as up in Go.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::LinkOptions;
use roots_client::links::link_id;
use roots_client::listen::spawn_listeners;
use roots_client::node::{Cmd, Node, PeerRow};
use tokio::sync::{mpsc, oneshot};

/// An ephemeral port, which is what Go's own tests use for a listener nobody
/// has to find again by number.
const ANY: &str = "tcp://127.0.0.1:0";

/// A node task, its listeners, and the identity the test knows it by.
struct Peer {
    key: [u8; 32],
    /// The URIs its listeners actually served, with the bound port filled in.
    served: Vec<String>,
    tx: mpsc::UnboundedSender<Cmd>,
    task: tokio::task::JoinHandle<Result<(), roots::Error>>,
}

impl Peer {
    /// Bind the listeners first, so `served` is real before the loop starts, then
    /// run the node. Every link these listeners accept reaches the node as
    /// [`Cmd::Accept`] — the same way the admin socket reaches it.
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

    fn dial(&self, uri: &str) {
        self.tx
            .send(Cmd::Dial {
                uri: uri.to_string(),
                sintf: String::new(),
                persistent: true,
                respond: None,
            })
            .expect("the node task is alive");
    }

    async fn report(&self) -> Vec<PeerRow> {
        let (rtx, rrx) = oneshot::channel();
        self.tx.send(Cmd::Report { respond: rtx }).unwrap();
        tokio::time::timeout(Duration::from_secs(5), rrx)
            .await
            .expect("the node answers a report in about one tick")
            .expect("the node task is alive")
            .peers
    }

    /// Ask for the row set until it looks like `want`, and hand back that set.
    /// The rows live in the node task, so there is no cheaper way to watch them.
    async fn wait_rows<F: Fn(&[PeerRow]) -> bool>(
        &self,
        what: &str,
        budget: Duration,
        want: F,
    ) -> Vec<PeerRow> {
        let end = Instant::now() + budget;
        loop {
            let rows = self.report().await;
            if want(&rows) {
                return rows;
            }
            assert!(
                Instant::now() < end,
                "timed out after {budget:?} waiting for {what}: {rows:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn stop(self) {
        let _ = self.tx.send(Cmd::Quit);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("the loop exits on Quit")
            .expect("no panic in the node task")
            .expect("the node loop ends cleanly");
    }
}

/// The claim Slice 8 could not make before: an accepted link is listed at all,
/// under the address it came from, and it leaves the list when it dies.
#[tokio::test]
async fn an_accepted_link_gets_its_own_row() {
    let b = Peer::start(0xB0, &[ANY]).await;
    let a = Peer::start(0xA0, &[]).await;
    let served = b.served[0].clone();
    // A `?priority=` on the dial URI: it must reach the row as the peer's
    // priority, and must not reach it as part of the URI.
    a.dial(&format!("{served}?priority=5"));

    let rows = a
        .wait_rows(
            "the dial side lists its peer",
            Duration::from_secs(10),
            |r| r.len() == 1 && r[0].up,
        )
        .await;
    let row = &rows[0];
    assert_eq!(row.uri, served, "Go echoes the link URI, query blanked");
    assert_eq!(row.sintf, "");
    assert!(!row.inbound, "we dialled this one");
    assert_eq!(row.key, Some(b.key));
    assert_eq!(row.priority, 5, "the option the operator set is the row's");
    assert!(row.port >= 1, "every registered peer gets a 1-based port");
    assert!(row.cost >= 1, "Go floors the cost at one millisecond");
    assert!(
        row.rx_bytes > 0 && row.tx_bytes > 0,
        "the handshake and the tree chatter are counted"
    );
    assert!(
        row.rx_rate <= row.rx_bytes && row.tx_rate <= row.tx_bytes,
        "a rate is the bytes since the last tick, so it can never exceed the total"
    );
    assert_eq!(row.last_error, None);

    let rows = b
        .wait_rows(
            "the listener side lists its own row",
            Duration::from_secs(10),
            |r| r.len() == 1 && r[0].up,
        )
        .await;
    assert_eq!(
        rows.len(),
        1,
        "an accepted link is a row, not a detail of the dialer's"
    );
    let row = &rows[0];
    assert!(row.inbound, "the peer dialled us");
    assert_eq!(row.key, Some(a.key));
    assert!(
        row.uri.starts_with("tcp://127.0.0.1:") && row.uri != served,
        "Go names an inbound link by the accepted socket's peer address, so it carries the peer's port: {row:?}"
    );
    assert_ne!(row.uri, served, "the row is not the listener's own address");

    // The dialer's task ends, its socket closes, and the listener's row is gone
    // with it. A configured row would still be here, reported down.
    a.stop().await;
    b.wait_rows(
        "the inbound row is deleted with its link",
        Duration::from_secs(10),
        |r| r.is_empty(),
    )
    .await;
    b.stop().await;
}

/// A configured row outlives its link: it stays listed, reports down, and picks
/// up the error of the redial that failed next.
#[tokio::test]
async fn a_dead_dial_row_stays_and_reports_down() {
    // A far side with no node behind it, so the link can be killed at a moment
    // of the test's choosing and the redial afterwards cannot possibly succeed.
    let listener = roots::link::listen(ANY).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let far = SigningKey::from_bytes(&[0xF0; 32]);
    let far_key = far.verifying_key().to_bytes();
    let opts = LinkOptions::default();
    let (ctx, crx) = oneshot::channel();
    tokio::spawn(async move {
        let conn = roots::link::accept(&listener, &far, &opts)
            .await
            .expect("the far side finishes the handshake");
        drop(listener);
        let _ = ctx.send(conn);
    });

    let c = Peer::start(0xC0, &[]).await;
    let uri = format!("tcp://{addr}");
    c.dial(&uri);
    let rows = c
        .wait_rows("the dial came up", Duration::from_secs(10), |r| {
            r.len() == 1 && r[0].up
        })
        .await;
    assert_eq!(rows[0].key, Some(far_key));

    drop(crx.await.expect("the far side has the link"));
    let rows = c
        .wait_rows(
            "the dead link is reported down",
            Duration::from_secs(10),
            |r| r.len() == 1 && !r[0].up,
        )
        .await;
    assert_eq!(rows.len(), 1, "a persistent row is never forgotten");
    assert_eq!(rows[0].uri, uri);
    assert!(!rows[0].inbound);
    assert_eq!(
        rows[0].key, None,
        "with no link there is no node key to report, and no router half to join"
    );
    assert_eq!(
        (
            rows[0].rx_bytes,
            rows[0].tx_bytes,
            rows[0].port,
            rows[0].cost
        ),
        (0, 0, 0, 0),
        "a down row counts nothing"
    );

    // The first redial is due after one backoff step, and the port is gone: that
    // failure is what `getPeers` prints, with the moment it happened.
    let rows = c
        .wait_rows(
            "the failed redial is reported with its error",
            Duration::from_secs(10),
            |r| r.len() == 1 && r[0].last_error.is_some() && r[0].err_at.is_some(),
        )
        .await;
    assert_eq!(rows.len(), 1, "and it is still the same row");
    c.stop().await;
}

/// Two directions to one node key are two rows, and each reports its own link.
/// Pre-Slice 8 the listener's direction had no row, so the single configured row
/// printed the *accepted* link's `inbound` against the dial's URI.
#[tokio::test]
async fn two_directions_to_one_peer_get_two_rows() {
    let a = Peer::start(0xA1, &[ANY]).await;
    let b = Peer::start(0xB2, &[ANY]).await;
    // `?maxbackoff=` only keeps a displaced row from starting another round while
    // the test reads it; the query is blanked in the URI the row reports.
    let slow = |uri: &str| format!("{uri}?maxbackoff=600s");
    a.dial(&slow(&b.served[0]));
    let first = a
        .wait_rows("the first direction is up", Duration::from_secs(10), |r| {
            r.len() == 1 && r[0].up
        })
        .await;
    assert!(
        !first[0].inbound,
        "the only link so far is the one we dialled, so its row is outbound — a \
         row that borrows its direction from the link set rather than from its own \
         kind is the bug Slice 7 could not fix"
    );
    b.dial(&slow(&a.served[0]));

    let rows = a
        .wait_rows(
            "the second direction gets its own row",
            Duration::from_secs(10),
            |r| r.len() == 2,
        )
        .await;
    let up: Vec<&PeerRow> = rows.iter().filter(|r| r.up).collect();
    assert_eq!(
        up.len(),
        1,
        "one node key is one slot in the link set, so the displaced direction reads down — where we still differ from Go"
    );
    assert!(
        up[0].inbound,
        "the live row is the link the peer dialled us on"
    );
    assert_ne!(up[0].uri, a.served[0], "and it names the peer, not us");
    let down = rows.iter().find(|r| !r.up).expect("two rows, one down");
    assert_eq!(
        down.uri,
        link_id(&slow(&b.served[0])),
        "the dial row keeps its own URI"
    );
    assert!(
        !down.inbound,
        "a dial row must not borrow the accepted link's direction"
    );
    assert_eq!(down.key, None);
    assert_eq!(
        down.rx_bytes, 0,
        "its link is not in the set, so nothing is counted"
    );

    a.stop().await;
    b.stop().await;
}
