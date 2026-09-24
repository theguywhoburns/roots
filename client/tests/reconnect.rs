//! Reconnect test (loopback, no internet): the server drops the first link
//! mid-run; the node must redial with backoff and deliver a payload queued
//! after the drop on the second link. Driven through `Node` + `Cmd`, which is
//! the only redial path the client has since Slice 5.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use roots::{AnyConn, Client, LinkSet, Router};
use roots_client::node::{Cmd, Node};

#[tokio::test]
async fn reconnect_delivers_after_drop() {
    let c_sk = SigningKey::from_bytes(&[0xC1; 32]);
    let s_sk = SigningKey::from_bytes(&[0xC2; 32]);
    let c_pub = c_sk.verifying_key().to_bytes();
    let s_pub = s_sk.verifying_key().to_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let uri = format!("tcp://{addr}?maxbackoff=5s");

    // Server: a short first link (the drop), then a long second one. `served`
    // tells the test when the first is over, so the payload is only queued while
    // no link exists at all.
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let server_sk = s_sk.clone();
    let server = tokio::spawn(async move {
        let mut inboxes = Vec::new();
        for hold in [Duration::from_secs(1), Duration::from_secs(10)] {
            let mut conn = Client::new(server_sk.clone())
                .accept(&listener)
                .await
                .expect("accept");
            let peer = conn.remote_key;
            assert_eq!(peer, c_pub);
            let mut router = Router::new(server_sk.clone());
            router.register(&mut conn, peer).await.expect("register");
            let mut links = LinkSet::single(AnyConn::new(conn));
            let mut no_out = Vec::new();
            let _ = router.serve(&mut links, Some(hold), &mut no_out).await;
            counter.fetch_add(1, Ordering::SeqCst);
            inboxes.push(router.inbox);
        }
        inboxes
    });

    let (mut node, tx) = Node::new(c_sk);
    let handle = tokio::spawn(async move { node.run().await });
    tx.send(Cmd::Dial {
        uri,
        sintf: String::new(),
        persistent: true,
    })
    .unwrap();

    let end = std::time::Instant::now() + Duration::from_secs(15);
    while served.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        served.load(Ordering::SeqCst) > 0,
        "the first link came up and was dropped"
    );
    tx.send(Cmd::Send {
        dest: s_pub,
        bytes: b"survives-drop".to_vec(),
    })
    .unwrap();

    let inboxes = tokio::time::timeout(Duration::from_secs(25), server)
        .await
        .expect("the server finishes both links")
        .expect("no panic in the server task");
    assert_eq!(inboxes.len(), 2);
    let got_second = inboxes[1]
        .iter()
        .any(|(from, msg)| *from == c_pub && msg == b"survives-drop");
    assert!(got_second, "payload delivered after reconnect");

    tx.send(Cmd::Quit).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the node loop exits on Quit")
        .expect("no panic in the node task")
        .expect("the node loop ends cleanly");
}
