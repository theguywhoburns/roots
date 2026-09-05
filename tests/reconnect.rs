//! Reconnect test (loopback, no internet): the server drops the first link
//! mid-run; the client must redial with backoff, re-establish the session,
//! and still deliver its queued payload on the second link.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use roots::{Client, Router};

#[tokio::test]
async fn reconnect_delivers_after_drop() {
    let c_sk = SigningKey::from_bytes(&[0xC1; 32]);
    let s_sk = SigningKey::from_bytes(&[0xC2; 32]);
    let c_pub = c_sk.verifying_key().to_bytes();
    let s_pub = s_sk.verifying_key().to_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let uri = format!("tcp://{addr}?maxbackoff=5s");

    // Server: serve a short first link (forces a client-side drop), then a
    // long second link, and report what arrived on each.
    let server = tokio::spawn(async move {
        let mut inboxes = Vec::new();
        for hold in [Duration::from_secs(1), Duration::from_secs(10)] {
            let mut conn = Client::new(s_sk.clone())
                .accept(&listener)
                .await
                .expect("accept");
            let peer = conn.remote_key;
            assert_eq!(peer, c_pub);
            let mut router = Router::new(s_sk.clone());
            router.register(&mut conn, peer).await.expect("register");
            let mut no_out = Vec::new();
            let _ = router.serve(&mut conn, peer, Some(hold), &mut no_out).await;
            inboxes.push(router.inbox);
        }
        inboxes
    });

    let client = Client::new(c_sk);
    let mut outgoing = vec![(s_pub, b"survives-drop".to_vec())];
    client
        .run_peer(&uri, &mut outgoing, Some(2))
        .await
        .expect("two served links");
    let inboxes = server.await.unwrap();
    assert_eq!(inboxes.len(), 2);
    let got_second = inboxes[1]
        .iter()
        .any(|(from, msg)| *from == c_pub && msg == b"survives-drop");
    assert!(got_second, "payload delivered after reconnect");
}
