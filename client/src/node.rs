//! The node loop: serve one peer URI with reconnects until it stops being
//! worth dialling. Moved out of `roots::Client`, which must stay a state
//! machine rather than a policy owner.

use roots::link::{DEFAULT_MAX_BACKOFF, parse_link_uri};
use roots::{Client, LinkSet, Router};

/// Go's `links.add` loop: dial, serve until the link drops, wait
/// `?maxbackoff=`-capped backoff (`1s << failures`, 2s after the first
/// failure), repeat. Router state (tree, paths, sessions) persists across
/// links, so traffic self-heals. Returns after `max_serves` completed links
/// (`None` = forever).
pub async fn run_peer(
    client: &Client,
    uri: &str,
    outgoing: &mut Vec<([u8; 32], Vec<u8>)>,
    max_serves: Option<u64>,
) -> Result<(), roots::Error> {
    let (_, peer) = parse_link_uri(uri)?;
    let max_backoff = peer.max_backoff.unwrap_or(DEFAULT_MAX_BACKOFF);
    let mut router = Router::new(client.key.clone());
    let mut supervised = roots::supervisor::SupervisedPeer::new(uri.to_string());
    let mut served: u64 = 0;
    loop {
        match client.connect_any(uri).await {
            Ok(mut conn) => {
                supervised.record_success();
                let peer_key = conn.remote_key;
                if router.register(&mut conn, peer_key).await.is_ok() {
                    let mut links = LinkSet::single(conn);
                    let _ = router.serve(&mut links, None, outgoing).await;
                    served += 1;
                    if max_serves.is_some_and(|m| served >= m) {
                        return Ok(());
                    }
                }
            }
            Err(_) => {
                supervised.record_failure(max_backoff);
            }
        }
        let wait = supervised
            .next_retry
            .saturating_duration_since(std::time::Instant::now());
        tokio::time::sleep(wait).await;
    }
}
