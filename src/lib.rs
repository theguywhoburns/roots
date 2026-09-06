//! `roots`: native Rust client for the Yggdrasil encrypted IPv6 mesh.
//!
//! Slice 1: key/address derivation, link `meta` handshake, and TCP peering
//! against existing (Go) nodes. Transports are compile-time [`link`]
//! primitives behind the [`link::Transport`] trait.

pub mod address;
pub mod bloom;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod link;
pub mod pathfind;
pub mod proto;
pub mod router;
pub mod session;
pub mod tls;
pub mod traffic;
pub mod tree;
pub mod ws;

pub use address::{Address, Subnet, addr_for_key, subnet_for_key};
pub use error::Error;
pub use frame::FrameType;
pub use handshake::Meta;
pub use link::{
    AnyConn, Link, LinkOptions, LinkSet, PeerConn, RunStats, Scheme, Tcp, Transport, parse_link_uri,
};
pub use router::Router;
pub use tls::Tls;
pub use ws::{Ws, Wss};

use ed25519_dalek::SigningKey;

/// A mesh node identity: an ed25519 keypair plus link options.
pub struct Client {
    pub key: SigningKey,
    pub opts: LinkOptions,
}

impl Client {
    pub fn new(key: SigningKey) -> Self {
        Self {
            key,
            opts: LinkOptions::default(),
        }
    }

    pub fn with_options(key: SigningKey, opts: LinkOptions) -> Self {
        Self { key, opts }
    }

    pub fn address(&self) -> Address {
        addr_for_key(&self.key.verifying_key().to_bytes())
    }

    pub fn subnet(&self) -> Subnet {
        subnet_for_key(&self.key.verifying_key().to_bytes())
    }

    /// Connect to a `tcp://` peer URI and complete the handshake.
    pub async fn connect(&self, uri: &str) -> Result<PeerConn<Tcp>, Error> {
        link::dial(uri, &self.key, &self.opts).await
    }

    /// Connect to a `tls://` peer URI and complete the handshake.
    pub async fn connect_tls(&self, uri: &str) -> Result<PeerConn<crate::tls::Tls>, Error> {
        crate::tls::tls_dial(uri, &self.key, &self.opts).await
    }

    /// Connect to a `ws://` peer URI and complete the handshake.
    pub async fn connect_ws(&self, uri: &str) -> Result<PeerConn<crate::ws::Ws>, Error> {
        crate::ws::ws_dial(uri, &self.key, &self.opts).await
    }

    /// Connect to a `wss://` peer URI and complete the handshake.
    pub async fn connect_wss(&self, uri: &str) -> Result<PeerConn<crate::ws::Wss>, Error> {
        crate::ws::wss_dial(uri, &self.key, &self.opts).await
    }

    /// Bind a `tcp://` listener for inbound peers.
    pub async fn listen(&self, uri: &str) -> Result<tokio::net::TcpListener, Error> {
        link::listen(uri).await
    }

    /// Accept one inbound peer on a listener from [`Client::listen`].
    pub async fn accept(&self, listener: &tokio::net::TcpListener) -> Result<PeerConn<Tcp>, Error> {
        link::accept(listener, &self.key, &self.opts).await
    }

    /// Serve one peer URI with reconnects (Go `links.add` loop): dial,
    /// serve until the link drops, wait `?maxbackoff=`-capped backoff
    /// (`1s << failures`, 2s after the first failure), repeat. Router state
    /// (tree, paths, sessions) persists across links, so traffic self-heals.
    /// Returns after `max_serves` completed links (`None` = forever).
    pub async fn run_peer(
        &self,
        uri: &str,
        outgoing: &mut Vec<([u8; 32], Vec<u8>)>,
        max_serves: Option<u64>,
    ) -> Result<(), Error> {
        let (scheme, peer) = link::parse_link_uri(uri)?;
        let max_backoff = peer.max_backoff.unwrap_or(link::DEFAULT_MAX_BACKOFF);
        let mut router = Router::new(self.key.clone());
        match scheme {
            Scheme::Tcp => {
                drive(&mut router, max_backoff, outgoing, max_serves, || {
                    link::dial(uri, &self.key, &self.opts)
                })
                .await
            }
            Scheme::Tls => {
                drive(&mut router, max_backoff, outgoing, max_serves, || {
                    crate::tls::tls_dial(uri, &self.key, &self.opts)
                })
                .await
            }
            Scheme::Ws => {
                drive(&mut router, max_backoff, outgoing, max_serves, || {
                    crate::ws::ws_dial(uri, &self.key, &self.opts)
                })
                .await
            }
            Scheme::Wss => {
                drive(&mut router, max_backoff, outgoing, max_serves, || {
                    crate::ws::wss_dial(uri, &self.key, &self.opts)
                })
                .await
            }
        }
    }
}

/// Reconnect driver shared by all transports.
async fn drive<T, F, Fut>(
    router: &mut Router,
    max_backoff: std::time::Duration,
    outgoing: &mut Vec<([u8; 32], Vec<u8>)>,
    max_serves: Option<u64>,
    mut dial: F,
) -> Result<(), Error>
where
    T: Transport,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<PeerConn<T>, Error>>,
{
    let mut failures: u32 = 0;
    let mut served: u64 = 0;
    loop {
        if let Ok(mut conn) = dial().await {
            failures = 0; // handshake completed inside dial
            let peer = conn.remote_key;
            if router.register(&mut conn, peer).await.is_ok() {
                let _ = router.serve(&mut conn, peer, None, outgoing).await;
                served += 1;
                if max_serves.is_some_and(|m| served >= m) {
                    return Ok(());
                }
            }
        }
        failures = failures.saturating_add(1).min(32);
        tokio::time::sleep(link::backoff_delay(failures, max_backoff)).await;
    }
}
