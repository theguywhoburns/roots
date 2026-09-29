//! `roots`: the library half of a Yggdrasil encrypted IPv6 mesh node,
//! interoperable with the Go implementation. Key/address derivation, the link
//! `meta` handshake, transports, framing, and the routing, pathfinding and
//! session state machines.
//!
//! This crate talks wires and owns state. It never prints, never opens a TUN,
//! never serves admin, and never builds a `Router` for a caller — that policy
//! lives in the `roots-client` package (`client/`).

pub mod address;
pub mod bloom;
pub mod driver;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod link;
pub mod multicast;
pub mod pathfind;
pub mod peer;
pub mod proto;
pub mod quic;
pub mod router;
pub mod session;
pub mod supervisor;
pub mod tls;
pub mod traffic;
pub mod traits;
pub mod tree;
pub mod views;
pub mod ws;

pub use address::{Address, Subnet, addr_for_key, subnet_for_key};
pub use error::Error;
pub use frame::FrameType;
pub use handshake::Meta;
pub use link::{
    AnyConn, Link, LinkId, LinkOptions, LinkSet, PeerConn, RunStats, Scheme, Tcp, Transport,
    complete_accept, complete_dial, dial_any, interface_index, parse_link_uri,
};
pub use peer::{PeerKind, feat};
pub use quic::Quic;
pub use router::Router;
pub use supervisor::{SupervisedPeer, backoff_cap};
pub use tls::Tls;
pub use traits::Snapshot;
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

    /// Connect with any scheme, type-erased to [`AnyConn`]. Replaces the
    /// per-callsite `if starts_with` chains with one [`Scheme`] match
    /// (see `link::dial_any`).
    pub async fn connect_any(&self, uri: &str) -> Result<AnyConn, Error> {
        link::dial_any(uri, &self.key, &self.opts).await
    }

    /// Connect to a `quic://` peer URI and complete the handshake.
    pub async fn connect_quic(&self, uri: &str) -> Result<PeerConn<crate::quic::Quic>, Error> {
        crate::quic::quic_dial(uri, &self.key, &self.opts).await
    }

    /// Bind a `tcp://` listener for inbound peers.
    pub async fn listen(&self, uri: &str) -> Result<tokio::net::TcpListener, Error> {
        link::listen(uri).await
    }

    /// Accept one inbound peer on a listener from [`Client::listen`].
    pub async fn accept(&self, listener: &tokio::net::TcpListener) -> Result<PeerConn<Tcp>, Error> {
        link::accept(listener, &self.key, &self.opts).await
    }
}
