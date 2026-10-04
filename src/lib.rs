//! `roots`: the library half of a Yggdrasil encrypted IPv6 mesh node,
//! interoperable with the Go implementation. Key/address derivation, the link
//! `meta` handshake, transports, framing, and the routing, pathfinding and
//! session state machines.
//!
//! This crate talks wires and owns state. It never prints, never opens a TUN,
//! never serves admin, and never builds a `Router` for a caller — that policy
//! lives in the `roots-client` package (`client/`).

pub mod bloom;
pub mod error;

/// The address module, now living in `roots-core`.
///
/// Kept as a `pub use` of the core module rather than deleted so that the 34
/// internal `crate::address::…` paths across this crate keep resolving **and so
/// that `roots::address::…` keeps working for downstream callers**. That is the
/// whole design of this slice: the module moved, the path did not.
///
/// A `pub use` of a module re-exports its public items, so `roots::address` and
/// `roots_core::address` are the *same* module — there is one `Address` type, not
/// two, and the constants (`KEY_LEN`, `SUBNET_LEN`) come from one place.
pub use roots_core::address;
pub mod driver;
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

// `address` and `error` moved to `roots-core` (no_std, no alloc) and are
// re-exported here, so **no call site in this crate or in `roots-client`
// changed**. That is the whole point of slice 1 of the separation: the boundary
// is real and the diff is zero at the use sites.
//
// `error` is re-exported rather than re-wrapped, which means `roots::Error` is
// `roots_core::Error` — one type, two paths — and that is deliberate. A wrapper
// enum with `Core(CoreError)` would have been the tidier-looking choice and the
// worse one: every `?` in every module below would need a `From` conversion, and
// a caller matching on errors would have to arm both halves. What `roots` adds
// on top is `Io(std::io::Error)`, and it does that by *extending* the core enum
// in the one place a crate can: a newtype that keeps the core variants
// reachable. See `error` below.
pub use error::Error;
pub use roots_core::address::{Address, Subnet, addr_for_key, subnet_for_key};
/// The `no_std` protocol-only error, for callers that need to match on it
/// without the wrapper's `Io` and `BadUri` arms.
///
/// `roots::Error` is a *superset* — it contains this — so a caller reaching for
/// `CoreError` is usually a caller that wants to name the protocol refusal
/// specifically. The one place that matters today is `match` patterns, where a
/// wrapper arm is `Error::Core(CoreError::Timeout)` rather than the
/// `Error::Timeout` construction shorthand.
pub use roots_core::error::Error as CoreError;

pub use frame::FrameType;
pub use handshake::Meta;
pub use link::{
    AnyConn, Link, LinkId, LinkOptions, LinkSet, PeerConn, Scheme, Tcp, Transport, complete_accept,
    complete_dial, dial_any, interface_index, parse_link_uri,
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
