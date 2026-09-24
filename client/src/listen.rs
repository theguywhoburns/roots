//! Inbound listeners: bind what the config's `Listen` list names, and hand each
//! handshaked link to the node as [`Cmd::Accept`].
//!
//! This is Go's `StartupListeners` plus one goroutine per listener
//! (`link.go:503-540`). The two halves stay separate on purpose: **binding** is
//! fatal at startup, a failed **handshake** is not. A caller that wants the node
//! running must call [`spawn_listeners`] before `Node::run`, because every link
//! accepted here belongs to a listener, not to the peer list, and is only ever
//! visible through the node task.

use ed25519_dalek::SigningKey;
use roots::link::{accept as tcp_accept, listen as tcp_listen};
use roots::{AnyConn, Error, LinkOptions, Scheme, parse_link_uri};
use tokio::sync::mpsc;

use crate::node::Cmd;

/// Bind every `Listen` URI and start its accept loop. An error means the node
/// cannot serve the address it was told to serve, which stops Go's startup too
/// (`core.go` returns `errBind`), so the caller must treat this as fatal.
///
/// It takes the identity as two refs rather than a `&Client` because the
/// `Client` moves into the [`crate::node::Node`] that owns the sender these
/// loops report into.
pub async fn spawn_listeners(
    key: &SigningKey,
    opts: &LinkOptions,
    uris: &[String],
    tx: &mpsc::UnboundedSender<Cmd>,
) -> Result<(), Error> {
    for uri in uris {
        let (scheme, _) = parse_link_uri(uri)?;
        // Owned, because each accept loop is a task that outlives this call.
        let key = key.clone();
        let opts = opts.clone();
        match scheme {
            Scheme::Tcp => {
                let listener = tcp_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started("TCP", &addr);
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match tcp_accept(&listener, &key, &opts).await {
                            Ok(conn) => accept(&tx, AnyConn::new(conn)),
                            Err(e) => failed("TCP", &addr, &e),
                        }
                    }
                });
            }
            Scheme::Tls => {
                let (listener, acceptor) = roots::tls::tls_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started("TLS", &addr);
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::tls::tls_accept(&listener, &acceptor, &key, &opts).await {
                            Ok(conn) => accept(&tx, AnyConn::new(conn)),
                            Err(e) => failed("TLS", &addr, &e),
                        }
                    }
                });
            }
            // `ws://` and `wss://` share a shape and differ only in whether the
            // TCP stream is wrapped in TLS first.
            Scheme::Ws => {
                let listener = roots::ws::ws_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started("WS", &addr);
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::ws::ws_accept(&listener, &key, &opts).await {
                            Ok(conn) => accept(&tx, AnyConn::new(conn)),
                            Err(e) => failed("WS", &addr, &e),
                        }
                    }
                });
            }
            Scheme::Wss => {
                let (listener, acceptor) = roots::ws::wss_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started("WSS", &addr);
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::ws::wss_accept(&listener, &acceptor, &key, &opts).await {
                            Ok(conn) => accept(&tx, AnyConn::new(conn)),
                            Err(e) => failed("WSS", &addr, &e),
                        }
                    }
                });
            }
            Scheme::Quic => {
                let (endpoint, addr) = roots::quic::quic_listen(uri).await?;
                started("QUIC", &addr.to_string());
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::quic::quic_accept(&endpoint, &key, &opts).await {
                            Ok(conn) => accept(&tx, AnyConn::new(conn)),
                            // `quic_accept` puts a handshake timeout on the
                            // `accept()` await, so an idle QUIC listener times
                            // out regularly and says nothing when it does.
                            Err(Error::Timeout) => {}
                            Err(e) => failed("QUIC", &addr.to_string(), &e),
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

fn started(scheme: &str, addr: &str) {
    // Go's `log.Infof("%s listener started on %s", strings.ToUpper(u.Scheme), addr)`
    // (`link.go:504`).
    eprintln!("{scheme} listener started on {addr}");
}

fn failed(scheme: &str, addr: &str, e: &Error) {
    eprintln!("{scheme} listener on {addr}: {e}");
}

fn accept(tx: &mpsc::UnboundedSender<Cmd>, conn: AnyConn) {
    // Dropping the link here is Go's `defer conn.Close()`.
    let _ = tx.send(Cmd::Accept { conn });
}
