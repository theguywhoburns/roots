//! Inbound listeners: bind what the config's `Listen` list names, and hand each
//! handshaked link to the node as [`Cmd::Accept`].
//!
//! This is Go's listener startup plus one goroutine per listener
//! (`link.go:503-540`). The two halves stay separate on purpose: **binding** is
//! fatal at startup, a failed **handshake** is not. A caller that wants the node
//! running must call [`spawn_listeners`] before `Node::run`, because every link
//! accepted here reaches the node only through that sender — as a row in the
//! same table the configured dials use, named by the accepted socket's own
//! address.

use ed25519_dalek::SigningKey;
use roots::link::{accept as tcp_accept, listen as tcp_listen};
use roots::{AnyConn, CoreError, Error, LinkOptions, Scheme, parse_link_uri};
use tokio::sync::mpsc;

use crate::node::Cmd;

/// Bind every `Listen` URI and start its accept loop, returning the URI each
/// listener ended up serving (`tcp://127.0.0.1:9001` — the same shape as the
/// inbound rows its links produce). An error means the node cannot serve the
/// address it was told to serve, which stops Go's startup too (`core.go`
/// returns `errBind`), so the caller must treat this as fatal.
///
/// It takes the identity as two refs rather than a `&Client` because the
/// `Client` moves into the [`crate::node::Node`] that owns the sender these
/// loops report into.
pub async fn spawn_listeners(
    key: &SigningKey,
    opts: &LinkOptions,
    uris: &[String],
    tx: &mpsc::UnboundedSender<Cmd>,
) -> Result<Vec<String>, Error> {
    let mut served = Vec::new();
    for uri in uris {
        let (scheme, _) = parse_link_uri(uri)?;
        // One name per listener: Go prints it upper case in the log line and
        // lower case in a link URI (`link.go:504`, `link.go:518`), so say it
        // once and let the two helpers differ the way Go does.
        let name = scheme_name(scheme);
        // Owned, because each accept loop is a task that outlives this call.
        let key = key.clone();
        let opts = opts.clone();
        match scheme {
            Scheme::Tcp => {
                let listener = tcp_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started(name, &addr);
                served.push(format!("{name}://{addr}"));
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match tcp_accept(&listener, &key, &opts).await {
                            Ok(conn) => accept(&tx, name, AnyConn::new(conn)),
                            Err(e) => failed(name, &addr, &e),
                        }
                    }
                });
            }
            Scheme::Tls => {
                let (listener, acceptor) = roots::tls::tls_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started(name, &addr);
                served.push(format!("{name}://{addr}"));
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::tls::tls_accept(&listener, &acceptor, &key, &opts).await {
                            Ok(conn) => accept(&tx, name, AnyConn::new(conn)),
                            Err(e) => failed(name, &addr, &e),
                        }
                    }
                });
            }
            // `ws://` and `wss://` share a shape and differ only in whether the
            // TCP stream is wrapped in TLS first.
            Scheme::Ws => {
                let listener = roots::ws::ws_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started(name, &addr);
                served.push(format!("{name}://{addr}"));
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::ws::ws_accept(&listener, &key, &opts).await {
                            Ok(conn) => accept(&tx, name, AnyConn::new(conn)),
                            Err(e) => failed(name, &addr, &e),
                        }
                    }
                });
            }
            Scheme::Wss => {
                let (listener, acceptor) = roots::ws::wss_listen(uri).await?;
                let addr = listener.local_addr()?.to_string();
                started(name, &addr);
                served.push(format!("{name}://{addr}"));
                let tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        match roots::ws::wss_accept(&listener, &acceptor, &key, &opts).await {
                            Ok(conn) => accept(&tx, name, AnyConn::new(conn)),
                            Err(e) => failed(name, &addr, &e),
                        }
                    }
                });
            }
            Scheme::Quic => {
                let (endpoint, addr) = roots::quic::quic_listen(uri).await?;
                started(name, &addr.to_string());
                served.push(format!("{name}://{addr}"));
                let tx = tx.clone();
                let addr = addr.to_string();
                tokio::spawn(async move {
                    loop {
                        match roots::quic::quic_accept(&endpoint, &key, &opts).await {
                            Ok(conn) => accept(&tx, name, AnyConn::new(conn)),
                            // `quic_accept` puts a handshake timeout on the
                            // `accept()` await, so an idle QUIC listener times
                            // out regularly and says nothing when it does.
                            //
                            // `Error::Core(CoreError::Timeout)` rather than
                            // `Error::Timeout`: the latter is an associated
                            // *constant*, and a constant of a non-structural type
                            // is not a valid pattern. That spelling is the
                            // wrapper's intended form for matching, and it says
                            // visibly that this is the protocol half.
                            Err(Error::Core(CoreError::Timeout)) => {}
                            Err(e) => failed(name, &addr, &e),
                        }
                    }
                });
            }
        }
    }
    Ok(served)
}

/// Go's scheme spelling for one parsed URI (`strings.ToUpper(u.Scheme)` in the
/// log, `u.Scheme` in a link URI).
fn scheme_name(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Tcp => "tcp",
        Scheme::Tls => "tls",
        Scheme::Ws => "ws",
        Scheme::Wss => "wss",
        Scheme::Quic => "quic",
    }
}

fn started(scheme: &str, addr: &str) {
    // Go's `log.Infof("%s listener started on %s", strings.ToUpper(u.Scheme), addr)`
    // (`link.go:504`).
    eprintln!("{} listener started on {addr}", scheme.to_uppercase());
}

fn failed(scheme: &str, addr: &str, e: &Error) {
    eprintln!("{} listener on {addr}: {e}", scheme.to_uppercase());
}

fn accept(tx: &mpsc::UnboundedSender<Cmd>, scheme: &str, conn: AnyConn) {
    // An inbound link is named by the *accepted socket's* peer address, in the
    // listener's scheme: Go copies the listener URL and replaces its host
    // (`link.go:514-524`), and `urlForLinkInfo` has already blanked the query,
    // so a `?password=` never reaches the admin socket. A transport that could
    // not name its peer leaves the link served but unlisted, which is what a
    // link that never entered Go's `_links` map looks like.
    let uri = conn
        .remote_addr
        .as_deref()
        .map(|addr| format!("{scheme}://{addr}"));
    // Dropping the link here is Go's `defer conn.Close()`.
    let _ = tx.send(Cmd::Accept { conn, uri });
}
