//! WebSocket link transport (`ws://`). Mirrors Go `src/core/link_ws.go`:
//! plain WS over TCP speaking the **`ygg-ws` subprotocol** (the Go server
//! closes anything else with a policy violation), binary messages as a
//! byte stream (Go wraps the conn in `websocket.NetConn(...,
//! MessageBinary)` — message boundaries carry no meaning, both sides
//! stream bytes).
//!
//! Framing: each `flush` emits the buffered bytes as ONE binary message;
//! inbound messages append to a read buffer. The `meta` handshake and
//! ironwood frames ride on top unchanged via the [`Transport`] trait.
//!
//! Known deviation: Go also answers `GET /health` with `200 OK`; we only
//! speak WebSocket on this port (a plain HTTP GET fails the upgrade).

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async, client_async};

use crate::error::Error;
use crate::link::{DIAL_TIMEOUT, LinkOptions, PeerConn, Scheme, Transport, parse_link_uri};

/// Required WebSocket subprotocol (Go `link_ws.go` accept path + dial).
pub const WS_SUBPROTOCOL: &str = "ygg-ws";

/// Byte stream over a WebSocket: outbound bytes buffer until `flush`,
/// which emits one binary message; inbound binary messages append to a
/// read buffer. Generic over the inner stream so `wss://` can layer TLS
/// underneath later.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    rx: VecDeque<u8>,
    tx: Vec<u8>,
    closed: bool,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            rx: VecDeque::new(),
            tx: Vec::new(),
            closed: false,
        }
    }

    /// Pull the next inbound message into the read buffer. Non-binary
    /// messages never carry link bytes (Go only sends binary; pings are
    /// answered inside tungstenite), so they are skipped.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                self.rx.extend(data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(Error::Io(std::io::Error::other(e.to_string()))))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.rx.is_empty() {
                let n = buf.remaining().min(self.rx.len());
                let mut tmp = vec![0u8; n];
                for (i, slot) in tmp.iter_mut().enumerate() {
                    *slot = self.rx[i];
                }
                buf.put_slice(&tmp);
                self.as_mut().rx.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            match self.as_mut().poll_fill(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.tx.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let map_err =
            |e: tokio_tungstenite::tungstenite::Error| std::io::Error::other(e.to_string());
        if !self.tx.is_empty() {
            let data = std::mem::take(&mut self.tx);
            let mut sink = Pin::new(&mut self.inner);
            match sink.as_mut().poll_ready(cx).map_err(map_err)? {
                Poll::Ready(()) => {}
                Poll::Pending => {
                    self.tx = data;
                    return Poll::Pending;
                }
            }
            sink.as_mut()
                .start_send(Message::Binary(data.into()))
                .map_err(map_err)?;
        }
        Pin::new(&mut self.inner).poll_flush(cx).map_err(map_err)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let map_err =
            |e: tokio_tungstenite::tungstenite::Error| std::io::Error::other(e.to_string());
        let mut sink = Pin::new(&mut self.inner);
        match sink.as_mut().poll_ready(cx).map_err(map_err)? {
            Poll::Ready(()) => {}
            Poll::Pending => return Poll::Pending,
        }
        let _ = sink.as_mut().start_send(Message::Close(None));
        let _ = sink.poll_flush(cx);
        Poll::Ready(Ok(()))
    }
}

/// Plain-TCP WebSocket transport.
pub struct Ws;

impl Transport for Ws {
    type Stream = WsStream<TcpStream>;

    async fn dial(addr: &str, timeout: Duration) -> Result<Self::Stream, Error> {
        ws_connect(addr, timeout).await
    }
}

async fn ws_connect(host_port: &str, timeout: Duration) -> Result<WsStream<TcpStream>, Error> {
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(host_port))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)?;
    ws_client_handshake(tcp, host_port, "ws", timeout).await
}

/// WS client handshake over an established byte stream (plain TCP for
/// `ws://`, TLS for `wss://`): HTTP upgrade offering `ygg-ws`, failing
/// when the server agrees to anything else.
async fn ws_client_handshake<S>(
    stream: S,
    host_port: &str,
    scheme: &str,
    timeout: Duration,
) -> Result<WsStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Go dials the authority root with the ygg-ws subprotocol offered.
    // A pre-built `Request` is sent as-is, so fill in the full client
    // handshake headers (key included) ourselves.
    let url = format!("{scheme}://{host_port}/");
    let request = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(&url)
        .header("Host", host_port)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
        .body(())
        .map_err(|_| Error::BadUri(url.clone()))?;
    let (ws, response) = tokio::time::timeout(timeout, client_async(request, stream))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let agreed = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if agreed != WS_SUBPROTOCOL {
        return Err(Error::BadSubprotocol);
    }
    Ok(WsStream::new(ws))
}

/// Dial a `ws://` peer: TCP + WS handshake (subprotocol `ygg-ws`) + `meta`.
pub async fn ws_dial(
    uri: &str,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Ws>, Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Ws {
        return Err(Error::BadUri(uri.to_string()));
    }
    let stream = tokio::time::timeout(DIAL_TIMEOUT, Ws::dial(&peer.host_port, DIAL_TIMEOUT))
        .await
        .map_err(|_| Error::Timeout)??;
    crate::link::complete_dial(stream, &peer, local, opts).await
}

/// Bind a `ws://host:port` listener (plain TCP accept + WS upgrade pair).
pub async fn ws_listen(uri: &str) -> Result<tokio::net::TcpListener, Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Ws {
        return Err(Error::BadUri(uri.to_string()));
    }
    tokio::net::TcpListener::bind(&peer.host_port)
        .await
        .map_err(Error::Io)
}

/// Accept one inbound WS peer: HTTP upgrade (requires the `ygg-ws`
/// subprotocol like the Go server) + `meta` handshake as responder.
pub async fn ws_accept(
    listener: &tokio::net::TcpListener,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Ws>, Error> {
    let (sock, _) = listener.accept().await.map_err(Error::Io)?;
    let stream = ws_server_handshake(sock).await?;
    crate::link::complete_accept(stream, local, opts).await
}

/// WS server handshake over an established byte stream (plain TCP for
/// `ws://`, TLS for `wss://`).
#[allow(clippy::result_large_err)] // tungstenite's `Callback` trait fixes the 136 B `ErrorResponse`; it becomes the HTTP 500 body inside tungstenite
async fn ws_server_handshake<S>(sock: S) -> Result<WsStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ws = accept_hdr_async(sock, |req: &Request, mut res: Response| {
        let offered = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Accept iff the client offers ygg-ws (Go closes with a policy
        // violation otherwise); echo it back as the agreed subprotocol.
        if offered
            .split(',')
            .map(str::trim)
            .any(|p| p == WS_SUBPROTOCOL)
        {
            res.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                WS_SUBPROTOCOL.parse().expect("static header value"),
            );
            Ok(res)
        } else {
            Err(
                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(Some(
                    "client must speak the ygg-ws subprotocol".to_string(),
                )),
            )
        }
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(WsStream::new(ws))
}

/// WebSocket-over-TLS transport (`wss://`). Same `ygg-ws` framing as
/// [`Ws`], layered on the [`crate::tls`] unauthenticated TLS (Go has no
/// wss *listener* — "use WS behind a reverse proxy" — but dials wss with
/// `InsecureSkipVerify`, so stock Go can dial us here).
pub struct Wss;

impl Transport for Wss {
    type Stream = WsStream<tokio_rustls::TlsStream<TcpStream>>;

    async fn dial(addr: &str, timeout: Duration) -> Result<Self::Stream, Error> {
        wss_connect(addr, addr, timeout).await
    }
}

async fn wss_connect(
    host_port: &str,
    sni: &str,
    timeout: Duration,
) -> Result<WsStream<tokio_rustls::TlsStream<TcpStream>>, Error> {
    let tls: tokio_rustls::TlsStream<TcpStream> = crate::tls::tls_connect(host_port, sni, timeout)
        .await?
        .into();
    ws_client_handshake(tls, host_port, "wss", timeout).await
}

/// Dial a `wss://` peer: TCP + TLS + WS handshake (`ygg-ws`) + `meta`.
pub async fn wss_dial(
    uri: &str,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Wss>, Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Wss {
        return Err(Error::BadUri(uri.to_string()));
    }
    let sni = crate::tls::sni_host(&peer)?;
    let stream = tokio::time::timeout(
        DIAL_TIMEOUT,
        wss_connect(&peer.host_port, &sni, DIAL_TIMEOUT),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    crate::link::complete_dial(stream, &peer, local, opts).await
}

/// Bind a `wss://host:port` listener (TCP + TLS acceptor + WS upgrade).
pub async fn wss_listen(
    uri: &str,
) -> Result<(tokio::net::TcpListener, tokio_rustls::TlsAcceptor), Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Wss {
        return Err(Error::BadUri(uri.to_string()));
    }
    let listener = tokio::net::TcpListener::bind(&peer.host_port)
        .await
        .map_err(Error::Io)?;
    Ok((listener, crate::tls::server_acceptor()))
}

/// Accept one inbound WSS peer: TLS + WS upgrade + `meta` as responder.
pub async fn wss_accept(
    listener: &tokio::net::TcpListener,
    acceptor: &tokio_rustls::TlsAcceptor,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Wss>, Error> {
    let (sock, _) = listener.accept().await.map_err(Error::Io)?;
    let tls: tokio_rustls::TlsStream<TcpStream> =
        tokio::time::timeout(crate::link::TLS_HANDSHAKE_TIMEOUT, acceptor.accept(sock))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Io(std::io::Error::other(e)))?
            .into();
    let stream = ws_server_handshake(tls).await?;
    crate::link::complete_accept(stream, local, opts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[tokio::test]
    async fn ws_loopback_handshake() {
        let a = SigningKey::from_bytes(&[0x61; 32]);
        let b = SigningKey::from_bytes(&[0x62; 32]);
        let listener = ws_listen("ws://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expect_b = b.verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            ws_accept(&listener, &b, &LinkOptions::default())
                .await
                .unwrap()
        });
        let uri = format!("ws://{addr}");
        let conn = ws_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        assert_eq!(conn.remote_key, expect_b);
        let srv = server.await.unwrap();
        assert_eq!(srv.remote_key, a.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn ws_loopback_frames() {
        let a = SigningKey::from_bytes(&[0x63; 32]);
        let b = SigningKey::from_bytes(&[0x64; 32]);
        let listener = ws_listen("ws://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut c = ws_accept(&listener, &b, &LinkOptions::default())
                .await
                .unwrap();
            let (t, p) = c.read_frame().await.unwrap();
            assert_eq!((t, p), (FrameType::SigReq, vec![1, 2]));
            c.write_frame(FrameType::KeepAlive, &[]).await.unwrap();
        });
        let uri = format!("ws://{addr}");
        let mut conn = ws_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        conn.write_frame(FrameType::SigReq, &[1, 2]).await.unwrap();
        let (t, p) = conn.read_frame().await.unwrap();
        assert_eq!((t, p), (FrameType::KeepAlive, vec![]));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wss_loopback_handshake() {
        let a = SigningKey::from_bytes(&[0x65; 32]);
        let b = SigningKey::from_bytes(&[0x66; 32]);
        let (listener, acceptor) = wss_listen("wss://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expect_b = b.verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            wss_accept(&listener, &acceptor, &b, &LinkOptions::default())
                .await
                .unwrap()
        });
        let uri = format!("wss://{addr}");
        let conn = wss_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        assert_eq!(conn.remote_key, expect_b);
        let srv = server.await.unwrap();
        assert_eq!(srv.remote_key, a.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn wss_loopback_frames() {
        let a = SigningKey::from_bytes(&[0x67; 32]);
        let b = SigningKey::from_bytes(&[0x68; 32]);
        let (listener, acceptor) = wss_listen("wss://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut c = wss_accept(&listener, &acceptor, &b, &LinkOptions::default())
                .await
                .unwrap();
            let (t, p) = c.read_frame().await.unwrap();
            assert_eq!((t, p), (FrameType::SigReq, vec![1, 2]));
            c.write_frame(FrameType::KeepAlive, &[]).await.unwrap();
        });
        let uri = format!("wss://{addr}");
        let mut conn = wss_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        conn.write_frame(FrameType::SigReq, &[1, 2]).await.unwrap();
        let (t, p) = conn.read_frame().await.unwrap();
        assert_eq!((t, p), (FrameType::KeepAlive, vec![]));
        server.await.unwrap();
    }

    #[test]
    fn ws_uri_schemes() {
        let (s, p) = parse_link_uri("ws://h:99?password=x&priority=3").unwrap();
        assert_eq!(s, Scheme::Ws);
        assert_eq!(p.password, b"x");
        assert_eq!(p.priority, 3);
        let (s, _) = parse_link_uri("wss://h:99").unwrap();
        assert_eq!(s, Scheme::Wss);
        let (s, _) = parse_link_uri("quic://h:1").unwrap();
        assert_eq!(s, Scheme::Quic);
    }
}
