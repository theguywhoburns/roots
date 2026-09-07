//! QUIC link transport (`quic://`). Mirrors Go `src/core/link_quic.go`:
//! one bidirectional stream per link (`OpenStreamSync` / `AcceptStream`
//! there, `open_bi` / `accept_bi` here), TLS like the `tls://` transport
//! (self-signed + unverified both ways; identity comes from `meta`).
//!
//! Timeouts mirror Go's `quic.Config`: 60s max idle, 20s keepalive — an
//! idle mesh link must survive much longer than quinn's short defaults.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Error;
use crate::link::{
    DIAL_TIMEOUT, HANDSHAKE_TIMEOUT, LinkOptions, PeerConn, Scheme, Transport, parse_link_uri,
};

/// Go `quic.Config` values (`link_quic.go` `newLinkQUIC`).
const QUIC_MAX_IDLE: Duration = Duration::from_secs(60);
const QUIC_KEEPALIVE: Duration = Duration::from_secs(20);

/// One QUIC bidirectional stream as a byte stream. quinn already speaks
/// `poll_read`/`poll_write`, so this is a thin error-mapping shell. The
/// endpoint and connection handles are kept alive here: dropping a quinn
/// `Endpoint` closes its connections, and dropping the last `Connection`
/// handle closes that connection — both would otherwise die with the
/// dial/accept future while the stream is still in use.
pub struct QuicStream {
    _endpoint: quinn::Endpoint,
    _conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    fn new(
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            _endpoint: endpoint,
            _conn: conn,
            send,
            recv,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.recv
            .poll_read_buf(cx, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        // QUIC streams are reliable and ordered; writes go out promptly.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.send
            .finish()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Poll::Ready(Ok(()))
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(QUIC_MAX_IDLE.try_into().expect("idle timeout fits")));
    t.keep_alive_interval(Some(QUIC_KEEPALIVE));
    Arc::new(t)
}

fn client_config() -> quinn::ClientConfig {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crate::tls::client_config())
        .expect("rustls client config converts");
    let mut c = quinn::ClientConfig::new(Arc::new(crypto));
    c.transport_config(transport_config());
    c
}

fn server_config() -> quinn::ServerConfig {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crate::tls::server_config())
        .expect("rustls server config converts");
    let mut s = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    s.transport_config(transport_config());
    s
}

/// QUIC transport: one bidi stream per link.
pub struct Quic;

impl Transport for Quic {
    type Stream = QuicStream;

    async fn dial(addr: &str, timeout: Duration) -> Result<Self::Stream, Error> {
        quic_connect(addr, addr, timeout).await
    }
}

async fn quic_connect(host_port: &str, sni: &str, timeout: Duration) -> Result<QuicStream, Error> {
    let addr: SocketAddr = tokio::net::lookup_host(host_port)
        .await
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::BadUri(host_port.to_string()))?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("unspecified v4"))
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    endpoint.set_default_client_config(client_config());
    let connecting = endpoint
        .connect(addr, sni)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let (send, recv) = tokio::time::timeout(timeout, conn.open_bi())
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(QuicStream::new(endpoint, conn, send, recv))
}

/// Dial a `quic://` peer: UDP + QUIC + one bidi stream + `meta`.
pub async fn quic_dial(
    uri: &str,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Quic>, Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Quic {
        return Err(Error::BadUri(uri.to_string()));
    }
    let sni = crate::tls::sni_host(&peer)?;
    let stream = tokio::time::timeout(
        DIAL_TIMEOUT,
        quic_connect(&peer.host_port, &sni, DIAL_TIMEOUT),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    crate::link::complete_dial(stream, &peer, local, opts).await
}

/// QUIC endpoint bound for `quic://host:port` (UDP socket + endpoint pair;
/// the endpoint must be kept alive while accepting).
pub async fn quic_listen(uri: &str) -> Result<(quinn::Endpoint, SocketAddr), Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Quic {
        return Err(Error::BadUri(uri.to_string()));
    }
    let addr: SocketAddr = tokio::net::lookup_host(&peer.host_port)
        .await
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::BadUri(uri.to_string()))?;
    let endpoint = quinn::Endpoint::server(server_config(), addr)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let bound = endpoint
        .local_addr()
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok((endpoint, bound))
}

/// Accept one inbound QUIC peer: new connection + first bidi stream +
/// `meta` handshake as responder.
pub async fn quic_accept(
    endpoint: &quinn::Endpoint,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Quic>, Error> {
    let incoming = tokio::time::timeout(HANDSHAKE_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| Error::Timeout)?
        .ok_or_else(|| Error::Io(std::io::Error::other("endpoint closed")))?;
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let stream = QuicStream::new(endpoint.clone(), conn.clone(), send, recv);
    crate::link::complete_accept(stream, local, opts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[tokio::test]
    async fn quic_loopback_handshake() {
        let a = SigningKey::from_bytes(&[0x71; 32]);
        let b = SigningKey::from_bytes(&[0x72; 32]);
        let (endpoint, bound) = quic_listen("quic://127.0.0.1:0").await.unwrap();
        let expect_b = b.verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            quic_accept(&endpoint, &b, &LinkOptions::default())
                .await
                .unwrap()
        });
        let uri = format!("quic://{bound}");
        let conn = quic_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        assert_eq!(conn.remote_key, expect_b);
        let srv = server.await.unwrap();
        assert_eq!(srv.remote_key, a.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn quic_loopback_frames() {
        let a = SigningKey::from_bytes(&[0x73; 32]);
        let b = SigningKey::from_bytes(&[0x74; 32]);
        let (endpoint, bound) = quic_listen("quic://127.0.0.1:0").await.unwrap();
        let server = tokio::spawn(async move {
            let mut c = quic_accept(&endpoint, &b, &LinkOptions::default())
                .await
                .unwrap();
            let (t, p) = c.read_frame().await.unwrap();
            assert_eq!((t, p), (FrameType::SigReq, vec![1, 2]));
            c.write_frame(FrameType::KeepAlive, &[]).await.unwrap();
            // QUIC has no TCP-like graceful FIN: dropping our handles
            // tears the connection down, possibly before the peer reads
            // the reply. Linger so the client reliably gets it.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let uri = format!("quic://{bound}");
        let mut conn = quic_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        conn.write_frame(FrameType::SigReq, &[1, 2]).await.unwrap();
        let (t, p) = conn.read_frame().await.unwrap();
        assert_eq!((t, p), (FrameType::KeepAlive, vec![]));
        server.await.unwrap();
    }

    #[test]
    fn quic_uri_schemes() {
        let (s, p) = parse_link_uri("quic://h:99?password=x&priority=3").unwrap();
        assert_eq!(s, Scheme::Quic);
        assert_eq!(p.password, b"x");
        assert_eq!(p.priority, 3);
    }
}
