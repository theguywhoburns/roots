//! TLS link transport (`tls://`). Mirrors Go `src/core/link_tls.go`: plain
//! TLS over TCP with **unauthenticated** certificates on both sides (Go uses
//! `InsecureSkipVerify` + self-signed certs; identity comes from the `meta`
//! handshake, not the certificate).

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::link::{
    DIAL_TIMEOUT, HANDSHAKE_TIMEOUT, LinkOptions, PeerConn, PeerUri, Scheme, TLS_HANDSHAKE_TIMEOUT,
    Transport, merge_opts, parse_link_uri,
};

/// TLS transport, usable for both dial (client) and accept (server) ends
/// via the unified [`tokio_rustls::TlsStream`].
pub struct Tls;

impl Transport for Tls {
    type Stream = tokio_rustls::TlsStream<TcpStream>;

    async fn dial(addr: &str, timeout: Duration) -> Result<Self::Stream, Error> {
        Ok(tls_connect(addr, addr, timeout).await?.into())
    }
}

/// Accept TLS certificates without verification, like Go's
/// `InsecureSkipVerify`. Handshake signatures are still checked by the
/// provider (proving peer possession of the cert key).
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Unverified, exactly like Go's `InsecureSkipVerify`: peer identity
        // comes from the `meta` handshake, TLS is only transport privacy.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

pub(crate) fn client_config() -> Arc<ClientConfig> {
    let prov = provider();
    let verifier = Arc::new(NoVerify(prov.clone()));
    Arc::new(
        ClientConfig::builder_with_provider(prov.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("tls versions")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

pub(crate) fn server_config() -> Arc<rustls::ServerConfig> {
    let key = rcgen::generate_simple_self_signed(vec!["roots".to_string()]).expect("self-signed");
    let cert_der = key.cert.der().to_vec();
    let key_der = key.key_pair.serialize_der();
    let cert = CertificateDer::from(cert_der);
    let secret = PrivateKeyDer::try_from(key_der).expect("rcgen emits PKCS#8 secrets");
    let prov = provider();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(prov.into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], secret)
            .expect("self-signed cert"),
    )
}

/// SNI host: `?sni=` override, else the authority host (brackets stripped).
pub(crate) fn sni_host(peer: &PeerUri) -> Result<String, Error> {
    if let Some(sni) = &peer.sni {
        return Ok(sni.clone());
    }
    let host = peer
        .host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&peer.host_port);
    Ok(host
        .strip_prefix('[')
        .unwrap_or(host)
        .strip_suffix(']')
        .unwrap_or(host)
        .to_string())
}

pub(crate) async fn tls_connect(
    host_port: &str,
    sni: &str,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(host_port))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)?;
    let name = ServerName::try_from(sni.to_string()).map_err(|_| Error::BadUri(sni.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(client_config());
    tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Io(std::io::Error::other(e)))
}

/// Dial a `tls://` peer: TCP + TLS + `meta` handshake.
pub async fn tls_dial(
    uri: &str,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Tls>, Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Tls {
        return Err(Error::BadUri(uri.to_string()));
    }
    tls_dial_peer(&peer, local, opts).await
}

async fn tls_dial_peer(
    peer: &PeerUri,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Tls>, Error> {
    let merged = merge_opts(peer, opts);
    let sni = sni_host(peer)?;
    let mut stream: tokio_rustls::TlsStream<TcpStream> = tokio::time::timeout(
        DIAL_TIMEOUT,
        tls_connect(&peer.host_port, &sni, DIAL_TIMEOUT),
    )
    .await
    .map_err(|_| Error::Timeout)??
    .into();
    let (remote_key, priority) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::link::run_handshake(&mut stream, local, &merged, false),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(PeerConn {
        remote_key,
        priority,
        stream,
    })
}

/// Bind a `tls://host:port` listener (TCP accept + TLS acceptor pair).
pub async fn tls_listen(
    uri: &str,
) -> Result<(tokio::net::TcpListener, tokio_rustls::TlsAcceptor), Error> {
    let (scheme, peer) = parse_link_uri(uri)?;
    if scheme != Scheme::Tls {
        return Err(Error::BadUri(uri.to_string()));
    }
    let listener = tokio::net::TcpListener::bind(&peer.host_port)
        .await
        .map_err(Error::Io)?;
    Ok((listener, server_acceptor()))
}

/// Self-signed TLS acceptor (Go mints its own node cert the same way;
/// identity comes from the `meta` handshake, not the certificate).
pub(crate) fn server_acceptor() -> tokio_rustls::TlsAcceptor {
    tokio_rustls::TlsAcceptor::from(server_config())
}

/// Accept one inbound TLS peer and complete the handshake as responder.
pub async fn tls_accept(
    listener: &tokio::net::TcpListener,
    acceptor: &tokio_rustls::TlsAcceptor,
    local: &SigningKey,
    opts: &LinkOptions,
) -> Result<PeerConn<Tls>, Error> {
    let (sock, _) = listener.accept().await.map_err(Error::Io)?;
    let mut stream: tokio_rustls::TlsStream<TcpStream> =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(sock))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Io(std::io::Error::other(e)))?
            .into();
    let (remote_key, priority) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::link::run_handshake(&mut stream, local, opts, true),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(PeerConn {
        remote_key,
        priority,
        stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LinkOptions;

    #[tokio::test]
    async fn tls_loopback_handshake() {
        let client_sk = SigningKey::from_bytes(&[0x51; 32]);
        let server_sk = SigningKey::from_bytes(&[0x52; 32]);
        let (listener, acceptor) = tls_listen("tls://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expect_server = server_sk.verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            tls_accept(&listener, &acceptor, &server_sk, &LinkOptions::default())
                .await
                .unwrap()
        });
        let uri = format!("tls://{addr}");
        let conn = tls_dial(&uri, &client_sk, &LinkOptions::default())
            .await
            .unwrap();
        assert_eq!(conn.remote_key, expect_server);
        let srv = server.await.unwrap();
        assert_eq!(srv.remote_key, client_sk.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn tls_loopback_frames() {
        use crate::frame::FrameType;
        let a = SigningKey::from_bytes(&[0x53; 32]);
        let b = SigningKey::from_bytes(&[0x54; 32]);
        let (listener, acceptor) = tls_listen("tls://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut c = tls_accept(&listener, &acceptor, &b, &LinkOptions::default())
                .await
                .unwrap();
            let (t, p) = c.read_frame().await.unwrap();
            assert_eq!((t, p), (FrameType::SigReq, vec![1, 2]));
            c.write_frame(FrameType::KeepAlive, &[]).await.unwrap();
        });
        let uri = format!("tls://{addr}");
        let mut conn = tls_dial(&uri, &a, &LinkOptions::default()).await.unwrap();
        conn.write_frame(FrameType::SigReq, &[1, 2]).await.unwrap();
        let (t, p) = conn.read_frame().await.unwrap();
        assert_eq!((t, p), (FrameType::KeepAlive, vec![]));
        server.await.unwrap();
    }

    #[test]
    fn link_uri_schemes() {
        let (s, p) = parse_link_uri("tls://h:99?password=x&priority=3&sni=example.com").unwrap();
        assert_eq!(s, Scheme::Tls);
        assert_eq!(p.password, b"x");
        assert_eq!(p.priority, 3);
        assert_eq!(p.sni.as_deref(), Some("example.com"));
        assert_eq!(sni_host(&p).unwrap(), "example.com");
        let (s, p) = parse_link_uri("tls://[::1]:99").unwrap();
        assert_eq!(s, Scheme::Tls);
        assert_eq!(sni_host(&p).unwrap(), "::1");
        let (s, _) = parse_link_uri("tcp://h:1").unwrap();
        assert_eq!(s, Scheme::Tcp);
        let (s, _) = parse_link_uri("quic://h:1").unwrap();
        assert_eq!(s, Scheme::Quic);
        // tcp-only parser still rejects tls.
        assert!(crate::link::parse_peer_uri("tls://h:1").is_err());
    }
}
