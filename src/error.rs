use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid handshake, remote side is not Yggdrasil")]
    InvalidPreamble,
    #[error("invalid handshake length, possible version mismatch")]
    InvalidLength,
    #[error("password does not match remote side")]
    BadPassword,
    #[error("incompatible version {0}.{1}, expected 0.5")]
    BadVersion(u16, u16),
    #[error("refusing to peer with self")]
    SelfDial,
    #[error("remote key not in allowlist")]
    KeyNotAllowed,
    #[error("pinned key mismatch")]
    PinnedMismatch,
    #[error("password longer than 64 bytes")]
    PasswordTooLong,
    #[error("bad peer URI: {0}")]
    BadUri(String),
    #[error("websocket subprotocol mismatch, expected ygg-ws")]
    BadSubprotocol,
    #[error("handshake timed out")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}
