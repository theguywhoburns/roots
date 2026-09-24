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
    #[error("node cannot connect to self")]
    SelfDial,
    #[error("remote key not in allowlist")]
    KeyNotAllowed,
    #[error("pinned key mismatch")]
    PinnedMismatch,
    #[error("password longer than 64 bytes")]
    PasswordTooLong,
    #[error("bad peer URI: {0}")]
    BadUri(String),
    // The five URI refusals below are Go's `linkError` constants verbatim
    // (`core/link.go:149-157`) because `addPeer` puts the string straight into
    // the admin socket's `error` field, where `yggdrasilctl` shows it.
    #[error("link schema unknown")]
    UnrecognisedSchema,
    #[error("pinned public key is invalid")]
    PinnedKeyInvalid,
    #[error("priority value is invalid")]
    PriorityInvalid,
    #[error("invalid password supplied")]
    PasswordInvalid,
    #[error("max backoff duration invalid")]
    MaxBackoffInvalid,
    #[error("websocket subprotocol mismatch, expected ygg-ws")]
    BadSubprotocol,
    #[error("handshake timed out")]
    Timeout,
    #[error("no open link to this peer")]
    NoLink,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl Error {
    /// True for the two errors that mean "this link is gone" rather than
    /// "this node is broken". A node loop keeps running on these and redials;
    /// Go's per-peer reader just returns and lets `removePeer` clean up
    /// (`peers.go:228`), which is why one dead link never stops its siblings.
    pub fn is_link(&self) -> bool {
        matches!(self, Error::Io(_) | Error::NoLink)
    }
}
