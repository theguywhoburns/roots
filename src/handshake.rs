//! Link handshake `meta` codec. Port of Go `src/core/version.go`.
//!
//! Wire format: `meta` + BE16(total len) + TLVs + 64B signature, where the
//! signature is `ed25519.Sign(blake2b512(password, public_key))`.

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2b512, Blake2bMac512, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::address::KEY_LEN;
use crate::error::Error;

/// First 4 bytes of every handshake message.
pub const PREAMBLE: &[u8; 4] = b"meta";
/// Preamble (4B) + length prefix (2B).
pub const HEADER_LEN: usize = 6;
/// Trailing ed25519 signature length in bytes.
pub const SIG_LEN: usize = 64;
/// Max link password length (== BLAKE2b key size, mirrors Go's cap).
pub const MAX_PASSWORD_LEN: usize = 64;
/// Protocol version this client speaks (must equal the peer's).
pub const PROTOCOL_MAJOR: u16 = 0;
/// Protocol minor version.
pub const PROTOCOL_MINOR: u16 = 5;

/// TLV tag: major version, BE16 value.
const TAG_MAJOR: u16 = 0;
/// TLV tag: minor version, BE16 value.
const TAG_MINOR: u16 = 1;
/// TLV tag: node public key, 32B value.
const TAG_PUBKEY: u16 = 2;
/// TLV tag: link priority, 1B value.
const TAG_PRIORITY: u16 = 3;
/// TLV field header length (tag BE16 + len BE16).
const FIELD_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub major: u16,
    pub minor: u16,
    pub public_key: [u8; KEY_LEN],
    pub priority: u8,
}

impl Meta {
    pub fn local(public_key: &[u8; KEY_LEN], priority: u8) -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            public_key: *public_key,
            priority,
        }
    }

    pub fn encode(&self, secret: &SigningKey, password: &[u8]) -> Result<Vec<u8>, Error> {
        if password.len() > MAX_PASSWORD_LEN {
            return Err(Error::PasswordTooLong);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 20 + KEY_LEN + SIG_LEN);
        out.extend_from_slice(PREAMBLE);
        out.extend_from_slice(&[0, 0]); // patched below
        push_field(&mut out, TAG_MAJOR, &self.major.to_be_bytes());
        push_field(&mut out, TAG_MINOR, &self.minor.to_be_bytes());
        push_field(&mut out, TAG_PUBKEY, &self.public_key);
        push_field(&mut out, TAG_PRIORITY, &[self.priority]);
        let hash = keyed_hash(&self.public_key, password)?;
        out.extend_from_slice(&secret.sign(&hash).to_bytes());
        let body_len = (out.len() - HEADER_LEN) as u16;
        out[4..HEADER_LEN].copy_from_slice(&body_len.to_be_bytes());
        Ok(out)
    }

    /// Decode a full message (header + body). Mirrors Go's streaming decode.
    pub fn decode(msg: &[u8], password: &[u8]) -> Result<Self, Error> {
        if msg.len() < HEADER_LEN || &msg[..4] != PREAMBLE {
            return Err(Error::InvalidPreamble);
        }
        let body_len = u16::from_be_bytes([msg[4], msg[5]]) as usize;
        if body_len < SIG_LEN || msg.len() != HEADER_LEN + body_len {
            return Err(Error::InvalidLength);
        }
        let body = &msg[HEADER_LEN..];
        let (fields, sig) = body.split_at(body.len() - SIG_LEN);
        let mut meta = Meta {
            major: 0,
            minor: 0,
            public_key: [0u8; KEY_LEN],
            priority: 0,
        };
        let mut rest = fields;
        while rest.len() >= FIELD_HEADER_LEN {
            let tag = u16::from_be_bytes([rest[0], rest[1]]);
            let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            rest = &rest[FIELD_HEADER_LEN..];
            if rest.len() < len {
                return Err(Error::InvalidLength);
            }
            let (val, tail) = rest.split_at(len);
            match tag {
                TAG_MAJOR if val.len() == 2 => {
                    meta.major = u16::from_be_bytes([val[0], val[1]]);
                }
                TAG_MINOR if val.len() == 2 => {
                    meta.minor = u16::from_be_bytes([val[0], val[1]]);
                }
                TAG_PUBKEY if val.len() == KEY_LEN => {
                    meta.public_key.copy_from_slice(val);
                }
                TAG_PRIORITY if val.len() == 1 => {
                    meta.priority = val[0];
                }
                TAG_MAJOR | TAG_MINOR | TAG_PUBKEY | TAG_PRIORITY => {
                    return Err(Error::InvalidLength);
                }
                _ => {} // forward-compatible: ignore unknown tags
            }
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(Error::InvalidLength);
        }
        let hash = keyed_hash(&meta.public_key, password)?;
        let sig = Signature::from_bytes(sig.try_into().map_err(|_| Error::InvalidLength)?);
        VerifyingKey::from_bytes(&meta.public_key)
            .map_err(|_| Error::InvalidLength)?
            .verify_strict(&hash, &sig)
            .map_err(|_| Error::BadPassword)?;
        Ok(meta)
    }

    pub fn check(&self) -> Result<(), Error> {
        if self.major != PROTOCOL_MAJOR || self.minor != PROTOCOL_MINOR {
            return Err(Error::BadVersion(self.major, self.minor));
        }
        Ok(())
    }
}

fn push_field(out: &mut Vec<u8>, tag: u16, val: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(val.len() as u16).to_be_bytes());
    out.extend_from_slice(val);
}

/// `blake2b-512(key=password, data=public_key)`. Empty password == unkeyed,
/// so `nil` and `""` interoperate exactly like the Go side.
fn keyed_hash(public_key: &[u8; KEY_LEN], password: &[u8]) -> Result<Vec<u8>, Error> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(Error::PasswordTooLong);
    }
    if password.is_empty() {
        let mut h = Blake2b512::new();
        h.update(public_key);
        Ok(h.finalize().to_vec())
    } else {
        let mut h = <Blake2bMac512 as KeyInit>::new_from_slice(password)
            .map_err(|_| Error::PasswordTooLong)?;
        h.update(public_key);
        Ok(h.finalize().into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn roundtrip_matrix_like_go() {
        for password in [&[][..], b"".as_slice(), b"foo".as_slice()] {
            for (major, minor, prio) in [(1, 0, 0), (2, 4, 0), (0, 5, 6), (0, 5, 255)] {
                let sk = key(7);
                let m = Meta {
                    major,
                    minor,
                    public_key: sk.verifying_key().to_bytes(),
                    priority: prio,
                };
                let enc = m.encode(&sk, password).unwrap();
                let dec = Meta::decode(&enc, password).unwrap();
                assert_eq!(dec, m);
            }
        }
    }

    #[test]
    fn password_matrix_like_go_version_test() {
        let sk = key(1);
        let pk = sk.verifying_key().to_bytes();
        let m = Meta::local(&pk, 0);
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"", b"", true),
            (b"", b"foo", false),
            (b"foo", b"", false),
            (b"foo", b"foo", true),
            (b"foo", b"bar", false),
        ];
        for (p1, p2, allowed) in cases {
            let enc = m.encode(&sk, p1).unwrap();
            assert_eq!(Meta::decode(&enc, p2).is_ok(), *allowed, "{p1:?}->{p2:?}");
        }
    }

    #[test]
    fn rejects_garbage() {
        let sk = key(2);
        let pk = sk.verifying_key().to_bytes();
        let enc = Meta::local(&pk, 0).encode(&sk, b"").unwrap();
        assert!(matches!(
            Meta::decode(b"nope", b""),
            Err(Error::InvalidPreamble)
        ));
        assert!(matches!(
            Meta::decode(&enc[..10], b""),
            Err(Error::InvalidLength)
        ));
        let mut bad = enc.clone();
        bad[4..6].copy_from_slice(&99u16.to_be_bytes());
        assert!(matches!(Meta::decode(&bad, b""), Err(Error::InvalidLength)));
    }

    #[test]
    fn check_rejects_wrong_version() {
        let m = Meta {
            major: 9,
            minor: 9,
            public_key: [0; KEY_LEN],
            priority: 0,
        };
        assert!(matches!(m.check(), Err(Error::BadVersion(9, 9))));
        assert!(Meta::local(&[0; KEY_LEN], 0).check().is_ok());
    }
}
