//! Wire vectors **captured from the installed Go 0.5.14 binary** — not
//! transcribed from Go's own tests, which build their expectations
//! programmatically and so prove nothing about our bytes.
//!
//! Provenance: `examples/go_capture.rs`, run 2026-09-24 inside
//! `unshare -Un --map-root-user` against
//! `/nix/store/3jrrg0hlz18ill7hq0liga4pg5mfgb3r-yggdrasil-0.5.14`, node key
//! derived from the 32-byte seed `0x5c` repeated (Go's `PrivateKey` config
//! field is seed||pub, so the pubkey below is derived, never chosen). The
//! harness asserts byte equality before it prints, so these constants are the
//! oracle's own output for a key we can re-sign with.
//!
//! CI stays hermetic: this file needs no Go, no namespace, no network.

use ed25519_dalek::SigningKey;
use roots::PeerKind;
use roots::frame::{self, FrameType};
use roots::handshake::{Meta, PREAMBLE, SIG_LEN};
use roots::{addr_for_key, subnet_for_key};

/// The seed the capture configured into Go.
const GO_SEED: [u8; 32] = [0x5c; 32];
/// The pubkey Go derived from it, as it appears inside the meta TLV.
const GO_PUB: &str = "ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3";
/// The `?password=` on the listener that produced `META_KEYED`.
const PASSWORD: &str = "roots-capture";

/// `meta` + BE16(117) + 4 TLVs + 64B signature, empty password.
const META_UNKEYED: &str = "6d657461007500000002000000010002000500020020\
ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3\
0003000100\
56f4c2eeca0bbf825440a694d86237facfd9e2567331ac5818280f3653090506\
8c7cab55c697b762aac5af47d75a738ed542f4d32db6cb825970017313b0d00c";

/// Same key, same version, same priority — only the membership hash changed
/// from unkeyed blake2b-512 to keyed blake2b-MAC, and the signature follows.
const META_KEYED: &str = "6d657461007500000002000000010002000500020020\
ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3\
0003000100\
4500cced6556af803c4d44f420d6f006858772b61ab12c2d70d316ef91b85e43\
3ac07b50c07f525f6f372f1486cc606687e10248603f2c9cae4d37a795f8f400";

/// Link frames pushed by Go right after the handshake: `SigReq` then
/// `BloomFilter` then the root `Announce` (`addPeer`, ironwood
/// `network/router.go:136-143`). The nonces inside them are random, so these
/// are envelope evidence, not re-encodable structs.
const FRAME_SIGREQ: &str = "0c0202989088dbb5989884a701";
const FRAME_BLOOM: &str = "2105ffffffffffffffffffffffffffffffff00000000000000000000000000000000";
const FRAME_ANNOUNCE: &str = "cd0104ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3\
ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3\
0193b1f6e39d8cc7c2ae0100\
4282a7770b9964becf44c3cee917b768b1c29a97bf41de3356451042b0b49124\
9ee601a26d762c0f5f2978d2a25d26148c7d59d155af3656c95ec7107aceed0e\
4282a7770b9964becf44c3cee917b768b1c29a97bf41de3356451042b0b49124\
9ee601a26d762c0f5f2978d2a25d26148c7d59d155af3656c95ec7107aceed0e";

fn bytes(hexed: &str) -> Vec<u8> {
    hex::decode(
        hexed
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    )
    .expect("vector is hex")
}

fn go_key() -> SigningKey {
    SigningKey::from_bytes(&GO_SEED)
}

/// Our `meta` encoder must reproduce Go's bytes exactly, in both hash branches.
/// Before this vector, version + pubkey + priority + the signature were only
/// tested by our own encoder agreeing with itself.
#[test]
fn go_meta_handshake_bytes_match_captured() {
    for (vector, password) in [(META_UNKEYED, &b""[..]), (META_KEYED, PASSWORD.as_bytes())] {
        let theirs = bytes(vector);
        let label = if password.is_empty() {
            "unkeyed"
        } else {
            "keyed"
        };
        assert_eq!(&theirs[..4], &PREAMBLE[..], "{label}: preamble");
        let body_len = u16::from_be_bytes([theirs[4], theirs[5]]) as usize;
        assert_eq!(theirs.len(), 6 + body_len, "{label}: BE16 body length");
        // 6B header + four TLVs (major 6, minor 6, pubkey 36, priority 5) + sig.
        assert_eq!(theirs.len(), 6 + 6 + 6 + 36 + 5 + SIG_LEN, "{label}: total");

        let ours = Meta::local_go(&go_key().verifying_key().to_bytes(), 0)
            .encode(&go_key(), password)
            .expect("encode");
        assert_eq!(ours, theirs, "our {label} meta diverged from Go's bytes");

        // And our decoder accepts what Go actually sent.
        let decoded = Meta::decode(&theirs, password).expect("decode Go's meta");
        assert_eq!(decoded.major, 0, "{label}: protocol major");
        assert_eq!(decoded.minor, 5, "{label}: protocol minor");
        assert_eq!(decoded.priority, 0, "{label}: listener default priority");
        assert_eq!(hex::encode(decoded.public_key), GO_PUB, "{label}: key");
        assert_eq!(decoded.vendor, None, "{label}: Go sends no vendor tag");
        assert_eq!(decoded.features, None, "{label}: Go sends no features tag");
        assert_eq!(
            decoded.peer_kind(),
            PeerKind::Go,
            "{label}: reads as a Go peer"
        );
    }
}

/// The password must actually bind the signature, not just the hash: Go's
/// keyed bytes must not verify under the empty password and vice versa.
#[test]
fn go_meta_password_binds_the_signature() {
    let unkeyed = bytes(META_UNKEYED);
    let keyed = bytes(META_KEYED);
    assert_ne!(unkeyed, keyed, "the branches must differ");
    // Everything before the signature is identical: only the hash input moved.
    assert_eq!(
        unkeyed[..unkeyed.len() - SIG_LEN],
        keyed[..keyed.len() - SIG_LEN]
    );
    assert!(
        Meta::decode(&keyed, b"").is_err(),
        "keyed bytes under no password"
    );
    assert!(Meta::decode(&unkeyed, PASSWORD.as_bytes()).is_err());
    // Our encoder lands in the same place both ways.
    assert_eq!(
        Meta::local_go(&go_key().verifying_key().to_bytes(), 0)
            .encode(&go_key(), PASSWORD.as_bytes())
            .unwrap(),
        keyed
    );
}

/// The post-handshake envelope, from Go's own bytes: `uvarint(len(type ||
/// payload)) || type || payload`. Our encoder must rebuild each frame exactly
/// from what our decoder read out of it.
#[test]
fn go_link_frame_envelope_matches_captured() {
    for (vector, want) in [
        (FRAME_SIGREQ, FrameType::SigReq),
        (FRAME_BLOOM, FrameType::BloomFilter),
        (FRAME_ANNOUNCE, FrameType::Announce),
    ] {
        let raw = bytes(vector);
        let (len, skip) = frame::read_uvarint(&raw).expect("uvarint length");
        // The length covers the type byte too: Go builds the uvarint from
        // `bufSize := uint64(data.size() + 1)` (`peers.go:202`, "The +1 is
        // from 1 byte for the pType" at :208) before writing the type.
        assert_eq!(
            len as usize,
            raw.len() - skip,
            "{want:?}: length covers type + payload"
        );
        let (ftype, payload) = frame::decode_body(&raw[skip..]).expect("decode Go frame");
        assert_eq!(ftype, want, "{want:?}: discriminant");
        assert_eq!(
            frame::encode_frame(ftype, payload),
            raw,
            "{want:?}: our encoder must reproduce Go's framing"
        );
    }
}

/// Addresses, and how Go renders them.
///
/// Captured 2026-09-24 from the installed 0.5.14 binary with
/// `yggdrasil -useconf -address` / `-subnet` for each `PrivateKey`. Both flags
/// return before Go touches a TUN (`cmd/yggdrasil/main.go:148-161`), so the
/// capture needed no namespace and no privileges.
///
/// The keys were searched for, not picked: one has a lone zero group in the
/// middle, the other has its only zero group last. Go prints through
/// `net.IP.String()`, which collapses the longest run of *two or more* zero
/// groups to `::` and leaves a single group as `0` even at the end — so the
/// second vector is what proves a trailing zero is not collapsed, and the two
/// subnets, which always end in four zero groups, what proves a run is. The
/// leading `200` in each address is the other half of the point: Go writes a
/// group without its leading zero.
const GO_ADDRESS_VECTORS: &[(&str, &str, &str)] = &[
    (
        "e226000000000000000000000000000000000000000000000000000000000000\
         f60f7fffa89be9ee53cf06df5b726dc2c5c01ba6e7e300dbe05ee5bfbe4fe52e",
        "200:13e1:0:aec8:2c23:5861:f241:491b",
        "300:13e1:0:aec8::/64",
    ),
    (
        "dd90010000000000000000000000000000000000000000000000000000000000\
         e1a84349ae7670f729420593ffffdc4a0fb8dfc5801710b001935a196301bc4f",
        "200:3caf:796c:a313:1e11:ad7b:f4d8:0",
        "300:3caf:796c:a313::/64",
    ),
];

/// Our printing must be Go's character for character: an operator pastes these
/// into a routing table or a `curl -g`, and `yggdrasilctl` output is compared
/// against them by eye.
#[test]
fn go_address_and_subnet_strings_match_captured() {
    for (private_hex, want_addr, want_subnet) in GO_ADDRESS_VECTORS {
        let raw = bytes(private_hex);
        assert_eq!(raw.len(), 64, "Go's PrivateKey is seed then public key");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[..32]);
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        assert_eq!(&raw[32..], &public[..], "vector must be one real key pair");
        assert_eq!(addr_for_key(&public).to_string(), *want_addr);
        assert_eq!(subnet_for_key(&public).to_string(), *want_subnet);
    }
}
