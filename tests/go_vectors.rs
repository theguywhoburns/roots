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
use roots::{bloom, tree};

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
const FRAME_SIGREQ: &str = "0c0202f4a6dfc495bdbeb4f601";
const FRAME_BLOOM: &str = "2105ffffffffffffffffffffffffffffffff00000000000000000000000000000000";
/// `SigRes`, which a passive capture never sees.
///
/// Go sends one only in answer to a `SigReq` it has not already answered
/// (`_handleRequest`, ironwood `network/router.go:409-416`), and the unsolicited
/// burst after a handshake is `SigReq` + `BloomFilter` + `Announce`. So the
/// harness sends a request first — `examples/go_capture.rs --frames`, which is
/// why this vector did not exist for the first four slices.
///
/// The request that produced it was `SigReq { seq: 1, nonce: 0 }` for the
/// harness's own identity, and the response echoes it back verbatim
/// (`routerSigRes{routerSigReq: *req}`, `:410-413`). That echo is the assertion
/// that catches a field-order mistake: every field of `SigRes` is a uvarint
/// except the signature, so a swapped pair is two plausible small numbers.
///
/// `port: 1` is the **requester's** port, not the responder's — Go fills
/// `port: p.port` from the peer the request arrived on (`:412`).
const FRAME_SIGRES: &str = "440301000185224f9d08ece29c8c70c62a7aab1b554d75fc11dc2afd5606b97ad32f0\
7bb11e337a23da6117bd2572499316df4416b49cefe87f566d33de31beddf4028dd06";
/// The identity the harness dials as, and so the *other* half of the `SigRes`
/// signature preimage: Go signs `res.bytesForSig(p.key, ourPublicKey)` with its
/// own key, where `p` is us (`network/router.go:412`). So this vector verifies
/// against (harness key, Go key) and **not** against Go's key twice.
const HARNESS_SEED: [u8; 32] = [0x2b; 32];
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
        (FRAME_SIGRES, FrameType::SigRes),
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

/// The three tree payloads, decoded from Go's own bytes and re-encoded to the
/// same bytes.
///
/// Before this, `SigReq`, `SigRes` and `Announce` were only round-tripped
/// through our own encoder (`sigreq_roundtrip_exact`,
/// `announce_chain_verifies`), which cannot catch a layout that is
/// self-consistent and wrong. What each vector adds:
///
/// - **`SigRes`** — the field order, and that `port` is the *requester's*
///   (`network/router.go:412`). The signature preimage is
///   `node ‖ parent ‖ req ‖ port` (`SigRes::bytes_for_sig`), and the vector
///   verifies only if all four are right, so a vector that checked would catch
///   a missing field; one that does not, proves nothing.
/// - **`Announce`** — that `res.port == 0` with `key == parent` is legal (a
///   root has no parent to sign for it) and that both signatures verify.
/// - **`SigReq`** — only the shape, since its nonce is Go's random draw.
#[test]
fn go_tree_payloads_match_captured() {
    let go_pub: [u8; 32] = hex::decode(GO_PUB).unwrap().try_into().unwrap();
    let our_pub = SigningKey::from_bytes(&HARNESS_SEED)
        .verifying_key()
        .to_bytes();

    let payload = |vector: &str| -> Vec<u8> {
        let raw = bytes(vector);
        let (_, skip) = frame::read_uvarint(&raw).expect("uvarint length");
        frame::decode_body(&raw[skip..]).expect("body").1.to_vec()
    };

    // SigReq: Go's own sequence and the random nonce it drew, 11 bytes of
    // uvarint in all. The nonce is a 10-byte value, which is why it is read off
    // the wire rather than written as a literal: a hand-typed `u64` constant
    // here would be silently truncated and the test would still compile.
    let req_bytes = payload(FRAME_SIGREQ);
    let (req, n) = tree::SigReq::decode(&req_bytes).expect("SigReq");
    assert_eq!(
        n,
        req_bytes.len(),
        "two uvarints and nothing else: {n} of {} consumed",
        req_bytes.len()
    );
    assert_eq!(req.seq, 2, "Go's own sequence number");
    let mut out = Vec::new();
    req.encode(&mut out);
    assert_eq!(out, payload(FRAME_SIGREQ), "our SigReq encoder");

    // SigRes: the request we sent (seq 1, nonce 0) comes back untouched, and
    // the port is ours.
    let raw_res = payload(FRAME_SIGRES);
    let (res, n) = tree::SigRes::decode(&raw_res).expect("SigRes");
    assert_eq!(n, raw_res.len(), "a trailing field would be a length bug");
    assert_eq!(
        (res.req.seq, res.req.nonce, res.port),
        (1, 0, 1),
        "the echoed request, and the requester's port"
    );
    assert!(
        res.check(&our_pub, &go_pub),
        "the signature covers node ‖ parent ‖ req ‖ port, signed by the responder"
    );
    assert!(
        !res.check(&go_pub, &go_pub),
        "and it is not signed over Go's key twice"
    );
    let mut out = Vec::new();
    res.encode(&mut out);
    assert_eq!(out, payload(FRAME_SIGRES), "our SigRes encoder");

    // BloomFilter: the captured payload is Go advertising an *empty* filter, and
    // that is exactly what it proves. `ff`×16 then `00`×16 reads as "every one of
    // the 128 words is zero", which is what a node sends before its filter has
    // any bits set.
    //
    // What it pins: **flags0 comes before flags1**. Swapped, the payload still
    // decodes to "every word is zero", because the two blocks are symmetric —
    // measured, by reversion. And a flag bit means the word is zero or all-ones
    // rather than a data word, since there is no third block to find.
    //
    // What it does *not* pin, and it is worth being exact here: the bit order
    // *within* a flag byte. An all-ones block has every position set, so
    // MSB-first (`0x80 >> (idx % 8)`) and LSB-first (`1 << (idx % 8)`) both
    // produce it — also measured, by reversion. That half of the format rests
    // on Go's source (`network/bloomfilter.go`) and is pinned by exact bytes in
    // `src/bloom.rs`. A second, non-empty bloom from Go would close the gap; the
    // capture cannot get one, and `examples/go_capture.rs --frames` says why.
    let raw_bloom = payload(FRAME_BLOOM);
    let bloom = bloom::BloomFilter::decode_exact(&raw_bloom).expect("Go's BloomFilter");
    // Every bit clear: a filter that matches nothing, which is what Go sends to
    // a node it has no bits for. `test` is the observable, since the words are
    // private.
    for probe in [b"".as_slice(), b"anything", &raw_bloom] {
        assert!(
            !bloom.test(probe),
            "a filter of 128 zero words matches nothing, including {} bytes",
            probe.len()
        );
    }
    assert_eq!(
        bloom.encode(),
        raw_bloom,
        "our BloomFilter encoder must reproduce Go's bytes"
    );
    // The same claim from the other direction, because `decode_exact` and
    // `encode` are separate code and a symmetric bug in both would pass.
    assert_eq!(
        bloom::BloomFilter::new().encode(),
        raw_bloom,
        "and a freshly-built empty filter encodes to those bytes"
    );

    // Announce: the root announcing itself, which is the only shape a capture
    // can see — a Go node with one peer has no other parent to announce.
    let ann = payload(FRAME_ANNOUNCE);
    let ann = tree::Announce::decode_exact(&ann).expect("Announce");
    assert_eq!(ann.key, go_pub, "a lone Go node announces itself");
    assert_eq!(ann.parent, go_pub, "as its own parent: it is the root");
    assert_eq!(ann.res.port, 0, "and has no port to advertise");
    assert!(ann.check(), "both signatures over the same preimage");
    let mut out = Vec::new();
    ann.encode(&mut out);
    assert_eq!(out, payload(FRAME_ANNOUNCE), "our Announce encoder");
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
