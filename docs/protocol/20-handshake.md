# Handshake `meta`

The first bytes on every new link, before any frame envelope
(`10-envelope.md`) applies. Both sides write one `meta` message, read the
other's, and close the connection if either fails. The exchange authenticates
the link identity and carries nothing else that the rest of the protocol needs
early.

Source of truth: `reference/yggdrasil-go/src/core/version.go` (encode :59-96,
decode :99-170, `check` :173-184) and `src/core/link.go:628-675`
(`links.handler`, the flow that drives it). Every byte layout below was
captured from the installed Go 0.5.14 binary and reproduced by our encoder —
see *Proof*.

Our implementation: `src/handshake.rs` (`Meta::encode`, `Meta::decode`,
`keyed_hash`).

## Layout

```
"meta" (4B) || size BE16 (2B) || TLV fields || signature (64B)
```

| offset | bytes | field |
|-------:|------:|-------|
| 0 | 4 | magic `6d 65 74 61` = `"meta"` |
| 4 | 2 | `size` — big-endian, body length **after** these 6 bytes |
| 6 | 4+2 | TLV: tag `0000` major, len `0002`, value |
| 12 | 4+2 | TLV: tag `0001` minor, len `0002`, value |
| 18 | 4+32 | TLV: tag `0002` node public key, len `0020`, value |
| 54 | 4+1 | TLV: tag `0003` priority, len `0001`, value |
| 59 | 64 | ed25519 signature |

Go writes the fields in exactly this order (`version.go:64-78`) and patches
`size` last, over the placeholder `00 00` (`:62`, `:94`). Total for a bare Go
peer: 6 + 6 + 6 + 36 + 5 + 64 = **123 bytes**, `size` = 117.

- A TLV is `tag BE16 || len BE16 || value`. No other integer in this message
  is big-endian — the envelope uses uvarints, `meta` does not.
- Tags are the `iota` order in `version.go:34-38`. Once released a tag is
  never renumbered or reordered; Go only ever adds new ones
  (`version.go:31-32` says so explicitly).
- The decoder ignores a tag it does not know (`version.go:126-150` has no
  `default` arm), which is how our extra vendor/features tags coexist with Go
  (see *Roots extensions*).
- A known tag with the wrong value length is `ErrHandshakeInvalidLength`
  (`:128-149`). A whole message whose `size` is below 64 is rejected before any
  TLV is read (`:109-111`), as is trailing garbage after the last complete TLV
  (`:153-155`).

## Signature and password

The signature is **not over the message**. It is over a keyed hash of the
public key:

```
hash = blake2b-512(key = password, data = public_key)
sig  = ed25519.Sign(local_private_key, hash)
```

(`version.go:80-92` for the writer, `:157-168` for the verifier, which uses the
*remote* public key from the TLV as both the verification key and the hash
input.) Consequences:

- The signer must hold the private key that matches the advertised public key,
  so a peer cannot claim a key it cannot sign with.
- A wrong password is indistinguishable from a bad signature: Go reports
  `ErrHandshakeIncorrectPassword` ("password does not match remote side"), and
  we report `Error::BadPassword`. A `meta` with no public-key TLV fails the
  same way, not as a parse error, because the default all-zero key verifies
  against nothing.
- `blake2b.New512(password)` with an empty or nil key is the plain unkeyed
  hash, so an unset password and `password=` interoperate with a peer that
  sends no password at all. Our `keyed_hash` takes an explicit unkeyed branch
  to match, and the unkeyed capture below proves it.
- The password comes from the link URI query, `?password=…`, on either the
  `Listen` or the `Peer` entry (`link.go:200-205`, `:492-496`). It is a
  per-link secret, unrelated to `Interface.GroupPassword`, which is
  session-layer.

## Version check

`size` and the TLVs are parsed before the version is judged. After the
signature verifies, Go calls `check()` (`version.go:173-184`): `major` must
equal `ProtocolVersionMajor` (0) and `minor` must equal
`ProtocolVersionMinor` (5) exactly — no range, no "greater-or-equal". A node
that advertises 0.6 is refused with "remote node incompatible version (local
0.5, remote 0.6)" (`link.go:650-652`). Our constants are
`handshake::PROTOCOL_MAJOR` / `PROTOCOL_MINOR`; `Meta::check` mirrors the
equality test and returns `Error::BadVersion(major, minor)`.

## Flow

From `link.go:628-675`, on both dial and accept, in this order:

1. Build `meta` from our own public key plus `options.priority`, encode it with
   our node secret and the link password.
2. Set a **6-second deadline** covering the whole exchange (`:635`), then write
   the bytes (`:638`). No framing, no length prefix on the socket beyond the
   in-message `size`.
3. Decode the remote's `meta` from the stream (`:647`) — Go reads the 6-byte
   header, then exactly `size` bytes (`version.go:100-115`).
4. `check()` the version (`:650`).
5. Clear the deadline (`:657`). Everything after this point uses the frame
   envelope.
6. Reject a peer whose public key equals ours: `ErrLinkToSelf` (`:661-663`,
   "node cannot connect to self", `:158`). This is why dialing a listener with
   the listener's own keypair tears the link down immediately and quietly.
7. Optionally enforce the pinned-key list, `?key=<hex pubkey>` repeated per
   allowed key (`:666-672`; parsed at `link.go:179-190`), and for links that
   did not come from the loopback interface the `AllowedPublicKeys` config —
   which Go applies to **inbound** links only (`:674-689`).

The exchange is symmetric but not simultaneous-safe: each side writes first and
then blocks on the read, so the messages cross on the wire. Nothing in `meta`
negotiates; there is no challenge, no nonce, no key agreement. Session keys are
established later, in the encrypted session layer.

## Roots extensions

We advertise two extra TLVs that Go's decoder skips as unknown, and that our
decoder tolerates from a peer that sends them:

| tag | value length | meaning |
|----:|-------------:|---------|
| 4 | 5 (up to 32 accepted on read) | vendor string, `"roots"` |
| 5 | 4 | feature bitflags, big-endian |

(Defined in `src/peer.rs` as `TAG_VENDOR` / `TAG_FEATURES`; carried on `Meta`
as `vendor` / `features`.) They are appended after Go's four, so a roots
`meta` is 140 bytes with the same 6-byte header and the same trailing
signature. They are advisory: a peer's *kind* is derived from them
(`Meta::peer_kind`, `PeerKind::Go` when the vendor tag is absent), which lets
the client describe a mixed mesh, but no protocol behaviour changes on the basis
of them. `Meta::local_go` builds a message with neither tag, which is what a Go
0.5.14 peer sends — and what the vectors below are.

Tags 4 and 5 continue Go's `iota` block, which is the extension route
`version.go:31-32` sanctions ("it is only safe to add new ones"). **They are not
reserved.** If upstream yggdrasil-go adds its own tag 4 or 5 first, the numbers
collide: Go's decoder would apply its length check to our value and refuse the
link (`version.go:126-150` returns `ErrHandshakeInvalidLength` for a known tag
with the wrong length, and it does not skip a tag it does recognise). Nothing
in this repo prevents that, so a version bump of the reference submodules must
re-check these two numbers.

## Proof

- `tests/go_vectors.rs::go_meta_handshake_bytes_match_captured` holds two
  captured 123-byte messages from Go 0.5.14: one with no password, one with
  `?password=roots-capture`. For each, our encoder must produce **exactly**
  those bytes for the same key, and our decoder must read Go's own bytes back
  into major 0, minor 5, priority 0, that public key, no vendor/features tags,
  and `PeerKind::Go`.
- `go_meta_password_binds_the_signature` shows the two captures differ only in
  the trailing 64 bytes, and that each fails to verify under the other's
  password. The password is load-bearing, not decoration.
- Mutating `PROTOCOL_MINOR` to 6 fails both tests at the first differing byte
  (offset 15, the minor value), which is the check that the vectors constrain
  our code and not just themselves.
- `handshake.rs` unit tests cover what a single capture cannot: the
  password matrix (`""`/`"foo"` both directions), garbage frames, and vendor
  round-trip.

## Capture and re-capture

The vectors came from `examples/go_capture.rs`, run 2026-09-24 against
`/nix/store/3jrrg0hlz18ill7hq0liga4pg5mfgb3r-yggdrasil-0.5.14`. Two privileges
get in the way, and the harness handles both:

- The node always creates a TUN and **panics at startup if it may not**
  (`cmd/yggdrasil/main.go:282`), so a capture runs inside a private user+net
  namespace, where TUN creation succeeds and the host's `tun0` and `200::/7`
  route are untouched.
- A fresh netns has `lo` administratively down, so loopback connects fail
  `ENETUNREACH`; the harness runs `ip link set lo up` itself, which is exactly
  what its `CAP_NET_ADMIN` is for.

```
unshare -Un --map-root-user cargo run -q --example go_capture -- --frames
```

The harness writes a JSON config on stdin (`-useconf`), dials the listener with
a bare TCP socket, and asserts byte equality *before* it prints hex, so the
constants in the test are the oracle's output for a key we can re-sign with.
`--frames` completes the handshake as a second identity and dumps the raw
envelope bytes, which is where `10-envelope.md`'s examples come from.
`cargo test` never needs Go, the namespace, or the network.
