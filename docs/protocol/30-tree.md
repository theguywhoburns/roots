# 30-tree.md — the tree payloads

`SigReq`, `SigRes` and `Announce` are how two nodes authenticate each other in
the tree: a node asks a peer to vouch for it, the peer answers with a signature
over that exact request, and the answer is what the *next* hop publishes. The
point of the whole shape is that the signature covers the request, so a
signature cannot be replayed onto a different one.

All three are carried as `FrameType` payloads, so the envelope is
[10-envelope.md](10-envelope.md) and this page is the payload only.

Every byte string below was **captured from the installed Go 0.5.14 binary** by
`examples/go_capture.rs --frames` and is checked by
`go_tree_payloads_match_captured` in `tests/go_vectors.rs`. The oracle's key is
the seed `[0x5c; 32]`, so `key = parent = ed6a47a3…`; the harness dials as
`[0x2b; 32]`, which is the other half of the `SigRes` preimage.

## `SigReq` — ask a peer to vouch for you

| offset | length | field |
|--------|--------|-------|
| 0 | uvarint | `seq` — the sender's `nextReq` counter |
| 0 | uvarint | `nonce` — random, and reused across retries |

Both are uvarints and nothing follows. Captured:

```
02 f4 a6 df c4 95 bd be b4 f6 01        seq = 2, nonce = 10 bytes on the wire
```

`seq` is `r.infos[ourKey].seq + 1` — the sender's own line to the root, so it
starts at 1 for a node that has just become root, and increments as the tree
settles (`network/router.go:381-390`). The nonce is eight random bytes read as
a big-endian `uint64` (`:383-384`), so it is *at most* ten bytes as a uvarint
and only reaches that when the top bit is set — as it is here. That is the
reason the test reads this value off the wire instead of writing a literal: a
hand-typed `u64` constant would be silently truncated and still compile.

The nonce exists so that two nodes with the same `seq` — which happens, since
both start at 1 — do not produce the same signed request.

**A repeated `(node, seq, nonce)` is dropped, not answered.** Go caches what it
has already signed (`peers.sigCache`), so re-sending a request the peer has seen
gets silence. That is why `examples/go_capture.rs` sends `seq: 1` — the oracle's
own next value — and gets exactly one `SigRes`.

Go: `network/router.go:381-390` (`_newReq`), `:140`/`:195` (`sendSigReq`).
Ours: `tree.rs` `SigReq`.

## `SigRes` — the vouch

| offset | length | field |
|--------|--------|-------|
| 0 | uvarint | `seq` — echoed from the request |
| … | uvarint | `nonce` — echoed from the request |
| … | uvarint | `port` — the **requester's** port |
| … | 64 | `psig` — ed25519 over the preimage below |

The `seq`/`nonce` pair comes back **verbatim**, not re-signed against our own
counter. That is the replay defence: a `SigRes` is only ever valid for the
request it answers, so it cannot be attached to a different one.

`port` is the port of the **peer the request arrived on**, not the responder's.
This is the field people get backwards, and it is why the signature covers it —
a peer that changes its port invalidates every `SigRes` it has already issued
about itself. Go: `network/router.go:409-416`.

### The preimage

```
node   ‖ parent  ‖ seq ‖ nonce ‖ port
32 B     32 B      uvarint  uvarint  uvarint
```

`node` is the **requester's** key and `parent` the **responder's**, which is
counter-intuitive: the responder signs with its own key, over a preimage that
starts with the requester's. A `SigRes` carried in an `Announce` is therefore
about the announcer as the *parent*, which is why a node with no upstream
answers its own `SigReq` and gets `key == parent`.

Go: `routerSigRes.bytesForSig` at `network/router.go:863-867`, delegating to
`routerSigReq.bytesForSig` at `:799-805`, called with
`(p.key, r.core.crypto.publicKey)` at `:414`. Ours: `tree.rs`
`SigRes::bytes_for_sig` and `SigRes::check`.

## `Announce` — publish what you know

| offset | length | field |
|--------|--------|-------|
| 0 | 32 | `key` — the node being announced |
| 32 | 32 | `parent` — its parent in the tree |
| 64 | … | `res` — a `SigRes` **about `key`** |
| … | 64 | `sig` — ed25519 over `res`'s preimage, by `key` |

So an `Announce` is a `SigRes` with a name attached. `res` uses the same layout
as above, so the preimage both signatures cover is
`key ‖ parent ‖ res.seq ‖ res.nonce ‖ res.port` — the outer `sig` is by `key`
and the inner `psig` by `parent`.

A lone node's first announce is the degenerate case where `key == parent`, and Go
does not compute the outer signature separately: `_becomeRoot` literally sets
`sig: res.psig`, because the same key signed the same preimage
(`network/router.go:391-400`). The captured bytes are therefore:

```
key    = ed6a47a3…   parent = ed6a47a3…   res.port = 0
res.seq = 1   res.nonce = 0x193b1f6e39d8cc7c2ae
sig == psig
```

`res.port = 0` is required in that shape, and Go's `// TODO? something else?` on
that line is the honest annotation: `Announce::check` rejects a `port` of 0 unless
`key == parent`, because a port of zero means "no link to vouch for" and a node
with an upstream *does* have one. Ours is Go's check.

## What an announce does *not* carry

**Only ancestry.** `_sendAnnounces` walks the ancestry of self plus the ancestry
of one peer, never the whole table (`ironwood/network/router.go:320-378`). So
`known_nodes()` is not network size, and in a line A—B—C the two ends
legitimately never learn each other from the tree — they resolve each other
through the DHT, or not at all. Pinned by `tests/mesh3.rs` phase 1.

## The frames, raw

Captured on one link, in the order Go sent them: `SigReq`, `BloomFilter`,
`SigRes` (our answer to the `SigReq` we sent), `Announce`. The
`SigRes` envelope is
`44 03` = length 0x44‖2-bit-continued = 67, then `03` = `FrameType::SigRes`,
then 67 bytes of payload.

## Provenance

| what | from |
|------|------|
| all three payloads, both signatures verified | captured, Go 0.5.14, `tests/go_vectors.rs` |
| the `psig` preimage order | captured **and** checked — the vector only verifies with `node ‖ parent ‖ req ‖ port` in that order, and the test also asserts it does *not* verify with Go's key on both sides |
| `port` is the requester's | captured, and the value is 1, which is the port the harness's own link was given |
| the only announce shape available | captured: a Go node with one peer is a root, so `key == parent`, `port == 0` and `sig == psig`. **An announce from a node with an upstream has not been captured**, and its non-zero `port` and a separately-computed `sig` are the only things that would differ |
| `sigCache` dropping a repeated request | Go source, `network/peers.go` — a silence, so nothing captures it |
| the 10-byte nonce | captured, and Go's `uint64` source is what makes it plausible rather than a bug |
