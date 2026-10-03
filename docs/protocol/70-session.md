# 70-session.md — the session layer

The session layer is the only part of the protocol that seals anything. Everything
above it is routing, everything below it is framing. One session per peer is opened
by exchanging two fixed-length messages, and after that every byte that peer sends
or receives is a NaCl box keyed on a pair only the two ends know.

Read the layering in Go in the order a packet travels, because getting it wrong is
the bug this repository shipped and measured. An application write goes to
`encrypted.PacketConn.WriteTo` (`reference/ironwood/encrypted/packetconn.go:66-84`),
which hands the blob to `sessions.writeTo` (`encrypted/session.go:142-152`); that
seals it under the existing session or buffers it behind a fresh `init`
(`:299-332`, `:154-178`); and the sealed message reaches
`network.PacketConn.WriteTo` (`reference/ironwood/network/packetconn.go:72-93`),
which fills in a `traffic` and calls `router.sendTraffic`. The order is therefore
**application → session → pathfinder → link**, with exactly one seal, applied to the
*destination's* session key before the route is chosen. Ours is `src/session.rs`;
`Router::net_send` (`:242-249`) is the whole of the downward half.

## The outer type byte

One byte at offset 0 of every session message, `sessionType*`
(`encrypted/session.go:27-32`), dispatched on by `handleData` (`:78-102`):

| value | name | meaning |
|------:|------|---------|
| 0 | `sessionTypeDummy` | an empty case arm, `:84` |
| 1 | `sessionTypeInit` | open or repair a session, `:85-90` |
| 2 | `sessionTypeAck` | the answer to an init, `:91-96` |
| 3 | `sessionTypeTraffic` | payload, `:97-98` |

Anything else falls into an empty `default` (`:99-100`). **There are four types, not
five**: an ack *is* an init with byte 0 patched (`sessionAck.encrypt`, `:561-567`),
and `sessionAckSize = sessionInitSize` (`:24`), so one layout covers both. There is
no `key` message; see *Rotation*.

## ed25519 → X25519

Everything on a link is keyed on ed25519; everything inside a session is a NaCl
box, which needs X25519. The conversion happens **once per node**, when the
PacketConn is built, not per message: `pc.secretBox = *pc.secretEd.toBox()`
(`encrypted/packetconn.go:43`), and `edPriv.toBox` is
`e2c.Ed25519PrivateKeyToCurve25519` (`encrypted/crypto.go:76-81`). The private side
is `sha512(seed)[..32]` as the X25519 scalar (`e2c.go:21-26`), clamped inside X25519
by `box.Precompute` (`crypto.go:116-118`); the public side is the Montgomery map
`u = (1+y)/(1−y)` (`e2c.go:28-55`). It exists so a session's *long-term* key can be
the node key, which is what binds a traffic frame's `source` to a box that opens:
the init seals to the recipient's `e2c` key and signs with the sender's ed key
(`session.go:483-520`). Ours is `src/session.rs:39-51`.

## `init` and `ack` — 193 bytes

The *seal* column is the offset inside the 144-byte plaintext; the seal's extra 16
bytes are the box overhead.

| offset | length | in the seal | field |
|--------|-------:|------------:|-------|
| 0 | 1 | | type: `01` init, `02` ack |
| 1 | 32 | | `fromPub` — the sender's **ephemeral** box keypair, discarded after this message |
| 33 | 160 | | `box.Seal`, nonce **0**, opened with `DH(e2c(recipient), fromPriv)` |
| 33 | 64 | 0 | ed25519 signature by the sender's long-term key |
| 97 | 32 | 64 | `current` — the key the sender receives on |
| 129 | 32 | 96 | `next` — the key the sender will switch to |
| 161 | 8 | 128 | `keySeq` — big-endian, the sender's local key sequence |
| 169 | 8 | 136 | `seq` — big-endian, strictly increasing per sender |

The signature covers `fromPub ‖ current ‖ next ‖ keySeq ‖ seq` — the ephemeral key
prepended to the plaintext minus the signature itself (Go `:490-502`, `:547-550`;
ours `sig_bytes`, `src/session.rs:86-94`). Go's own `GO_INIT`, A → B with
`keySeq = 3`:

```
type 01
eph  26ba02e793077cc6eae80d427a5551ef09a1671f490d922b9f014984ef96ca67
seal b554d46a178f6df3fc6d4d47ba55107174a1510c3fdbf7b947f24c1ee940585e43e3ad78bceee3efea03eed31620167d7227cff2cecaf1589b1321e2de41e08b6a1959446d9c4a3a15c4ead208c684f29119460a0fc616f002e01fb6337d66c54ecbe0e0acb52eadd36c069e8ebf0b718e8d5987cdcb86b3051d73cb8eab5e43b9e66c162035d3cec5429a43172c39a018fd3a78d6b9608de4bbef106aadee32
```

`go_init_decrypts_with_b_key` (`src/session.rs:739-748`) opens it with `E2C_PRIVB`,
asserts `key_seq == 3`, and requires it to *fail* under the sender's own key.
`E2C_PUBA`/`E2C_PUBB`/`E2C_PRIVB` (`:709-711`) are the Montgomery forms of
`PUBA`/`PUBB`, so the vector and the map are pinned by the same constants. **These
bytes are transcribed from a local Go generator, not captured from the binary.**

Two fields carry the state machine. **`seq`** is a replay guard and nothing more: Go
sets it to `uint64(time.Now().Unix())` (`:474-481`) and both ends refuse an init or
ack whose `seq` is not strictly greater (`:265-267`, `:276-278`). **`keySeq`** is how
the ends agree which generation each other's keys are from: every `_handleUpdate`
bumps the receiver's `localKeySeq` (`:293`) and adopts the sender's as `remoteKeySeq`
(`:288`), and both then ride in **every traffic frame**. A fresh session has both at
zero.

**`ack`** is byte-identical apart from byte 0. It carries the *responder's*
post-update `sendPub`, `nextPub`, `localKeySeq` and a fresh `seq` — `_sendAck` runs
after `_handleUpdate` has already advanced the keys (`:268-270`, `:457-461`), so an
ack's `keySeq` is one higher than the init's. It acknowledges no packet: no echo of
the init's `seq`, no counters, nothing to retry. It is the responder's half of the
key agreement. An ack for a session we do not have is handled **as an init**
(`_handleAck`'s `isOld` test, `:113-125`); ours does the same and flushes any
buffered payload in the same breath (`src/session.rs:270-294`).

## Rotation, and the message that does not exist

**There is no `key` message.** The pinned `reference/ironwood` declares four session
types and no fifth, and `sessionTypeKey` appears nowhere in either reference
submodule. What the wire table calls "session `key` (rotation)" is rotation
*state*, and it travels two ways. **Silently, on nonce wraparound:** `doSend`
increments `sendNonce` before anything else and, if it wrapped to zero, swaps in the
`next` keys, bumps `localKeySeq` and recomputes the shared secrets — with no message
at all (`:303-311`; ours `src/session.rs:587-598`). The peer learns of it from the
*next traffic frame's* first uvarint, which is why that header carries both key
sequences. **In an `init`, carrying a non-zero `keySeq`:** `_sendInit` (`:452-455`)
builds exactly the message above with `localKeySeq` in that field, and is reached
when the far end sends something that cannot be opened at all.

The receiving half is `doRecv`'s `fromNext` arms (`:375-424`): a traffic frame whose
first uvarint is `remoteKeySeq + 1` is opened with the precomputed *next* secret, its
inner 32-byte key is adopted as the new `next`, `remoteKeySeq` is incremented, the
local keys ratchet forward, and `info.rotated` is stamped so it happens at most once
a minute (`:383-397`). Ours is `Session::maybe_rotate` (`src/session.rs:678-699`).
Four shared secrets are precomputed per session, not two — `recv`, `send`,
`next`-as-send, `next`-as-receive (`_fixShared`, `:241-248`; ours `shared4`,
`:172-189`) — because the receiver cannot know which way the peer ratcheted.

## `traffic` — 52 bytes minimum

| offset | length | field |
|--------|-------:|-------|
| 0 | 1 | `03` = `sessionTypeTraffic` |
| 1 | uvarint | the sender's `localKeySeq` |
| … | uvarint | the sender's `remoteKeySeq` |
| … | uvarint | `sendNonce` |
| … | rest | `box.Seal` of `nextPub(32) ‖ plaintext`, nonce = `sendNonce` |

52 is the floor because `sessionTrafficOverheadMin` (`:21`) assumes all three
uvarints are one byte; Go's working figure is 79, adding three maximal 9-byte
uvarints (`:22`), and `MTU()` subtracts it (`:87-89`). Two traps. The header's
**first** uvarint is the sender's `localKeySeq` and the reader calls it
`remoteKeySeq` (`:316-318` against `:343-344`) — both right, from opposite ends. And
`nextPub` is inside the box, so a peer's next send key never appears in the clear
(`:320-321`). The nonce is the counter in the **last 8 bytes of a 24-byte**
big-endian nonce (`crypto.go:133-138`).

## The second type byte, and the bug it caused

The session layer's own type byte is `3`. **Inside** the box is a *different*
one-byte enum, and it is yggdrasil's, not ironwood's: `typeSessionTraffic` = 1,
`typeSessionProto` = 2, from an `iota` after a dummy 0
(`reference/yggdrasil-go/src/core/types.go:4-8`). `Core.WriteTo` prepends it to the
**plaintext** before handing anything down (`src/core/core.go:210-216`), and
`Core.ReadFrom` dispatches on it and `continue`s on anything else
(`core.go:187-198`) — silently, with no counter movement and no log.

**Exactly one layer adds that byte.** Ours adds it in `session_send_inner`
(`src/session.rs:381-383`), which every send path funnels through, so
double-wrapping is impossible by construction; and the buffered payload carries the
kind byte beside the bytes (`SessionBuf.data`, `:209`), because a nodeinfo request
queued before the session exists must still be framed as proto when it is flushed.
Our `send_or_resolve` originally reached past the session layer straight into
`pathfinder_send`, so a TUN packet left unboxed and untyped: the frame went on the
wire, the counters moved, and the far end dropped it. Measured as 100% ICMP loss
over a link `up: true` on both ends (`src/driver.rs:235-242`, fix `53c6d36`). Two
things were missing at once and either alone is fatal.

## The pre-session buffer is one slot

`sessionBuffer` holds a data payload, the pending `init`, the two ephemeral private
keys and a timer (`session.go:573-579`). `_bufferAndInit` assigns `buf.data = msg`
with no length check (`:167`) — **last write wins**, so a second payload to the same
unknown peer overwrites the first and only the newest is ever flushed. One slot per
destination is deliberate: a session must open before anything can be sealed, and the
alternative is a queue growing without bound against a peer that may never answer.
Ours is the same shape (`src/session.rs:203-211`), keyed by peer key, with a
60-second deadline pruned in `expire_ephemeral` (`src/driver.rs:352`). A buffer that
outlives its session re-adopts its keys: on an init from a peer we have no session
for we take the buffered initiator's keys and rebuild every shared secret
(`_sessionForInit`, `:61-76`; ours `adopt_buffered`, `src/session.rs:523-535`).

## A failed decrypt does not drop the session

Go never deletes a session on a failed open. Both failure paths in `doRecv` send a
fresh `init` and return: the `default` arm when the two key sequences cannot be
reconciled (`:425-429`), and the `boxOpen` failure (`:443-448`, commented "Keys
somehow became out-of-sync — this seems to happen in some edge cases if a node
restarts"). `_sendInit` advertises the sender's *current* send keys, so the peer's
`handleInit` runs a normal `_handleUpdate` and both ends are back in step. Ours is
the same (`src/session.rs:341-345`), and it matters for interop: a node that
restarts mid-session recovers on the next message instead of needing a new peer.

A third, different repair: traffic from a peer with **no** session gets a throwaway
init — two fresh keypairs that are not stored (`_handleTraffic`, `:127-140`), with
Go's own reason: "We don't know that the node really exists, it could be
spoofed/replay, so we don't want to save session or a buffer based on this node." If
the peer is real it acks and the exchange self-heals (`src/session.rs:347-360`).
Sessions and buffers both expire after one minute (`session.go:20`, `:250-261`; ours
`SESSION_TIMEOUT`, swept in `src/driver.rs:353-355`).

## Deviations from Go

- **No group password.** Go folds `groupAuth.preimage()` — SHA-256 of
  `"ironwood/encrypted\x00"` plus the password (`crypto.go:149-157`) — into the
  session signature preimage (`crypto.go:47-63`, called at `session.go:502`), so
  `GroupPassword` gates traffic as well as links. Ours signs `sig_bytes` with no
  preimage (`src/session.rs:107`) and `client/src/config.rs:306-307` says
  `GroupPassword` is deliberately not wired, so a node configured with one will not
  verify our init or ack. This is the largest gap on the page, acknowledged and not
  measured.
- **`seq` is a counter, not a clock** — `max(now+1, last+1)`
  (`src/router.rs:82-93`), which satisfies the same rule and survives a clock
  behind.
- **A resend queue Go has no equivalent for**: app payloads whose write failed
  mid-link are retried, at-least-once, on the next link (`src/session.rs:222`). A
  payload lost to a dead link is a Go bug we fixed, not a format change.
- **No MTU accounting.** Go reserves `sessionTrafficOverhead` against the link MTU
  (`encrypted/packetconn.go:76`, `:87-89`); ours reserves `frame::MAX_MESSAGE_SIZE`.

## Provenance

| what | from |
|------|------|
| the four session types, the 193-byte init, the 52-byte traffic floor, the four shared secrets, the `_handleUpdate` key dance | Go source read line by line against `encrypted/session.go` and `crypto.go`. **Nothing on this page has been seen from the Go binary**, and nothing about the session layer appears in `tests/go_vectors.rs` |
| the `GO_INIT` vector, 193 bytes, `keySeq = 3` | **transcribed** from a local Go generator (`TestZZVectors`, whose harness is gone), *not* captured from the installed Go 0.5.14 binary. `go_init_decrypts_with_b_key` (`src/session.rs:739-748`) opens it with the right key, asserts `key_seq == 3`, and requires failure under the wrong one |
| the preimage `fromPub ‖ current ‖ next ‖ keySeq ‖ seq` | Go source (`:490-502`, `:547-550`); the vector verifies only in that order, and `tampered_init_rejected` (`:789-809`, one flipped bit at offset 40) is the check |
| the ed25519→X25519 map | **Go source**, `e2c.go:21-55`, pinned by constants from a Go generator rather than by bytes: `e2c_pub_matches_go` (`:723-726`), `e2c_priv_is_sha512_seed_prefix` (`:729-736`). `E2C_PUBA`/`E2C_PUBB`/`E2C_PRIVB` (`:709-711`) are transcribed |
| the in-band type bytes 1 and 2 | **Go source**, `src/core/types.go:4-8`, asserted by `packet_type_constants_match_go` (`src/proto.rs:405-409`) and `packet_type_constants_match_go_core_types` (`src/session.rs:812-820`), the latter also asserting that 1 and 2 are *not* the session's own `3`. No bytes behind them |
| **`ack`** | **round-trip only.** `session_handshake_roundtrip` (`src/session.rs:751-786`) builds an ack, decodes it and runs traffic both ways. No captured bytes, and nothing pins an ack's `keySeq` to Go's post-increment value |
| **rotation, and the `key` field's only carrier** | **no test at all.** `Session::maybe_rotate` (`src/session.rs:678-699`) is never reached: no test drives a nonce wraparound, a `remoteKeySeq + 1` traffic frame, or a repair init. `keySeq` is asserted exactly once, as the literal 3 in the transcribed init |
| the traffic layout and the field-order trap | Go source (`:314-318` against `:343-344`). No traffic frame has been captured from Go; `tests/mesh3.rs` and `tests/resolve_queue.rs` exercise ours end to end and would pass with the three uvarints in any order both ends agreed on |
| the decrypt-failure repair and the unknown-peer throwaway init | Go source (`:425-429`, `:443-448`, `:127-140`). Both are a silence plus a message we would have to answer with Go to observe; `tests/mesh3.rs` drops a link, which is the link layer, not this |
| the single-slot pre-session buffer | Go source (`:154-178`, last write wins at `:167`). `tests/resolve_queue.rs` covers the queued-and-flushed path on our side; Go's overwrite-the-payload behaviour has no test on either side |
| the missing group-password preimage | Go source (`crypto.go:47-63`, `session.go:502`) against ours. Unmeasured: no capture, no test, and no plan slice owns it |
| the 100% loss regression | measured, both directions, by `proof/10-tun.sh`; the mechanism is Go source (`encrypted/packetconn.go:66-84` → `network/packetconn.go:72-93` → `src/core/core.go:187-216`) |
