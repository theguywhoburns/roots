# 60-traffic.md — the Traffic frame

`wireTraffic` is the only frame that carries data, and it is also the frame that
carries the pathfinder's own decisions: two coordinate lists, two keys and a
watermark wrapped around an opaque payload. Type `0x09` in the envelope, so
[10-envelope.md](10-envelope.md) is the framing and this page is the payload.
Go: `traffic` at `reference/ironwood/network/traffic.go:9-16`, with
`size`/`encode`/`decode` at `:26-69` and the discriminant at
`reference/ironwood/network/wire.go:17`. Ours is `src/traffic.rs`.

**The vector is transcribed, not captured.** It comes from the same local Go
generator as the pathfinder vectors on [40-path.md](40-path.md) — `TestZZVectors`,
a patch on a private ironwood copy, since gone — not from the installed Go 0.5.14
binary. Nothing about `wireTraffic` appears in `tests/go_vectors.rs`.

## Layout

74 bytes, with `path = [4, 2]`, `from = [3, 1]`, `watermark = 77`:

```
0402000301008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c4d090807
```

| offset | length | field | bytes in the vector |
|-------:|-------:|-------|--------------------|
| 0 | var | `path` — the coords of the **destination**, zero-terminated | `04 02 00` = `[4, 2]`, `0` |
| 3 | var | `from` — the coords of the **originator**, zero-terminated | `03 01 00` = `[3, 1]`, `0` |
| 6 | 32 | `source` — the originator's full key | `8139770e…c9b394` |
| 38 | 32 | `dest` — the final destination's full key | `8a88e3dd…f6f5c` |
| 70 | uvarint | `watermark` — the best distance to `path` any hop has seen | `4d` = 77 |
| 71 | rest | `payload` — see *There is no per-path box* | `09 08 07` = `[9, 8, 7]` |

Both paths are zero-terminated uvarint lists, encoded by the same
`wireAppendPath` as the pathfinder's ([40-path.md](40-path.md)). The payload has
**no length prefix**: `decode` takes everything left (`traffic.go:66`), so the
envelope's declared size is the only framing. Two `peerPort` lists plus two keys
plus a maximal watermark is 76 bytes, which is the overhead Go reserves for the
MTU — and its reservation assumes *both* paths are empty, with an upstream `TODO`
saying exactly that (`network/packetconn.go:190-196`). We do not mirror that
MTU computation; ours is `frame::MAX_MESSAGE_SIZE`.

The stale `// *not* zero terminated` on `path.path` (`traffic.go:10`) is discussed
on the pathfinder page. It is a comment about the in-memory slice; the codec
always writes the terminator.

## `path` and `from`: one is the way out, one is the way home

They are not redundant, and the names are the only thing distinguishing them.

- **`path`** is the route to the destination — the coords the sender learned from
  a `PathNotify`, or its own tree path. It is what every hop chases: `greedy_next`
  picks the connection that is strictly closer to it, and a hop that cannot find
  one has reached the end of the route.
- **`from`** is the originator's own position in the tree, written once at
  `_handleTraffic` on the send side (`pathfinder.go:194-224`; ours
  `Router::pathfinder_send`, `src/pathfind.rs:596-624`) and never touched again.
  Its only reader is the failure path: a hop that cannot forward builds a
  `PathBroken` out of `tr.from` (`pathfinder.go:226-234`; ours
  `src/traffic.rs:78-84`), which is how the report gets back to the node that
  actually owns the stale path rather than to the last hop that saw the frame.

So a frame needs `path` to be routed and `from` to be *complained about*, and a
forwarder rewrites only the watermark, which is why `from` can stay constant
across a whole route. Neither field is encrypted, and neither is authenticated:
they are routing hints, which is exactly what the upstream comment about a lying
parent ([40-path.md](40-path.md), `router.go:23-24`) is about.

`source` and `dest` are likewise never rewritten. `source` is the key the
destination needs in order to decrypt, and it is the address the far end
attributes the delivery to (`network/packetconn.go:65-66`, `:203`).

## There is no per-path box

**The payload is not sealed per path element. It is the session message.** This
is the single most misread fact in the format, and it cost this repository a
100% ICMP loss over a link that was `up: true` on both ends.

The layering is application → session → pathfinder → link, and only the session
layer seals. Read it in Go in the order a packet travels: an application write
goes to `encrypted.PacketConn.WriteTo` (`reference/ironwood/encrypted/packetconn.go:66-84`),
which hands the blob to `sessions.writeTo`; that builds the session header,
`boxSeal`s `nextPub ‖ msg` and calls down to `network.PacketConn.WriteTo`
(`reference/ironwood/network/packetconn.go:72-93`), which fills in a `traffic` and
calls `router.sendTraffic`. One seal, to the *destination's* session key, before
the route is chosen — and nothing seals `path`, `from`, `source`, `dest` or the
watermark.

Two different one-byte enums are involved, and confusing them is how the bug
happened. The session layer's own type byte is `sessionTypeTraffic` = 3, written
outside the box as part of the header (`encrypted/session.go:27-32`, `:312-325`).
*Inside* the box, the first plaintext byte is yggdrasil's in-band type,
`typeSessionTraffic` = 1 or `typeSessionProto` = 2, prepended by `Core.WriteTo`
(`reference/yggdrasil-go/src/core/core.go:210-216`, `:187-198`, constants at
`reference/yggdrasil-go/src/core/types.go:4-8`). Anything else is dropped in
silence. So an application payload has to be sealed *and* typed, and getting
either one wrong is fatal on its own.

Our `send_or_resolve` reached straight past the session layer into
`pathfinder_send`, so a TUN packet left unboxed and untyped, the frame went on the
wire, the counters moved, and the far end's `handle_session_bytes` discarded it:
100% ICMP loss, measured, over a healthy link (`src/driver.rs:235-242`,
`AGENTS.md`, fix `53c6d36`, `docs/plans/go-client-parity/04-slices.md:636-642`).
The test that should have caught it read plaintext off a wire tap, which no
working mesh ever sends.

## Forwarding

`handle_inbound_traffic` is a three-way branch, and the order matters
(`src/traffic.rs:61-85`; Go `router.handleTraffic`, `router.go:592-605`):

1. **Forward a hop.** If `greedy_next` finds a connection strictly closer to
   `tr.path`, encode and write to it, with the watermark updated, and return. A
   node does not need to know the payload to forward it, and does not look at it.
2. **Deliver to us.** Otherwise, if `tr.dest == our key`, hand `tr.payload` to the
   session layer with `tr.source` as the sender. Go additionally refreshes the
   path timeout here (`router.go:597`, `_resetTimeout` at `pathfinder.go:259-266`).
3. **Report it broken.** Otherwise we are a hop that has run out of route: build a
   `PathBroken` from `tr.from`, `tr.source`, `tr.dest` and hand it to
   `handle_broken`, which routes it back to the originator and marks the path
   broken over there.

`greedy_next` (`src/pathfind.rs:280-345`; Go `router._lookup`,
`router.go:685-758`) is the only thing that decides hop *n+1*. It compares
coordinate prefixes — `len(keyPath) + len(destPath) − 2 × common prefix` — first
to find every peer that is strictly closer at all, which is what makes the next
hops loop-free, and then picks the best of those by `cost × distance`. It returns
a link, not a key, because the candidate set is one entry per connection
(`router.go:702-707`).

## The watermark

One `u64`, written by every hop, and it means "the smallest distance to `path`
that any hop on this route has already seen". `_lookup` opens by comparing *our*
distance against it and returning nothing if we are not strictly better
(`router.go:689-696`; ours `src/pathfind.rs:286-295`); otherwise it lowers the
watermark to our distance and passes the frame on with that value inside it.

Two consequences worth stating plainly:

- **Locally originated traffic starts at `u64::MAX`** — `tr.watermark =
  ^uint64(0)` in `network/packetconn.go:91`, ours at `src/pathfind.rs:614`, and
  again for the broken report at `src/traffic.rs:80`. It is a fresh frame, so
  there is no previous hop to beat.
- **That `u64::MAX` almost never reaches the wire**, because the very function
  that routes the frame lowers the watermark to our distance before encoding it.
  The exception is a node with no tree path of its own — `root_path()` is `None`,
  `src/pathfind.rs:287` — where the first pass is skipped and the field is written
  as it stands. So a first-hop frame carries a small distance, not a sentinel, and
  the vector's 77 is a hand-set value no live first hop produces;
  `tests/mesh3.rs` and `tests/resolve_queue.rs` are what cover the real value.

## Deviations from Go

- **When the path timer is refreshed.** Go refreshes the learned path on *any*
  inbound frame addressed to us, before the session layer touches the payload
  (`router.go:597`). Ours refreshes it inside the session's traffic arm and only
  after a successful decrypt (`src/session.rs:320-324`), which does mirror
  `_resetTimeout`'s `!info.broken` guard. A peer that only ever sends us session
  `init`s — nodeinfo, say — therefore ages out of our path table after
  `PATH_TIMEOUT` where Go would keep it.
- **The pre-session buffer.** Go caches the whole `traffic` struct against the
  path entry or the rumor (`pathfinderTrafficCache`, `pathfinder.go:194-224`) and
  replays it once a notify names the key. Ours holds only the payload, one slot
  per transformed key, and rebuilds the frame from the path it has just learned
  (`src/pathfind.rs:596-624`). One payload per destination is the point, and the
  slot is last-write-wins.
- **No MTU accounting for path length**, which upstream also does not do.

## Provenance

| what | from |
|------|------|
| the layout, the field order and the offsets | Go source read field by field against `traffic.go:26-69`; transcribed vector agrees |
| the vector, 74 bytes | transcribed from a local Go generator; `traffic_vector_matches_go` (`src/traffic.rs:95-104`) decodes it, asserts every field and requires byte equality on re-encode |
| **no per-path box**; the payload is a sealed session message | Go source end to end (`encrypted/packetconn.go:66-84` → `network/packetconn.go:72-93` → `encrypted/session.go:312-325`), plus our own regression (`src/driver.rs:235-242`). This is the one claim on the page with a real bug behind it, and no captured frame |
| both paths being zero-terminated | Go codec (`wire.go:80-86`) plus the vector |
| the payload having no length prefix | Go `traffic.go:66`; a captured frame would show it, so this is source-only |
| `from` never being rewritten, and only the broken report reading it | Go source (`pathfinder.go:226-234`, `router.go:592-605`). A forwarded frame is indistinguishable from a directly delivered one, so no capture can show it |
| the watermark's meaning and the `^uint64(0)` start | Go source (`router.go:689-696`, `network/packetconn.go:91`) and our comment at `src/views.rs:175-178`; **no test** asserts the value a real first hop writes |
| the three-way forward/deliver/broken branch | Go source; `tests/mesh3.rs` phase 3 fails if the transit write is deleted (see its own header), and `tests/resolve_queue.rs` covers delivery through a held payload |
| the path-timeout refresh difference | Go source against ours; a timing difference no test measures |
| the 77-byte MTU reservation ignoring path length | Go source and its own `TODO` (`network/packetconn.go:190-196`) |
