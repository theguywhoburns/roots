# 50-path.md — PathLookup, PathNotify, PathBroken

The pathfinder is the source-routing layer. Routing in a spanning tree is not
hop-by-hop: a sender picks a *coordinate* for the destination and then greedily
walks toward it, one connection at a time, until no connection left is strictly
closer. Three frames carry everything that is not data — a lookup, the answer to
one, and the report that a learned path has gone stale. All three are envelope
payloads, so [10-envelope.md](10-envelope.md) is the framing and this page is the
payload. Every layout was read field by field out of
`reference/ironwood/network/pathfinder.go` at the pinned revision (`d50055b`) and
against our `src/pathfind.rs`.

**All three vectors here are transcribed, not captured.** They come from a local
Go generator (`TestZZVectors`, a patch on a private ironwood copy — upstream
ships no `TestZZ*`, and `docs/plans/rust-client/00-status.md:43` records that
the harness is gone), not from the installed Go 0.5.14 binary, so they are one
step weaker evidence than the rows on [30-tree.md](30-tree.md). Nothing about
these three formats appears in `tests/go_vectors.rs`.

| frame | type | role | our type |
|-------|-----:|------|----------|
| `wireProtoPathLookup` | 0x06 | flooded along the tree by anyone who wants a path | `PathLookup` |
| `wireProtoPathNotify` | 0x07 | sent back along the requester's own coords | `PathNotify` |
| `wireProtoPathBroken` | 0x08 | sent back along the sender's own coords | `PathBroken` |

None is acknowledged and none has an envelope sequence number; each is re-sent by
every forwarding hop with its *watermark* rewritten. The watermark is not
integrity, it is loop prevention — the same field on a data frame is covered in
[50-traffic.md](50-traffic.md).

## The path encoding

A path is a `[]peerPort` and `peerPort` is a `uint64` (`peers.go:19`). On the
wire: LEB128 uvarints terminated by a `0`. `wireAppendPath` (`wire.go:80-86`)
writes each port with `wireAppendUint` and then unconditionally appends a `0`,
and `wireSizePath` (`:71-78`) budgets one more uvarint for it, which is why every
encoder's `end-start != size()` panic check balances. `wireDecodePath`
(`:88-102`) reads until it sees the `0` and returns the bytes consumed.

**The `// *not* zero terminated` comments at `traffic.go:10` and
`pathfinder.go:273` are stale.** They describe the in-memory struct; the codec
always appends the terminator and the reader always requires it. Our
`frame::append_path` / `frame::split_path` (`src/frame.rs:125-148`) mirror the
codec, and `src/traffic.rs` says so in its module header.

Port `0` is never allocated — `newPeer` starts at `for idx := 1; ; idx++`
(`peers.go:53-60`) — so the terminator cannot collide with a real port. It is
also the value a root advertises for itself (`port: 0`, `router.go:394`), which
is why `_getRootAndPath` stops before appending a root's self port ("it should
be zero anyway", `router.go:643-646`).

## Coordinates, not keys and not links

`_getRootAndPath(dest)` (`router.go:630-659`) walks `dest` → `parent` → …,
appending `info.port` per step, then reverses. `info.port` is not a port for a
connection to that node: it is the port the node's **parent** allocated for it,
carried down inside the `SigRes` that parent signed (`router.go:409-416`,
`routerSigRes` at `:852-867`). Read root-ward, element *i* is "the child of the
*i*-th node on this path that this parent numbered".

Ports are allocated per distinct remote key from 1 upward, and **two connections
to the same key share one port** (`peers.go:46-63`). So a path element names a
*node*: a node with several links is one coordinate rather than several, and
nothing on the wire enumerates or chooses those links. Which connection carries a
frame is a fresh per-hop decision (see `greedy_next` in
[50-traffic.md](50-traffic.md)). Distance is pure coordinate arithmetic —
`len(keyPath) + len(destPath) − 2 × common prefix` (`router.go:661-683`; ours
`coords_dist`, `src/pathfind.rs:263-270`) — and no key is ever resolved from a
port: Ironwood keeps `r.ports map[peerPort]publicKey` commented "used in tree
lookups" (`router.go:48`, written `:123`, deleted `:157`) and **never reads it**
in the pinned revision. The exposure is upstream's own, under a comment headed
"Potential showstopping issue (long term)": "Nothing prevents a node from
advertising the same port number to two different children" (`router.go:23-24`).

## `xkey`, and why the rendezvous is on a transform

`xkey(key)` is yggdrasil's DHT transform, `SubnetForKey(key).GetKey()` — ours in
two lines (`src/bloom.rs:264-267`), Go's as `WithBloomTransform(keyXform)` at
`reference/yggdrasil-go/src/core/core.go:95-101`, applied by `blooms.xKey`
(`reference/ironwood/network/bloomfilter.go:176-182`). Ironwood's own default is
the identity (`network/config.go:31`); the subnet transform is yggdrasil's
choice, and `Subnet.GetKey` → `Address.GetKey`
(`reference/yggdrasil-go/src/address/address.go:118-150`) is deliberately
**lossy** — it recovers only the key bits visible in the address and sets every
remaining bit to 1 (`key[idx] = ^key[idx]` over a zero array, `:138-140`).

That lossiness is the whole reason. For a routed `/64` the lookup carries a
*partial* key that no full key equals, so three things rendezvous on the
transform rather than the key: **who answers**, `xKey(lookup.dest) ==
xKey(self)` (`pathfinder.go:60-62`; ours `src/pathfind.rs:382`); **who it is
flooded toward**, `_sendMulticast` testing each on-tree peer's filter against
`xKey(toKey)` (`bloomfilter.go:301-317`; ours `src/bloom.rs:409`); and **whether
a notify is believed**, a notify from an unknown source being accepted only if
`pf.rumors[xKey(notify.source)]` exists (`pathfinder.go:121-124`; ours
`src/pathfind.rs:443-449`). The asymmetry that makes it work: `lookup.source` is
the requester's **full** key (`pathfinder.go:34-40`), so the notify is addressed
to a key the requester can be found at, while the requester filed its rumor under
`xKey` of the key it asked about and `notify.source` is the responder's full key.

## `PathLookup` — ask for a path

Three fields and nothing else. With `RPUB = 8a88e3dd…f6f5c` (asked about) and
`PPUB = 8139770e…c9b394` (asking), 67 bytes:

```
8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c030100
```

| offset | length | field | bytes in the vector |
|-------:|-------:|-------|--------------------|
| 0 | 32 | `source` — the requester's **full** key | `8139770e…c9b394` = `PPUB` |
| 32 | 32 | `dest` — the key asked about, possibly lossy | `8a88e3dd…f6f5c` = `RPUB` |
| 64 | 3 | `from` — the requester's coords, zero-terminated | `03 01 00` = `[3, 1]`, `0` |

Guarded by `lookup_vector_matches_go` (`src/pathfind.rs:656-665`): decode, assert
each field, re-encode, require byte equality. Go: `pathLookup` at
`pathfinder.go:295-348`, `_sendLookup` at `:27-42`. A lookup addresses no link at
all — it floods over the bloom filters of on-tree nodes and names itself as the
source (`src/pathfind.rs:352-363`), throttled by `pathThrottle`, which we set to
one second (`PATH_THROTTLE`, `src/pathfind.rs:55`).

## `PathNotify` — the answer, and the only signed one

149 bytes, `info.seq = 1234567890` (a five-byte uvarint), `info.path = [4, 2]`:

```
030100ffffffffffffffffff018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394d285d8cc04040200a9b666a872fc3894af2435bf21e124680234a3df4e0db8747b7e9b99b3908d47bad956fe0400131c102b601d925aca1ed8f98739c3297ba051e8e28264537b04
```

| offset | length | field | bytes in the vector |
|-------:|-------:|-------|--------------------|
| 0 | 3 | `path` — the **requester's** coords, echoed, to route the reply back | `03 01 00` = `[3, 1]`, `0` |
| 3 | 10 | `watermark` — loop guard on that return route | `ffffffffffffffffff01` = `^uint64(0)`, as every locally constructed frame starts |
| 13 | 32 | `source` — the answering node's **full** key | `8a88e3dd…f6f5c` = `RPUB` |
| 45 | 32 | `dest` — the requester's full key, from `lookup.source` | `8139770e…c9b394` = `PPUB` |
| 77 | 5 | `info.seq` — seconds since the Unix epoch | `d285d8cc04` = 1234567890 |
| 82 | 3 | `info.path` — the **answering node's** own coords | `04 02 00` = `[4, 2]`, `0` |
| 85 | 64 | `info.sig` — ed25519 by `source` | `a9b666a8…537b04` |

Two paths, and which is which is the field people get backwards: `path` is the
return route, `info.path` is the route the requester will use for its traffic, and
they come from different keys (`pathfinder.go:66-75`). The reply is therefore
routed by `r._lookup(notify.path, &notify.watermark)` (`pathfinder.go:94`) — by
the frame's own path, not by the link it arrived on; Go's `_handleNotify` takes a
`fromKey` and never reads it.

### The preimage, and what `check()` verifies

```
info.seq ‖ info.path
uvarint    zero-terminated ports
```

`bytesForSig` is `wireAppendUint(seq)` then `wireAppendPath(path)` and nothing
else (`pathfinder.go:375-380`; ours `NotifyInfo::bytes_for_sig`,
`src/pathfind.rs:113-118`), and `check()` verifies it with `notify.source` as the
key (`pathfinder.go:433-435`; ours `src/pathfind.rs:124-133`, `:165-167`). Note
what is **not** covered: the outer `path`, the watermark and `dest`. A notify can
be re-pointed at another destination or re-routed without invalidating the
signature — which is the point, since every hop rewrites the first two.

Two accept rules, both drops rather than errors. For a known source: accept only
if `info.seq > stored seq` **and** `info.path` differs from the stored path
(`pathfinder.go:105-118`; ours `src/pathfind.rs:425-441`) — an unchanged path at
a new second is not worth a signature, which is what stops a busy node
re-signing. For an unknown source: only if the rumor exists under
`xKey(notify.source)` (`pathfinder.go:121-127`). `seq` is
`uint64(time.Now().Unix())` (`pathfinder.go:72`), one-second granularity and not
a counter, and the signature is recomputed only when `seq` or path actually
changed (`pathfinder.go:76-82`; ours `src/pathfind.rs:391-396`).

Guarded by `notify_vector_matches_go` (`src/pathfind.rs:667-681`, which also
requires `dec.check()` to succeed) and `notify_rejects_tampered_sig` (`:695-701`,
one flipped bit inside the path).

## `PathBroken` — "your path to me is stale"

`pathBroken` (`pathfinder.go:497-502`) is `pathNotify` minus `info`, and that is
the entire difference: no signature, no sequence number, nothing to validate. It
is a hint, and it is safe to be lied to about. 67 bytes, a one-element path and a
small watermark, which is the shape a real one-hop forwarder produces:

```
03002a8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
```

| offset | length | field | bytes in the vector |
|-------:|-------:|-------|--------------------|
| 0 | 2 | `path` — the **originating sender's** coords, to route the report back | `03 00` = `[3]`, `0` |
| 2 | 1 | `watermark` — loop guard | `2a` = 42 |
| 3 | 32 | `source` — whose path is broken (the traffic's sender) | `8139770e…c9b394` = `PPUB` |
| 35 | 32 | `dest` — who could not be reached | `8a88e3dd…f6f5c` = `RPUB` |

A node sends one when it holds a traffic frame, is not the destination, and has
no next hop that is closer — it has just dropped the frame. `_doBroken`
(`pathfinder.go:226-234`) builds it from that frame, taking `path` from the
frame's **`from`** field: the original sender's coords, which is the route back
to the sender rather than to the last hop. Ours is the same construction
(`src/traffic.rs:78-84`). On arrival (`_handleBroken`, `pathfinder.go:236-251`;
ours `src/pathfind.rs:491-515`): forward if a closer next hop exists, else accept
only if `broken.source == our key`, then mark the stored path to `broken.dest`
broken and re-send a lookup for it. `broken` is sticky — cleared only by a fresh
notify (`pathfinder.go:153`) — and `pathfinder_send` skips a broken path rather
than reusing it.

## Deviations from Go

Go's chopper starts from a `[128]peerPort` array (`wire.go:105`) but `append`
grows past it, so Go accepts any path length; ours returns `None` beyond 128
ports (`src/frame.rs:143-145`) and drops the frame. Go rejects a lookup with
anything after the terminator (`pathfinder.go:329-331`), where ours discards
`split_path`'s consumed count (`src/pathfind.rs:101`) and ignores it —
`PathNotify` and `PathBroken` both enforce exactness and match Go. And nothing on
this page has been seen from the Go binary, so field *order* rests on reading
Go's codec plus the vectors agreeing with it.

## Provenance

| what | from |
|------|------|
| the three layouts and field order | Go source read field by field against `pathfinder.go`; transcribed vectors agree |
| the three payloads, and the notify signature **verifying** | transcribed from a local Go generator; `notify_vector_matches_go` asserts `check()` |
| the preimage being `seq ‖ path` and nothing else | transcribed; the vector only verifies in that order, and `notify_rejects_tampered_sig` fails if the path is uncovered |
| paths being zero-terminated on the wire | Go codec (`wire.go:80-86`) plus the vectors; the `// *not* zero terminated` comments are stale |
| ports allocated per key from 1 and shared by two links to one key | Go source, `peers.go:46-63`. Nothing on the wire can show this, so no vector proves it |
| a path naming nodes rather than links; `router.ports` unread | Go source. Dead state is invisible to any capture |
| the `xkey` rendezvous and its lossiness | Go source (`bloomfilter.go:176-182`, `address.go:118-150`). **No** test asserts a lookup and a notify rendezvousing on a transform; the DHT's use of `xkey` is covered, that is not |
| `broken` being sticky, and the accept/drop order (seq, then path, then signature) | Go source. State transitions and silences: no vector covers a *rejected* notify, and `tests/mesh3.rs` covers a dead link end to end rather than the flag |
| the 128-port cap, and the trailing-byte tolerance | ours only; nothing upstream to compare against |
