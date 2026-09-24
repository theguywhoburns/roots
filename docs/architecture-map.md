# Architecture Map: roots

Current-state map of the whole crate: all 21 files in `src/` (the `roots`
library), how they own state, how a packet crosses them, and which invariants
break interop if edited loose. Node policy — the binary, the redial loop, and
from Slice 5 on the config/admin/TUN/multicast halves — lives in the sibling
`client/` package (`roots-client`), which this map covers only at its seam.

Relationship to gate docs: `01`–`04` are frozen approval records. `00-status.md`
is the slice checklist and resume point. `02-architecture.md` describes Slice 1–2
scope only (TCP/TLS, "ironwood NOT ported in full") and is now wrong on both
counts — read this file for the module graph, not that one.

## Stack

```
  app / demo          client/src/{main,node,links}.rs · examples/* · tests/*
        |             drains Router::inbox / proto_inbox, feeds the outbox Vec,
        |             owns the LinkSet (which owns its own conns), smoltcp
        |             bridges, admin socket, TUN
        v
  facade              src/router.rs  Router { five tables }   (no locks, no tasks)
        |             src/views.rs read-only snapshots · src/traits.rs Snapshot
        v
  orchestration       src/driver.rs  register · maintain · dispatch_frame · serve
        |             reaches every table as an `impl Router` method
        v
  algorithm tables    tree   pathfind   bloom   session   proto   traffic
        |             each owns its own map; cross-table calls take explicit refs
        v
  link framing        src/frame.rs  uvarint len + type byte + payload
        v
  transport           src/link.rs (Tcp, traits, LinkSet, handshake drive)
        |             tls.rs  ws.rs  quic.rs
        v
  identity / crypto   handshake.rs (meta: BLAKE2b + ed25519)
                      session.rs   (crypto_box / X25519)   address.rs (key -> IPv6)
```

Two files span layers: `link.rs` is both the driver-facing `LinkSet` and the
transport primitives; `session.rs` is both a routing table and the crypto layer.
Note the count mismatch too — `Router` holds **five** state tables
(tree/path/bloom/sess/proto); `traffic.rs` is a stateless header codec plus the
forwarding handler, not a sixth table.

## Module map

Go-origin column is taken from each module's own port header and checked against the `reference/` submodules (ironwood `d50055b`, yggdrasil-go `422836e` = v0.5.14).

| File | Job | Go origin |
|---|---|---|
| `lib.rs` | crate root, `Client` sugar (`new`, per-scheme dial, listen/accept), re-exports — no node loop (Slice 3) | — |
| `router.rs` | `Router` struct composing the five tables; `new`, `pubkey`, `next_init_seq`, `announces_*`, `peer_kind`, `is_roots_peer`; `MAINTENANCE_INTERVAL`, `UNKNOWN_LATENCY` | — (facade) |
| `driver.rs` | link I/O orchestration: `register` `resolve` `maintain` `dispatch_frame` `serve` `serve_links`, keepalive, dead-link eviction, `fatal_link_error` | `network/router.go` peer upkeep |
| `views.rs` | read-only snapshots: `parent` `root_and_depth` `known_nodes` `dump` `has_path` `has_session` `path_details` `get_paths` `get_sessions` `link_peers` `dropped_no_link` `tree_entries` + `Snapshot` impl | diagnostic funcs |
| `traits.rs` | `Snapshot` trait (25 lines) | — |
| `tree.rs` | `TreeState`: spanning tree — SigReq/SigRes/Announce, `peers` `infos` `sent` `deadlines` `next_port`, root election | `ironwood/network/router.go` |
| `pathfind.rs` | `PathState`: DHT pathfinder — `entries`, `rumors` (keyed by transformed key), lookup/notify/broken, `greedy_next` forwarding | `ironwood/network/pathfinder.go` |
| `bloom.rs` | `BloomState`: per-peer send/recv bitfilters (M=8192, K=8, Murmur3-x64-128 `sum256`), `bloom_fix`, `bloom_maintenance` | `bloom/v3` + `ironwood/network/bloomfilter.go` |
| `session.rs` | `SessionState`: crypto_box sessions, init/ack/update, key ratchet, pre-session buffer slot, `resend` | `ironwood/encrypted/session.go` + `crypto.go` |
| `proto.rs` | `ProtoState`: nodeinfo advertisement, proto channel over `typeSessionProto` | admin/debug subset |
| `traffic.rs` | `Traffic` header codec (path + from + source + dest + watermark + payload) and inbound forwarding decision | `ironwood/network/traffic.go` |
| `peer.rs` | `PeerKind` (Go vs roots via vendor TLV), `feat` constants, `PeerState` | `meta` vendor fields |
| `supervisor.rs` | persistent redial: `SupervisedPeer`, `due_indices`, `backoff_cap` | `core` peer monitor |
| `link.rs` | `Transport`/`Link` traits, `AnyConn`, the **owning** `LinkSet` (`write` hard / `write_via` soft / `stats` / `idle_for`, retirement on write failure), `complete_dial`/`complete_accept`/`dial_any`, URI parsing, backoff, `meta` handshake drive | `src/core` |
| `tls.rs` | `Tls` transport (`tls://`), rustls/ring NoVerify, rcgen listener cert | `src/core/link_tls.go` |
| `ws.rs` | `Ws`/`Wss` transports, `ygg-ws` subprotocol, message-per-flush | `src/core/link_ws.go` |
| `quic.rs` | `Quic` transport (quinn), one bidi stream per link | `src/core/link_quic.go` |
| `frame.rs` | link framing, `FrameType` + `FRAME_KINDS`/`FrameType::ALL`, `wire_len` (what the counters count), uvarint + path helpers, keepalive, size caps | `ironwood/network/peers.go` + `wire.go` |
| `handshake.rs` | `meta` TLV codec + signature, `Meta` struct, version gate | `src/core/version.go` |
| `address.rs` | key -> IPv6 (`02…` node, `03…` subnet), `lookup_key_for_addr`, prefix scan | `src/address/address.go` |
| `error.rs` | `Error` enum (thiserror) | — |
| `main.rs` | *(moved, Slice 3)* now `client/src/main.rs` — Go-shaped flag front end (`-genconf`/`-useconf`/`-useconffile` + `-address`/`-subnet`/`-publickey`, Go's `flag` rejection wording), then the demo probe: dial by scheme, hold, `ROOTS_DBG_DUMP` | `cmd/yggdrasil/main.go` |
| `client/src/node.rs` | *(the other package)* `Cmd` + `Node`: the single-task node loop — one task owns `Router` + `LinkSet` + the mailbox, drains commands between `DEFAULT_TICK` serve slices, is the only non-test `Router` builder | `core` `links` actor + `switch.go` |
| `client/src/links.rs` | *(the other package)* `Links`: one `Entry` per `(link_id, sintf)` — Go's dedup, `LinkKind::{Persistent,Ephemeral}`, `SupervisedPeer` backoff, last error, dial tasks in/out over `LinkEvent`, `report()` | `core/link.go` `links.add`/`remove` |
| `client/src/config.rs` | *(the other package, Slice 6)* `Config` with Go's `NodeConfig` key names **and declaration order**, `defaults()` = the Linux column, `generate`/`load`/`from_json` (strip nulls → deserialize → postprocess), `signing_key`/`address`/`subnet`/`link_options`/`to_json`, plus `Flags`/`ConfigSource`/`USAGE`. JSON only | `src/config/config.go` + `defaults_linux.go` |

## State ownership

One `Router` per task. There is no `Mutex`, no `RwLock`, no channel and no
`spawn` in library code (`tokio::spawn` appears only inside `#[cfg(test)]`
servers; the only `Arc` is the required rustls config handle in
`tls.rs:80,93`). Concurrency lives entirely in the caller (`client/src/node.rs`,
`examples/`, the smoltcp bridges) — and since Slice 5 the client keeps its own
router state the same way: `Node` is one task, so the production client code has
no lock either, only channels.

- Every table field is `pub(crate)`; `Router` is the only public handle.
  External code cannot reach `TreeState`/`PathState`/… directly.
- Each algorithm module adds its own `impl crate::router::Router` block, so
  cross-table work is a method call on one borrow (`self.bloom_fix(...)`,
  `self.greedy_next(...)`) rather than a shared god-object field access.
- Async methods never hold a connection: `LinkSet` **owns** its links
  (`Vec<LinkEntry>` of `AnyConn` plus per-link `last_write` clocks, no lifetime
  parameter since Slice 4), so it is `'static` and movable into one task's loop
  without a lock. Every router I/O call still takes `&mut LinkSet`. **The set is
  caller-owned and must outlive slices** — it is where the keepalive clock lives.
- Sends are keyed by link peer, and a write failure retires the entry: `send`
  removes the link whose `write_frame` errored before returning, so the next
  `maintain` sees a smaller set rather than a poisoned one.
- `SessionState::init_seq` is the one atomic (`Cell`-like usage through `&self`),
  because init/ack construction happens while `sess.sessions` is already mutably
  borrowed (`router.rs:78-89`).

Egress has no public send function. Apps drain `Router::inbox` /
`Router::proto_inbox` and push `(dest_key, payload)` into the `outgoing` `Vec`
handed to `serve`. `session_send` is `pub(crate)` (`session.rs:405`).

## Table graph

"A --> B" means B consumes what A produces.

```
tree    --> bloom    bloom advertises bits derived from our parent info
        --> path     root_path_for + peer latency scores feed greedy_next
        --> proto    getPeers / getTree replies are built from tree.peers/infos
        --> views    every snapshot (parent, dump, tree_entries)

session --> path     every outbound byte rides pathfinder_send
path    --> session  a notify flushes whatever pathfinder_send parked in
                     rumors[].pending (pathfind.rs:424-431); session setup
                     refreshes the entry deadline
path    --> traffic  greedy_next picks the next hop for a forwarding packet
bloom   --> path     multicast gate: flood a lookup/notify only to useful peers
session --> inbox    decrypted payload lands in `inbox` (type byte 1); byte 2
                     routes to `proto_inbox` instead
```

`tree` is the root of truth for who exists; `bloom` and `path` are both derived
views of it; `traffic` is the forwarding carrier; `session` is the endpoint
consumer. `proto` is a session payload variant, not a separate transport.

## Link lifecycle

1. **Dial or accept.** `dial_any` parses the scheme and dispatches to
   `Tcp`/`Tls`/`Ws`/`Wss`/`Quic` (`link.rs:770-790`); listener paths accept and
   upgrade. Both wrap the stream in `AnyConn::new`, which hoists
   `remote_key`/`priority`/`PeerKind` and boxes the stream.
2. **Handshake.** `complete_dial` merges URI opts then runs `run_handshake`
   under `HANDSHAKE_TIMEOUT` as outbound; `complete_accept` runs it inbound and
   deliberately skips `merge_opts` (`link.rs:721-768`). The exchange yields
   `(remote_key, priority, PeerKind)` — **no key material**; session keys come
   later from `crypto_box` in `session.rs`.
3. **`register` — once per link, never per slice** (`driver.rs:19`). Writes our
   bloom, `SigReq`, then replays everything already in `tree.sent[peer]`.
   Port, `req` and `lag` are reused for a known key so a redial does not look
   like a new node.
4. **`serve` / `serve_links` — repeated slices** over the same `LinkSet`
   (`driver.rs:344`/`357`; `serve` forwards straight to `serve_links`, so
   single-link is just a one-entry set). One slice:
   splice `sess.resend` onto the front of `outgoing` → one `maintain` per peer →
   loop { expiry check → drain outbox via `session_send` → `maintain` per peer
   every 1 s → read one frame per link (reads sliced to 100 ms only when 2+
   links) → count the frame's wire bytes into the entry's `rx` → `frames[t] += 1`
   → `dispatch_frame` → on read **or write** error evict the link, abort the
   serve only if `fatal_link_error` says so (i.e. only when the set went empty or
   the error is ours) → on quiet timeout `keepalive_if_idle` }.
   Because the set owns its conns, eviction hands the `AnyConn` back to the
   caller (`remove`) instead of invalidating a borrow.
5. **`maintain` tick** (`driver.rs:165`): `expire` → `fix` → `send_announces` →
   `bloom_maintenance` → `expire_ephemeral` → re-`rumor_lookup` still-pending
   rumors.

`resolve` is the same loop pinned to one peer: `rumor_lookup` → throttled
`maintain` → read → `dispatch_frame` → test `path.entries` for a key whose
address or subnet matches (`driver.rs:109-162`).

## Frame dispatch

`dispatch_frame` (`driver.rs:256-329`) is a `match` on `FrameType`:

| type | handler | table |
|---|---|---|
| `KeepAlive` / `Dummy` | ignored | — |
| `SigReq` | `handle_request` | tree |
| `SigRes` | `handle_response` (after `res.check`) | tree |
| `Announce` | `handle_announce` → returns an optional better announce, written straight back | tree → bloom, path |
| `BloomFilter` | `bloom_handle` | bloom |
| `PathLookup` / `PathNotify` / `PathBroken` | `handle_lookup` / `handle_notify` / `handle_broken` | path |
| `Traffic` | `handle_inbound_traffic` | traffic → path / session / proto |

Every arm except `KeepAlive`/`Dummy` ends with `keepalive_if_idle` — that is the
lazy keepalive reply, and dropping it from a new arm kills the link at ~4 s.
Each handler also gates on a strict decode (`decode_exact`, or `n == payload.len`)
before touching state; trailing garbage means the frame is dropped silently.

`Traffic` inbound: `greedy_next` forwards one hop if the path still scores a
better peer; else `dest == our key` → `handle_session_bytes`, where payload byte
`1` → `inbox`, `2` → `handle_proto_bytes`; else emit `PathBroken` (`traffic.rs:61-86`).

## Boundary: library vs node

`src/` talks wire and owns state. It never prints, never opens TUN, never serves
admin, and never builds a `Router` for a caller. Everything that decides *what to
do* lives in the `client/` package (`roots-client`: `main.rs`, `node.rs`,
`links.rs`, `config.rs`, and the admin/TUN/multicast slices to come) or in root
`examples/` / `tests/`.

Two things enforce it. Crate visibility: `smoltcp`, `serde_json` and `tun` are
dev-dependencies of the root package only, so the lib target cannot see them.
And a package boundary: a redial loop, a listener task or an admin handler added
to `src/` has to construct a `Router`, which is the one thing Slice 3 made hard to
do by accident. Check both mechanically with `grep -n "mod tests" src/*.rs`
(every `Router::new` must sit below its file's test module) and `cargo tree -p
roots -e normal` (15 crates, no client-only dependency).

The admin adapter (`examples/admin.rs`, yggdrasilctl-compatible) and the TUN
bridge (`examples/tun_ping.rs`) are demos riding the public query surface; both
move into `client/src/` in Slices 7 and 14, and only then can their
dev-dependencies leave the root manifest.

## The client's node loop (Slice 5)

Go runs a `links` actor and a `core` actor behind channels (`yggdrasil-go
src/core/link.go`, `switch.go`). We collapse that into one task, which is only
possible because `LinkSet` owns its connections (Slice 4) — a set that borrowed
`&mut dyn Link` could not be a struct field, and a struct field is what lets one
task own it.

```
listener ─┐                                   ┌─ spawn: connect_any(uri) ─┐
admin    ─┼─ mpsc::UnboundedSender<Cmd> ─→ Node::run ─┤  (touches no router state) │
multicast─┘        Dial/Drop/Accept/Send/Quit   │                        │
                                               ← ┴── LinkEvent::Dialed ──┘
```

`run` is five steps per tick: drain `rx` → drain `events` →
`peers.note_liveness(&links)` → `peers.start_due(now)` →
`router.serve(&mut links, Some(tick), &mut outbox)`. `Links` (`client/src/links.rs`)
is the configured-peer list: one `Entry` per `(link_id, sintf)` carrying kind,
`SupervisedPeer` backoff, `live` key, `last_error` and the in-flight dial token.

- **Off-task work is dialling only**, and it is safe because connecting plus the
  `meta` handshake read no router state. The dial task is handed a token and
  returns a `LinkEvent`; `mark_live` answers false when the entry is gone, and
  the caller drops the connection — Go's "if a peering has come up in this time,
  abort this one" (`link.go:366-373`).
- **Liveness is reconciled, not notified.** `serve` evicts a dead link silently,
  so `note_liveness` diffs each entry's `live` key against `LinkSet::peers()`
  once per tick: gone means `record_failure` (and, for an `Ephemeral` entry,
  deletion — Go's goroutine-exit `delete(l._links, info)`).
- **`Drop` ≠ disconnect.** `Links::remove` forgets the entry, which cancels the
  redial and leaves the link serving (`api.go:207-211`). A duplicate `Dial`
  kicks the entry's backoff and answers `AlreadyConfigured` (`link.go:236-245`);
  the kick reschedules for the next tick rather than interrupting a sleep.
- **A `serve` error is not fatal unless `Error::is_link()` says so** — the loop
  keeps running on a dead link and returns the error for anything else.
- Command latency is bounded by `tick` (50 ms, `DEFAULT_TICK`), which is the
  price of the lock-free invariant (Gate 3, least-confident decision 3).

## Config (Slice 6)

`client/src/config.rs` is a **wire format**, not a settings bag: the proof is that
the installed Go binary reads what we write and vice versa. Four rules carry that,
each with a test that fails when the rule is broken:

- **Key set and order are Go's.** `NodeConfig`'s declaration order
  (`config.go:42-58`) is `encoding/json`'s output order, and `omitempty` sits on
  exactly four fields (`PrivateKey`, `PrivateKeyPath`, `AdminListen`,
  `LogLookups`) — so `skip_serializing_if` mirrors that list, and `-genconf`
  blanks `AdminListen` first (`main.go:121`) so the key disappears the way Go's
  does.
- **Defaults come from overlaying, not from field attributes.** Go's `ReadFrom`
  calls `GenerateConfig()` and parses the document *on top of* it
  (`config.go:114-119`), so the struct carries `#[serde(default = "defaults")]`.
  Per-field defaults would be wrong in an observable way: a config with no
  `PrivateKey` must still boot, with a fresh identity each run.
- **A JSON `null` is an absent key**, at every depth, because Go's decoder leaves
  the destination untouched. `strip_nulls` runs before deserialising; without it
  `{"IfMTU":null}` is a type error where Go shrugs.
- **Address text is Go's text.** `Address`/`Subnet`'s `Display` (`src/address.rs`)
  formats through `Ipv6Addr`/`net.IPNet` semantics. Byte derivation was always
  correct; the *string* was zero-padded until Slice 6, which is exactly the class
  of bug a byte vector cannot catch and a captured `-address` line can.

Deliberate divergences: JSON only (no HJSON writer, no UTF-16 BOM sniff),
`-json` accepted as a no-op, no `-normaliseconf`/`-exportkey`/`-autoconf`,
`KeyMismatch` rejected where Go trusts the tail of `PrivateKey`, unknown *flags*
rejected with Go's own wording while unknown *keys* are ignored like Go ignores
them. Running a node from a config is Slice 7's; until then that path prints what
it read and exits 2.

## Invariants — things that break silently

Wire-level (must stay byte-identical to Go):
- `FrameType` discriminant order mirrors Go `wirePacketType`; `Router::frames`
  is `[u64; FRAME_KINDS]` indexed by `ftype as usize`, so a new type panics —
  `FRAME_KINDS` (`frame.rs:16`) and `FrameType::ALL` are both sized from the
  same const and `frame_kinds_match_table_len` asserts the table and the count
  agree. Counters are bumped by the **caller** of `dispatch_frame`, not inside it.
- Link byte counters are `frame::wire_len(payload.len())` in both directions, so
  `getPeers`' `bytes_recvd`/`bytes_sent` will be what the peer's NIC saw, not the
  payload size (Go counts on the framed stream).
- `meta` signature must remain the trailing 64 bytes; empty password takes a
  different unkeyed hash branch — nil-vs-`""` interop depends on it.
- `run_handshake` writes ours before reading theirs; reordering deadlocks both
  ends.
- Session payloads and proto requests need their leading type byte
  (`session_send` / `proto_send` wrap, inbox strips).
- Bloom hashes are Murmur3-x64-128 `sum256`, not a stock murmur3 crate default.
- DHT rumors rendezvous by **transformed** key, so a full-key notify matches a
  partial-key lookup. Keying by destination key drops every resolution.
- `SigRes.psig` and announce `sig` cover node + parent + req + **port**.
- Announce scope: `_send_announces` (`tree.rs:530`, mirroring Go
  `network/router.go:321`) sends the ancestry of self plus the ancestry of that
  one peer — never the whole table. So `tree.infos` holds a node's line to the
  root and its neighbours on it, and in a line A—B—C the two ends legitimately
  never learn each other. Proven by `tests/mesh3.rs` phase 1 (A and C sit at 2
  infos, B at 3). Do not treat `known_nodes()` as network size, and do not route
  a query through `tree.infos` expecting to find a non-relative.

Lifetime / sequencing:
- `LinkSet` must outlive slices, or per-link send clocks reset and the peer
  read-times-out the link at ~4 s.
- `register` twice on one link = SigReq + announce replay every slice ≈ a
  protocol storm in frame counters.
- Pre-session buffer is a single slot, last write wins (Go `_bufferAndInit`);
  stagger proto requests behind `has_session`.
- `ws://` requires the `ygg-ws` subprotocol both ways. `QuicStream` must keep
  endpoint + conn handles alive or the connection tears mid-link.
- Two send strengths, and picking wrong one is the silent-failure bug this split
  exists to kill: `LinkSet::write` is **hard** (`Err(Error::NoLink)` for a peer
  with no entry) and is only for a caller that just held that link;
  `LinkSet::write_via` is **soft** (`Ok(false)`, frame discarded, counted by
  `Router::dropped_no_link`) and is mandatory for anything addressed from router
  state. Every `Ok(false)`/`Err(NoLink)` is visible — a drop nobody can count is
  the failure mode Gate 2 audited.
- **Router books outlive links, so a key they name may have no link** (Slice 4).
  Nothing prunes `tree.peers`/`tree.infos`/`bloom.on_tree` when a link dies —
  Go's `removePeer` (`router.go:147`) does, and adding that is the router-state
  lifecycle slice's job. Until then the three reads that mirror Go must ask the
  live set: `_sendReqs` iterates `links.peers()` (`router.go:189`), the bloom
  fan-out is guarded by the peer lookup (`bloomfilter.go:277`), and `fix` checks
  `links.peers().contains(&info.parent)` (`router.go:229`). Each has a test that
  fails only when the guard is reverted
  (`router_books_can_name_a_peer_with_no_link`,
  `fix_refuses_a_parent_with_no_link`); `tests/mesh3.rs` passes under all three
  reversions, so it is not the coverage.
- A dead link is evicted from the `LinkSet` only (`driver.rs:446`); `tree.peers`,
  `tree.responses` and `bloom.send`/`recv` keep their entries. Deliberate — that
  retention is what lets traffic self-heal across redials. Every map keyed by a
  *network node* does expire (`tree.infos` + `tree.deadlines` at
  `tree.rs:336-349`, `path.entries` / `path.rumors` / `sess.bufs` /
  `sess.sessions` at `driver.rs:200-207`, and each `tree.sent[peer]` set is
  pruned by the same pass at `tree.rs:345-349`), so surviving growth is bounded
  by distinct link peers ever seen, not by network size. Repeated admin
  `addPeer` against many one-off URIs is the realistic way to grow it.
- Link errors are fatal **only when they take the last link with them**:
  `Router::fatal_link_error(links, e)` gates all five `serve_links` error sites
  — `Error::Io`/`Error::NoLink` on a set that still has members just drop that
  member, anything else aborts (that error came from our own code, not the
  wire). Mirrors Go, where each peer owns a reader goroutine whose
  `defer router.removePeer` cannot disturb the others (`peers.go:189,228,449`).
- Dead code mirrors Go: `BloomState::dirty` is written and never read; `fix`
  ignores its `peer_key` yet is called per link per tick. Leave both.

Client-side (the single-task rule):
- **Only `Node::run` touches `Router`/`LinkSet`.** That is what keeps `src/`
  lock-free, so a listener, admin handler, multicast task or TUN bridge that
  wants router state must send a `Cmd`, not take a `Mutex`. Dialling is the one
  exemption, and it earns it by touching no router state.
- **Redial has exactly one owner.** `Links::start_due` + the loop; `run_peer` and
  `Client::drive` are deleted, and Gate 3's `serve_until_closed` was deliberately
  never built because it would be a second policy home.
  `examples/admin.rs` still runs its own `PeerCfg` loop until Slice 7 moves it
  onto `Node`.
- **`link_id` is URI-minus-query, and the dedup key is `(link_id, sintf)`**
  (`link.go:54-57`, `766-769`). Two URIs that differ only in options are the same
  peer; two URIs on different source interfaces are not.

## Resume point

The live plan is `docs/plans/go-client-parity/` — Slices 1–5 DONE 2026-09-24,
resume from its `00-status.md` (checklist, findings) and `04-slices.md` (proof per
slice). The earlier `docs/plans/rust-client/` plan is closed: its Slices 1–19 are
`DONE`, and the only open item there is the Slice 20+ public-mesh TUN run (needs a
TUN host plus a second live node; loopback-verified so far) — see `TODO.md`.
