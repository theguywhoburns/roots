# Architecture: go-client-parity

Scope of this gate: where the library ends and the client begins, how multicast
autopeering fits, what "documented wire format" means as an artifact, and the
exact coverage denominator Gate 1 deferred.

Verified against the submodules at `reference/yggdrasil-go` `422836e` (v0.5.14)
and `reference/ironwood` `d50055b`.

## Fit

Two things have to be separated before anything else can be built cleanly.

| Today | Where it sits | Where it belongs |
|---|---|---|
| `Client` + `Client::run_peer` | `src/lib.rs:47-155` — builds its own `Router`, owns the redial loop | client |
| Admin adapter | `examples/admin.rs` (650 lines) | client |
| TUN plumbing | `examples/tun_ping.rs`, fixed keys | client |
| `src/main.rs` | positional args, hardcoded `bode` URI, ephemeral key, prints | client |
| Wire codec, tree, DHT, sessions, transports, backoff, snapshots | `src/` | library (keep) |

`src/` is otherwise clean: no printing, no `std::env`, no TUN, no admin outside
`main.rs` and `#[cfg(test)]`. The one leak is `Client`, which is node policy
wearing a library coat.

**The constraint that decides the shape:** Cargo does not let a `[[bin]]` target
use `[dev-dependencies]`. The client needs `serde_json` (config + admin JSON),
`tun`, and `smoltcp`/an ICMP answerer. So a real client binary cannot live in
this package without promoting those to normal dependencies — which would drag
them into every downstream library build. That forces one of:

- **A** — status quo: client stays in `examples/`, never installable, parity is
  proven by running examples. No dependency change.
- **B** — workspace: `roots` (library) + `roots-client` (binary owning config,
  listeners, multicast policy, admin, TUN). Contradicts AGENTS.md's "no
  workspace" line, and matches the stated end state (client extracted to its own
  project) most directly.
- **C** — single package, `[[bin]] required-features = ["client"]` with
  `tun`/`serde_json`/`smoltcp` promoted behind that feature. Installable, one
  package, but every client dep is one `--features` away from the lib graph.

**Recommendation: B**, and it is the same decision the product answer implies
("later will separate it into another binary/project"). Doing it now costs one
`Cargo.toml` and a directory move; doing it later costs a breaking release and a
re-based `AGENTS.md`. B also gives the doc target a natural home
(`roots-client` ships the protocol guide; `roots` ships the wire).

Whatever gets chosen, the rule to encode: **the library may not construct a
`Router` on the caller's behalf.** `Client::run_peer` moves out; `Router` stays
caller-owned, which is already how `register`/`serve`/`LinkSet` behave.

## Endpoints

No HTTP service. The network surface of a node is links plus a local socket.

| Surface | Direction | Library | Client | Notes |
|---|---|---|---|---|
| `tcp://` `tls://` `ws://` `wss://` `quic://` | dial + listen | both, today | loop policy | `listen`/`tls_listen`/`ws_listen`/`wss_listen`/`quic_listen` all exist; nothing loops over them |
| `unix://`, `socks://`, `sockstls://` | dial + listen | **missing** | — | Go has them (`link_unix.go`, `link_socks.go`) |
| `[ff02::114]:9001` UDP6 multicast | beacon + listen | **new** | policy | see Flow; group is a hardcoded setup option in Go, not a config key |
| admin socket `tcp://` / `unix://` | serve | never | **client** | framing today is `\n`-delimited JSON; Go uses stream-delimited JSON values + `DisallowUnknownFields` + `keepalive` |

## Data

Nothing persistent. Identity (`SigningKey`) and every table stay in memory.
Three state classes, because the lifecycle differs and Gate 1's metric depends
on it:

- **Node-keyed, expiring**: `tree.infos`, `tree.deadlines`, each
  `tree.sent[peer]` set, `path.entries`, `path.rumors`, `sess.bufs`,
  `sess.sessions`. Bounded by time (`tree.rs:346-350`, `driver.rs:205-210`).
- **Link-peer-keyed, retained on purpose**: `tree.peers`, `tree.responses`,
  `bloom.send`/`recv`. Survives a dead link so traffic self-heals across
  redials; grows only with distinct peers ever registered. A client that
  exposes `addPeer` to untrusted input turns this into slow growth — noted, not
  fixed here.
- **Interface-keyed, new**: multicast listener per interface name + its
  throttled beacon interval + the link-local addresses it was seen with. Go
  refreshes the interface set on every beacon tick (`multicast.go:251`) and
  garbage-collects listeners whose address disappeared (`262-301`); we mirror
  both, including re-`JoinGroup` idempotently and never calling `LeaveGroup`.

### Wire-format coverage — the Gate 1 denominator

A kind is **guarded** only if a checked-in byte string came from Go and a test
fails when our bytes differ. Round-tripping our own encoder proves nothing about
the wire.

| Family | Kind | Now |
|---|---|---|
| Envelope | frame header (uvarint len + type) | V (`rejects_bad_frames`) |
| Envelope | keepalive `[0x01 0x01]` | V (`keepalive_wire_bytes_match_go`) |
| Envelope | 10 `FrameType` discriminants | P (`packet_type_constants_match_go` ×2) |
| Handshake | `meta` TLV body | **R** |
| Handshake | `meta` signature (keyed/unkeyed blake2b branches) | **R** (`roundtrip_matrix_like_go`, `password_matrix_like_go_version_test`) |
| Tree | `SigReq` | **R** (`sigreq_roundtrip_exact`) |
| Tree | `SigRes` + `psig` payload | **R** |
| Tree | `Announce` | **R** |
| Tree | announce signature payload (node+parent+req+port) | P (`announce_chain_verifies`, `update_precedence_matches_go`) |
| Bloom | filter wire encoding | V (`bloom_vector_matches_go`) |
| Path | `PathLookup` / `PathNotify` / `PathBroken` | V ×3 |
| Traffic | header | V (`traffic_vector_matches_go`) |
| Session | `init` | V (`go_init_decrypts_with_b_key`) |
| Session | `ack` | **R** (`session_handshake_roundtrip`) |
| Session | `key` (rotation) | **R** |
| Session | inner `info` (traffic/proto type bytes) | P (`packet_type_constants_match_go`) |
| Session | ed25519→X25519 map | V (`e2c_pub_matches_go`) |
| Address | node addr / subnet / lossy reverse | V ×3 |
| Proto | nodeinfo JSON + 16384 cap | P (`nodeinfo_size_cap_matches_go`) |
| Proto | debug req/resp payloads | **R** (`debug_round_trips`) |
| Multicast | advertisement (104 B) | **— (not implemented)** |
| Multicast | keyed group-membership hash | **— (reuse `handshake::keyed_hash`)** |

**22 kinds. 12 guarded with Go bytes, 5 guarded as constants/semantics, 5
round-trip only, 2 absent.** So Gate 1's "8 message kinds today" understates it:
the real number is **12 of 22**, and the metric target is 22 of 22 plus a
documented page for each.

The embarrassing column is the handshake: the first bytes on every link, and the
only guard is our own encoder agreeing with itself.

> **Correction, 2026-09-24 (after approval; two claims in this doc were
> wrong about *how* the gaps close, not about *what* to build — the decisions
> stand).**
>
> 1. Closing the `meta`/multicast gaps is **not** mechanical by transcription.
>    `reference/yggdrasil-go/src/core/version_test.go` and
>    `src/multicast/advertisement_test.go` build their expectations
>    *programmatically* (blake2b + `ed25519.Sign` in the test body); they contain
>    no hex to copy. No Go compiler is installed, so nothing can be regenerated
>    from them. What closes the gap instead is **capture from the Go binary that
>    is already on this host** — `/run/current-system/sw/bin/yggdrasil` 0.5.14,
>    the exact version `reference/yggdrasil-go` pins, which takes a JSON config on
>    stdin (`-useconf`, `-genconf -json`). A local Go listener, dialed by us,
>    emits real `meta` bytes; a `tcp_proxy`-style MITM on a Go↔Go link emits real
>    `SigReq`/`SigRes`/`Announce`/bloom/path/session bytes. That is how
>    `GO_INIT` at `src/session.rs:724` was already captured. Gate 3 designs the
>    harness.
> 2. "unknown JSON fields are not rejected" is **not** a divergence. Go's only
>    `DisallowUnknownFields()` call (`src/admin/admin.go:309`) decodes into a
>    `json.RawMessage`, which swallows the whole object, and the request struct is
>    then filled by a plain `json.Unmarshal` (`admin.go:326`) that allows unknown
>    fields. Go is lenient; our parser is too. Dropped from the parity list.

### Documentation artifact

One page per family under `docs/protocol/`, same order as the table:
`00-overview.md` (link → handshake → tree → DHT → session lifecycle, with the
byte offsets of a real capture), then `10-envelope`, `20-handshake`,
`30-tree`, `40-bloom`, `50-path`, `60-traffic`, `70-session`, `80-address`,
`90-proto`, `a0-multicast`. Each page carries: byte-layout table, the checked-in
vector with the Go `file:line` it came from, and the quirks we mirror on purpose
(`psig` covering the port, the empty-password hash branch, `xkey` rumor
rendezvous). Rule: **a page with no test is a page that rots** — every code
block in a page must appear verbatim in a `#[cfg(test)]` const.

## Flow

Node assembly, mirroring Go's startup order (`cmd/yggdrasil/main.go`) so an
operator can diff the two behaviors:

```
identity  load/generate SigningKey -> derive address, cert
config    defaults <- user file (HJSON or JSON) <- flags        [client]
core      Router::new(key)                                      [lib]
listeners one task per Listen URI, accept -> complete_accept
          -> register -> insert into shared LinkSet              [client loop, lib parts]
peers     static Peers/InterfacePeers -> dial_retry + Supervisor [client]
          allowlist check on inbound (AllowedPublicKeys)         [lib]
admin     bind tcp://|unix:// -> command dispatch                [client]
          self/multicast/tun handlers registered by each module  [each owner]
multicast per-iface: join ff02::114:9001 -> beacon + listen      [new: lib codec + socket,
          discovered tls://...?key=..&priority=.. -> ephemeral   client supplies iface set]
          dial (never redialed, never backed off)
tun       create iface -> resolve-wait -> session send/recv      [client + lib seam]
shutdown  admin -> multicast -> tun -> core, on SIGINT/SIGTERM   [client]
```

Two library seams this exposes, and they are the only lib changes in the feature
besides multicast and the missing transports:

1. **`LinkSet` is single-threaded by construction.** Every loop above wants to
   add and drop links while `serve_links` runs. Today that is one caller's job.
   Either the client drives all of it from one task (Go's actor model, honest
   and simplest) or the library grows interior locking. Plan: **one task, one
   `Router`, message-driven** — keep the library lock-free, and let the client
   own a command queue that the serve loop drains between slices. This is the
   shape Go actually uses (`phony.Inbox`).
2. **TUN needs resolve-and-hold.** `resolve()` blocks and drives the link loop
   itself (`driver.rs:109-165`), which is fine for a probe and unusable behind a
   kernel interface that expects packets buffered while resolution runs. Go keeps
   that queue in `ipv6rwc`. Plan: the library grows a "lookup with pending
   payload queue" that reuses the existing `rumors[].pending` slot
   (`pathfind.rs:422-430`) — the mechanism is already there; it needs a public
   entry point, not new state.

Multicast discovery, concretely, is: send `tls://[fe80::x%iface]:<ephemeral>`
beacon; on receipt, verify version `0.5` + not-self + keyed hash, then dial
`tls://<linklocal>:<port>?key=<hex>&priority=<n>&password=<pw>` as an ephemeral
peer. Both sides beacon and both dial; crossed duplicates are resolved by the
existing Slice 16 convergence work, not by a new tiebreak. Dedup is by
`(uri-minus-query, source-interface)`. Ephemeral links never back off — they
fail and vanish.

Verified line by line against `reference/yggdrasil-go/src/multicast/` on
2026-09-24, with three details worth pinning down:

- The version gate is **exact on both fields** — `major != 0 || minor != 5 ||
  self` all drop the beacon (`multicast.go:413-419`,
  `core/version.go:27-28`). Not "0.5-compatible".
- Dedup does **not** live in the multicast package. `_listen` calls
  `core.CallPeer` for *every* valid beacon (`multicast.go:453`); the link manager
  keys links on `linkInfo{uri: urlForLinkInfo(u) /* RawQuery stripped */, sintf}`
  and answers a duplicate with `ErrLinkAlreadyConfigured` after kicking the
  existing link (`core/link.go:160-243`, `766-769`). Ephemeral and persistent
  peers share that one map, so multicast can collide with a configured peer by
  design.
- The membership hash is `blake2b-512(key=<receiver's per-interface password>,
  msg=<sender's pubkey>)` — the sender precomputes it once per interface
  (`multicast.go:213-223`), the receiver recomputes it over the advertised key
  with *its own* password and byte-compares (`multicast.go:429-441`). Same
  construction as `handshake::keyed_hash`, different message.
- Beacon throttle ramps: each interface starts at 0 and grows 1 s per beacon
  until 15 s (`multicast.go:368-370`), on a ~1 s ± 1 s jitter timer
  (`multicast.go:373`). Ephemeral port advertised is the *bound* listener port,
  not the configured one (`multicast.go:352`).

## External

- Submodules `reference/yggdrasil-go`, `reference/ironwood` — read-only truth for
  every `file:line` in `docs/protocol/`. CI does not check them out.
- No env vars in the library. `ROOTS_DBG_DUMP` stays a `main.rs`/client thing.
- Live peers for manual checks: `tcp://bode.theender.net:42069` (reliable),
  `yggdrasil.su:62486` (throttles heavy dialing). Both TCP-open as of
  2026-09-24; neither is reachable from CI, by design.
- Go **toolchain** (compiler) for the vecgen harness: not installed, later on a
  dedicated machine. Not needed for vectors — the installed Go **binary**
  (`/run/current-system/sw/bin/yggdrasil`, 0.5.14 = the pinned submodule version)
  is a working oracle: JSON config on stdin, no root, no TUN. Every new
  Go-sourced vector is a capture from it, committed as a hex constant with its
  provenance (`yggdrasil-0.5.14`, capture date, which link produced it).
- TUN work needs `/dev/net/tun` + `CAP_NET_ADMIN`; the sandbox denies
  `TUNSETIFF`, and the host's own service node already owns `tun0` and the
  `200::/7` route, so a client test interface needs its own name.

## Folded in (the hardening items)

Not slices of their own; they ride along with whichever slice touches the file.

- `LinkSet::write` returns `Ok(())` when there is no entry for the target
  (`link.rs:260-264`). Change the signature to report the miss so
  `greedy_next`-chosen forwards can't vanish silently.
- `Router::frames` is `[u64; 10]` indexed by `ftype as usize`; a new
  `FrameType` panics. Add a const assertion tying the length to the discriminant
  count.
- Both are one test each, and both tests must fail against today's code.

## Least confident decisions

Deferred to Gate 3 deliberately, listed so nothing is decided silently:
whether B vs C is really worth breaking "no workspace"; whether multicast lives
in the library or the client (the codec says library, the sockets say both);
whether the single-task/message-driven client survives contact with `tun`
throughput; and whether `docs/protocol/` should live in the library crate or the
client crate.
