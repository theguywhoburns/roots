# AGENTS.md

Rust client for the Yggdrasil encrypted IPv6 mesh, interoperable with the Go
implementation. Two-package workspace: the root `roots` package is the library
(the product) — its `examples/` and `tests/` are demo scaffolding — and
`client/` (`roots-client`, bin `roots`) is the runnable node that mirrors Go's
binary. No release process; CI covers static checks plus loopback tests only.

## Toolchain

- Nightly Rust pinned in `rust-toolchain.toml` (`channel = "nightly"`, edition 2024). Do not downgrade or add a separate toolchain file.
- Toolchain is provisioned by devenv (`devenv.nix`: `languages.rust` with `toolchainFile`). Enter it via `direnv allow` / `devenv shell`; plain `cargo` works once inside.
- Components available: `rustfmt`, `clippy` (`profile = "minimal"` — anything else needs `rustup component add`).
- No `python3` on PATH; use `perl` for one-off text munging. Go reference source lives in-repo as submodules under `reference/` (see Reference material) — no `/tmp` clones anymore.
- **No Go toolchain is installed** (`go` is off PATH and `devenv.nix` provisions none), so building a Go oracle node or regenerating wire vectors requires adding `languages.go` to `devenv.nix` first. `yggdrasil-go` `develop` declares `go 1.25.0`.

## Layout

- `src/lib.rs` — library root (`Client`: identity + dial/accept per scheme, re-exports). The lib owns no node loop: it never constructs a `Router` outside `#[cfg(test)]`.
- `src/address.rs` — key→IPv6 derivation. `src/handshake.rs` — link `meta` codec. `src/link.rs` — `Transport` trait + TCP dial/listen/handshake, backoff + `?maxbackoff=`/`?sni=` URI opts; `Link` trait + type-erased `AnyConn` + `LinkSet`, which **owns** its connections (no lifetime parameter, `Transport::Stream: 'static`) — one set per link-collection, reused across slices, because per-link send clocks live in the set. `src/tls.rs` — `Tls` transport (rustls/ring, NoVerify like Go InsecureSkipVerify, rcgen self-signed listener). `src/ws.rs` — `Ws`/`Wss` transports (`ygg-ws` subprotocol, one binary message per flush, byte-stream reads; WSS layers WS on the TLS connector). `src/frame.rs` — ironwood link framing + uvarint/path helpers, plus `FRAME_KINDS`/`FrameType::ALL`/`wire_len` (byte counts for link stats; `frame_kinds_match_table_len` keeps the dispatch table and the count honest). `src/quic.rs` — `Quic` transport (quinn, one bidi stream per link, Go's 60s-idle/20s-keepalive timeouts; stream keeps endpoint+conn handles alive).
- `src/link.rs` API (Slice 4): `LinkSet::single`/`add`/`remove`/`peers`/`get`/`len`/`is_empty`, `stats(&peer) -> Option<LinkStats>`, `idle_for(&peer)`. `add` replaces by remote key and **keeps the send clock** through it; every other field belongs to the new link. `LinkStats { up, rx_bytes, tx_bytes, inbound }` is the `getPeers` field set for later slices; the per-link `LinkEntry` (conn + `up`/`rx`/`tx`) stays private. `write` and `write_via` share a private `send` that **retires** the entry whose `write_frame` fails (a link we cannot write is dead whatever the read side thinks). Counters use `frame::wire_len()` both ways, so they count what the peer's NIC saw.
- `src/router.rs` — facade: `Router` struct composing the tables below + `new`/`next_init_seq`/`peer_kind`/`announces_*` accessors. `src/driver.rs` — link I/O orchestration (`register`/`resolve`/`maintain`/`dispatch_frame`/`serve`/`serve_links`, dead-link eviction, empty-set sleep, `fatal_link_error`) — the two send strengths live on `LinkSet` (`write` hard / `write_via` soft) and the counter they bump lives on `Router` (`dropped_no_link`). `src/views.rs` — read-only snapshots (`parent`/`dump`/`get_paths`/…​) + `Snapshot` trait impl (`src/traits.rs`). `src/tree.rs:TreeState`, `src/pathfind.rs:PathState`, `src/bloom.rs:BloomState`, `src/session.rs:SessionState`, `src/proto.rs:ProtoState` — per-algorithm tables owning their own maps. `src/peer.rs` — `PeerKind` (Go vs roots via vendor TLV) + `PeerState`. `src/supervisor.rs` — persistent redial (`SupervisedPeer`/`due_indices`/`backoff_cap`). `src/link.rs` — `Transport`/`Link` (with `remote_key`)/`AnyConn`/`LinkSet` + `complete_dial`/`complete_accept` templates + `dial_any` (single scheme match).
- `src/router.rs` API notes: `register()` is once per LINK, `serve()`/`serve_links()` drive slices of it over a caller-owned persistent `LinkSet` (single link or many, mixed transports via `&mut dyn Link` + type-erased `AnyConn`); `resolve()` maps IPv6 addr→node key over DHT (also over the caller's set); `session_send` wraps the `typeSessionTraffic` byte, inbox strips it; `proto_send`/`request_nodeinfo`/`request_debug` frame `typeSessionProto` (replies land in `proto_inbox`); `set_nodeinfo` advertises JSON (≤16384 B); `has_path`/`has_session`/`path_details`/`get_paths`/`get_sessions`/`link_peers`/`dropped_no_link`/`tree_entries` + `dump()` (returns `String`, never prints) are diagnostics; link byte counters come from `links.stats(&peer)` on the caller's set, not from the `Router`. Sends come in two strengths and the choice is load-bearing: **hard** `write()` returns `Err(Error::NoLink)` for a missing peer (use it when the caller addressed a link it just held), **soft** `write_via()` returns `Ok(false)` and increments `dropped_no_link()` (use it for anything addressed from router state — see the stale-books gotcha).
- `src/traffic.rs` — `Traffic` header codec (`path + from + source + dest + watermark + payload`) and the inbound forward/deliver/PathBroken decision. `src/error.rs` — `Error` enum (thiserror). `src/traits.rs` — `Snapshot` trait, implemented in `views.rs`.
- `examples/` (dev-deps only, lib never sees them): `common/` (shared smoltcp `MeshPhy` bridge + `new_iface`/`new_tcp_socket`/`smol_now`, used by all TCP examples and `tests/tcp_loopback.rs` via `#[path]`), `http_fetch` (smoltcp TCP GET), `mesh_tcp` (bilateral TCP, both ends ours), `irc_watch` (smoltcp IRC: register/LIST/JOIN #ru, verified live — first user message caught 2026-09-06), `proto_probe` (nodeinfo/debug exchange with a Go node, verified live), `admin` (yggdrasilctl-compatible adapter: local list/getSelf/getPeers/getTree/getPaths/getSessions + remote getNodeInfo/debug_remoteGetSelf/Peers/Tree via mesh round trips + addPeer/removePeer with live multi-link set rebuilds and Go-style persistent redial with per-URI backoff, verified with real yggdrasilctl), `tun_ping` (kernel TUN↔mesh ICMP round trip, needs TUN privs), `ping6`, `listen_ping`, `oracle_probe` (one payload + ticks), `tcp_proxy` (logging MITM proxy), `hs_answer` (cross-impl handshake helper), `go_capture` (the wire oracle: starts the installed Go 0.5.14 binary from a JSON config, dials its listener, asserts our `meta` is byte-identical to Go's, prints hex for `tests/go_vectors.rs`; needs `unshare -Un --map-root-user`, no Go compiler).
- `tests/`: `mesh_ping.rs` (`#[ignore]`, A↔B ICMPv6 via public peer), `mesh3.rs` (three-node loopback mesh A—B—C: tree convergence, cross-hop DHT resolve, transit forwarding, dead-link eviction, session surviving the eviction — the refactor safety net, ~2.3s), `tcp_loopback.rs` (pure smoltcp driver check, no mesh), `go_vectors.rs` (Go-captured `meta` + envelope frames, pure hex, no privileges — this is what makes the handshake wire claim testable).
- `client/` — the `roots-client` package (workspace member): `src/main.rs` (bin `roots`, thin demo probe — dial + router status), `src/node.rs` (`run_peer`: dial, serve, `?maxbackoff=`-capped redial — the node loop Go's `links.add` runs; its only caller today is
the reconnect test, while `main.rs` still dials a single link), `src/lib.rs` (declares the modules so `client/tests/` can reach them), `tests/reconnect.rs` (drop→redial delivery, ~11s loopback). Grows the config/admin/TUN/multicast halves of Go's node in later slices.
- `reference/` — git submodules holding the Go source of truth (`yggdrasil-go`, `ironwood`); read-only, never edit, see Reference material.
- Build artifacts in `/target` (gitignored). Do not commit.

## Boundary: library vs node client

- **Library (`src/`, lib target)** talks wires and owns state: key/address
  derivation, `meta` handshake, `Transport` impls (`Tcp`/`Tls`/`Ws`/`Wss`/
  `Quic`), frame codec, spanning-tree router, pathfinder/DHT,
  sessions, nodeinfo/debug proto, backoff primitives, plus read-only query
  snapshots (`parent`, `has_path`, `has_session`, `path_details`, `dump`).
  The lib never prints, never opens TUN, never serves admin, and never builds
  a `Router` for a caller — no redial loop, no listener task, no config.
- **`client/` (`roots-client`)** is the node: the `roots` binary plus the
  policy that decides what to do with the library — the `run_peer` redial loop
  today, and the config, admin socket, TUN and multicast slices to come.
  Nothing in it is importable product surface.
- **Root `examples/` + `tests/`** stay demo/debug scaffolding around the lib:
  smoltcp bridges (`examples/common/`), app demos (`http_fetch`, `mesh_tcp`,
  `irc_watch`, `proto_probe`), tools (`ping6`, `listen_ping`, `oracle_probe`,
  `tcp_proxy`, `hs_answer`, `go_capture`, `admin`, `tun_ping`). As slices 4–14
  land, the ones that are really node behaviour move into `client/src/`;
  until then `tun`/`serde_json` must stay in the root `[dev-dependencies]` for
  them (the approved plan's "move to the client" completes slice by slice).

## Reference material (executable truth, in order)

- `docs/plans/rust-client/` — gate docs + `00-status.md` (slice checklist, resume here).
- `docs/protocol/` — the wire reference, one page per format, written from captured Go bytes with offsets and `file:line` citations (`README.md` lists which of the 22 formats have a page). If you change a codec, change its page in the same commit; if a page has no vector behind it, say so on the page.
- `docs/architecture-map.md` — current module graph, `Router` state ownership, frame dispatch table, and the invariant list. `02-architecture.md` is a frozen Slice 1–2 record and is stale; read the map.
- `reference/yggdrasil-go` (submodule, HEAD `422836e` = tag `v0.5.14`, branch `develop`) — Go node impl: `src/core/` link transports (`link_tcp.go`, `link_tls.go`, `link_ws.go`, `link_quic.go`), `src/core/version.go` (`meta` handshake TLVs + signature), `src/address/address.go` (key→IPv6).
- `reference/ironwood` (submodule, HEAD `d50055b`) — routing/session impl: `network/router.go` (spanning tree, SigReq/SigRes/Announce), `network/pathfinder.go` (DHT lookup/notify/broken), `network/bloomfilter.go`, `network/traffic.go`, `network/peers.go` + `network/wire.go` (link framing), `encrypted/session.go` + `encrypted/crypto.go`. Its commit is exactly what `yggdrasil-go` pins in `go.mod`, so the two always agree — trust the pair over any doc.
- Both are shallow (`--depth 1`) clones. Fresh checkout: `git submodule update --init --depth 1`. Never edit or commit inside them; bump a gitlink instead.
- Golden wire vectors live **in the Rust tests** as hex constants: `addr_vector_matches_go`, `subnet_vector_matches_go`, `getkey_lossy_vectors_match_go`, `bloom_vector_matches_go`, `lookup_vector_matches_go`, `notify_vector_matches_go`, `broken_vector_matches_go`, `traffic_vector_matches_go`. The old `vectors.txt` and the `/tmp/opencode/vecgen-ironwood` harness are gone; `TestZZVectors`/`TestZZReplay`/`TestZZHandshake` were local patches, NOT upstream in ironwood (which ships only `TestBloom`/`TestSign`/`TestVerify`/`TestEdX`/`TestTwoNodes`/`TestLineNetwork`/`TestRandomTreeNetwork`/`TestSessionInitPasswordAuth`). Regenerating or adding vectors needs a Go toolchain plus re-adding that harness — **except** for the bytes the capture harness below produces, which need no compiler at all.
- `tests/go_vectors.rs` is a different kind of evidence: hex **captured from the installed Go 0.5.14 binary** (`meta` with both password branches, plus real `SigReq`/`BloomFilter`/`Announce` envelope frames), not transcribed from Go tests. Re-capture with `unshare -Un --map-root-user cargo run -q --example go_capture -- --frames` (see `docs/protocol/20-handshake.md`); it needs the binary and the namespace, never a Go compiler, and never runs in CI. The prose that grows from it is `docs/protocol/` — byte-offset specs with `file:line` citations and a table of which of the 22 formats has a page and which has only a vector.
- Scratch Go oracle nodes are gone: the 127.0.0.1:18233/18234/18235/18236 pair (admin 19001–19004) and its `yggdrasilctl` died with the `/tmp` clones. Rebuild from `reference/yggdrasil-go/cmd/{yggdrasil,yggdrasilctl}` once `devenv.nix` gains `languages.go`.
- The host's own Yggdrasil **service** node is live (NixOS service, 0.5.14, `Listen: []`, no admin socket — a traffic carrier, not a queryable peer). `tun0` is up and owns the `200::/7` route; its address this session (2026-09-24) was `200:a319:38e3:5833:d91e:70da:4c0c:71f0` — re-read it with `ip -6 addr show dev tun0`, never hardcode. It carries `curl -g`/`ping6` cross-checks, and it means any `tun_ping` run must claim its own interface name rather than `tun0`.
- Protocol rule: docs never override wire code. When porting, mirror the Go function (including its quirks) and cite `file:line` in a comment.

## Gotchas

- Capturing from the Go oracle has three traps, all handled inside
  `examples/go_capture.rs`: the node **panics** unless it may create a TUN (so
  run it under `unshare -Un --map-root-user`), a fresh netns has **`lo` down**
  (the harness raises it), and a link whose `meta` carries the **listener's own
  key** is accepted, then closed silently (`ErrLinkToSelf`, `core/link.go:158`,
  checked at :662) — dial with a second identity when you need frames. A frame
  window that yields nothing is that bug, not a dead protocol.
- Announces carry **ancestry only** (Go `network/router.go:321`, mirrored at
  `tree.rs:524`): a node learns its own line to the root and nothing else. In a
  line A—B—C the two ends never learn each other from the tree — so
  `known_nodes()` is not network size, and a query that must reach a
  non-relative goes through the DHT/blooms (`tests/mesh3.rs` pins this).
- `register()` once per link, `serve()` per slice over ONE caller-owned `LinkSet` reused across slices. Rebuilding the set per slice resets per-link send clocks → lazy keepalives never fire → the peer read-times-out the link at ~4s (caught live; the set must outlive slices, like the conn does). Registering per slice re-sends SigReq + replays announces every 250ms (~800 dupes/run) and the peer answers each one — looks exactly like a protocol storm in frame counters.
- `serve()` answers keepalive lazily (Go `peerMonitor` semantics: only after a full idle tick with no sends, plus a top-up on quiet read slices); the link drops in ~4s without it. (Old code replied eagerly to every frame — pure chatter.)
- `serve_links` slices reads (100ms) ONLY when multiplexing 2+ links; a single link blocks for the whole budget (exact old `serve` timing). Slicing a single link flaked `resolve_loopback` to ~50/50 (convergence starved — mechanism unclear, rule stands).
- `SigRes.psig` and announce `sig` cover node + parent + req + **port** — signing the bare req bytes verifies against nothing (caught by `announce_chain_verifies`).
- Session payloads need the `typeSessionTraffic` (1) leading byte (`Core.WriteTo` adds it, `Core.ReadFrom` dispatches on it) — Go silently drops anything else, including valid IPv6 starting with 0x60. Wrap in `session_send`, strip on inbox delivery (live-fetch outage, guarded by `packet_type_constants_match_go`). Same framing for `typeSessionProto` (2): `proto_send` wraps, `handle_proto_bytes` dispatches.
- Crossed simultaneous session opens collide on `seq` (unix seconds in Go) and drop as stale — deadlocking fast crossed opens. Fixed via per-router monotonic `next_init_seq` (wire-compatible: peers only require `seq` greater than last seen) + fresh `next` keys in `apply_update` like Go `_handleUpdate` (we recycled; loopback-symmetric but hygiene-divergent). First-flight payloads on an exact cross may still drop (each side's ack advances key expectations ahead of the other's flushed payload — inherent to the protocol, same in Go); sessions converge and the next flight delivers. Regression test: `crossed_session_open_delivers_both_ways`.
- Pre-session send buffer is a SINGLE slot, last write wins — Go `_bufferAndInit` does `buf.data = msg` unconditionally. Queueing 4 proto requests before the session opens delivers only the last; stagger behind `has_session` (caught live by `proto_probe`: only GETTREE arrived).
- Bloom hashes must be bit-identical Murmur3-x64-128 `sum256` (`bloom.rs`), not any standard murmur3 crate default — verified by `bloom_vector_matches_go`.
- DHT rumors rendezvous by TRANSFORMED key (`xkey`), not dest key — a notify from the full key must match a lookup for a partial key. Keying rumors by dest silently drops all resolutions.
- QUIC links: `QuicStream` keeps the endpoint + connection handles alive (dropping either tears the connection down mid-link); no TCP-style graceful FIN exists, so tests linger the server side instead of asserting post-close reads.
- WS links REQUIRE the `ygg-ws` subprotocol both ways (Go closes violators); binary messages are a byte stream, one message per `flush`. (Known deviation: Go answers `GET /health` with 200 OK; we only upgrade WebSocket on that port.)
- Go has no `wss://` listener ("use WS behind a reverse proxy"); we serve one anyway (same code path as `ws://` over our TLS acceptor), so stock Go can only ever *dial* wss — verify via admin `addPeer`, never via a Go listener.
- One `Router` serves any number of links through a `LinkSet` (`serve_links`; `serve` is the one-entry case). The set owns the conns, so callers keep it across await points and hand it to a task without locks. Dead links are evicted, not fatal — survivors keep serving; the set empties only when the last link dies (preserves the old single-link `serve` contract), and `Router::fatal_link_error(links, e)` is the single gate on that: an I/O or `NoLink` error kills only the link that caused it, anything else is a bug and aborts the serve. `prio`/`order` tiebreaks are recorded per link for the multi-peer future.
- **Stale router books can name a key with no link, and that is the rule to design against** (Slice 4). Nothing prunes `tree.peers`/`tree.infos`/`bloom.on_tree` when a link dies — Go prunes them in `removePeer` (`router.go:147`) and we deliberately do not yet (that is the router-state-lifecycle hardening slice; `a_stale_parent_is_kept_and_the_serve_survives_it` is the tripwire). Consequence: every send addressed **from router state** must be `write_via` (soft) or iterate `links.peers()`, never a hard `write` to a key a book remembered — `_sendReqs` (Go `router.go:189`), the bloom fan-out guard (Go `bloomfilter.go:277`) and `_fix`'s parent check (Go `router.go:229`) all ask the live map, and each of those three has a test that only fails when it is reverted (`router_books_can_name_a_peer_with_no_link`, `fix_refuses_a_parent_with_no_link`). `tests/mesh3.rs` passes under all three reversions; do not treat it as coverage.
- `fix`'s parent-liveness branch is **unreachable in a converged loopback star**: the client is the largest key, so `root_and_dists(self)` never offers a root better than self and the candidate scan skips its own children (same in Go, `router.go:607-628`). Any test of that guard must be built by hand out of `tree.infos`/`responses`/`peers`, like `fix_refuses_a_parent_with_no_link` — no socket timing produces it.
- Assert a failing write with `tokio::io::duplex` and drop the far half. A real loopback socket absorbs a 512-byte write and returns `Ok`, so `a_failed_write_retires_the_link` was flaky until it stopped using one.
- Live-test peers: `tcp://bode.theender.net:42069` (reliable); `yggdrasil.su:62486` throttled us after heavy dialing. Stagger dials; `dial_retry` in the mesh test.
- Env-gated debug tap: `ROOTS_DBG_DUMP` in `client/src/main.rs` prints `Router::dump()` (a `String`; the lib never writes to stderr — fatal `connect/register/link` errors in binaries are the only `eprintln!` paths).

## Commands

- `cargo build --workspace` / `cargo run -q -p roots-client -- <peer-uri> [hold_secs]` (`cargo run` alone picks the lib package, which has no bin)
- `cargo run -q --example http_fetch -- <ipv6> [peer-uri]` (page fetch demo, needs internet)
- `cargo test --workspace` (unit + loopback integration; live tests excluded)
- `cargo test --test mesh_ping -- --ignored --nocapture` (live, ~3 min, needs internet)
- `cargo test -p roots-client --test reconnect -- --nocapture` (~13s, loopback)
- `unshare -Un --map-root-user cargo run -q --example go_capture -- --frames` (re-capture the Go vectors; no Go compiler needed, ~5 s; prints hex to paste into `tests/go_vectors.rs`)
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt` before finishing (`cargo fmt --check` must pass — from the root it already walks every workspace member)
- CI (`.github/workflows/ci.yml`, added 2026-09-24) runs exactly `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` on `ubuntu-latest` with the pinned nightly. No Go, no network peers, no submodule checkout — so anything a slice needs verified must be reproducible by those three. Locally as of writing: all green, 81 unit + 6 integration tests (`mesh3`, `tcp_loopback`, `go_vectors` in the lib; `reconnect` in the client), ~25 s.
