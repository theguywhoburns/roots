# AGENTS.md

Rust client for the Yggdrasil encrypted IPv6 mesh, interoperable with the Go implementation. Single package, no workspace, CI, or release process yet.

## Toolchain

- Nightly Rust pinned in `rust-toolchain.toml` (`channel = "nightly"`, edition 2024). Do not downgrade or add a separate toolchain file.
- Toolchain is provisioned by devenv (`devenv.nix`: `languages.rust` with `toolchainFile`). Enter it via `direnv allow` / `devenv shell`; plain `cargo` works once inside.
- Components available: `rustfmt`, `clippy` (`profile = "minimal"` — anything else needs `rustup component add`).
- No `python3` on PATH; use `perl` for one-off text munging. A Go toolchain lives at `/tmp/opencode/go/bin/go` (1.24.6; 1.25.5 at `/tmp/opencode/go125/go/bin/go`, needed for `yggdrasil-go` HEAD) plus reference clones under `/tmp/opencode/ygg-ref/` — see below.

## Layout

- `src/lib.rs` — library root (`Client`, re-exports). `src/main.rs` — thin demo probe (dial + router status), not the product.
- `src/address.rs` — key→IPv6 derivation. `src/handshake.rs` — link `meta` codec. `src/link.rs` — `Transport` trait + TCP dial/listen/handshake, backoff + `?maxbackoff=`/`?sni=` URI opts. `src/tls.rs` — `Tls` transport (rustls/ring, NoVerify like Go InsecureSkipVerify, rcgen self-signed listener). `src/ws.rs` — `Ws` transport (`ygg-ws` subprotocol, one binary message per flush, byte-stream reads). `src/frame.rs` — ironwood link framing + uvarint/path helpers.
- `src/router.rs` — spanning-tree router (owns all protocol state). `src/bloom.rs`, `src/pathfind.rs`, `src/session.rs`, `src/traffic.rs`, `src/proto.rs` — `impl Router` protocol extensions + wire types.
- `src/router.rs` API notes: `register()` is once per LINK, `serve()` drives slices of it; all router methods take `&mut dyn Link` (`PeerConn<T>` per transport + type-erased `AnyConn`, so one router drives mixed links); `resolve()` maps IPv6 addr→node key over DHT; `session_send` wraps the `typeSessionTraffic` byte, inbox strips it; `proto_send`/`request_nodeinfo`/`request_debug` frame `typeSessionProto` (replies land in `proto_inbox`); `set_nodeinfo` advertises JSON (≤16384 B); `has_path/has_session/path_details` + `dump()` (returns `String`, never prints) are diagnostics.
- `examples/` (dev-deps only, lib never sees them): `common/` (shared smoltcp `MeshPhy` bridge + `new_iface`/`new_tcp_socket`/`smol_now`, used by all TCP examples and `tests/tcp_loopback.rs` via `#[path]`), `http_fetch` (smoltcp TCP GET), `mesh_tcp` (bilateral TCP, both ends ours), `irc_watch` (smoltcp IRC: register/LIST/JOIN #ru, verified live — first user message caught 2026-09-06), `proto_probe` (nodeinfo/debug exchange with a Go node, verified live), `ping6`, `listen_ping`, `oracle_probe` (one payload + ticks), `tcp_proxy` (logging MITM proxy), `hs_answer` (cross-impl handshake helper).
- `tests/`: `mesh_ping.rs` (`#[ignore]`, A↔B ICMPv6 via public peer), `reconnect.rs` (drop→redial delivery), `tcp_loopback.rs` (pure smoltcp driver check, no mesh).
- Build artifacts in `/target` (gitignored). Do not commit.

## Boundary: library vs demo client

- **Library (`src/`, lib target)** talks wires and owns state: key/address
  derivation, `meta` handshake, `Transport` impls (`Tcp`/`Tls`/`Ws`, later
  `wss`/`quic`), frame codec, spanning-tree router, pathfinder/DHT,
  sessions, nodeinfo/debug proto, reconnect/backoff, plus read-only query
  snapshots (`parent`, `has_path`, `has_session`, `path_details`, `dump`).
  The lib never prints, never opens TUN, never serves admin.
- **Demo client (binaries: `src/main.rs`, `examples/`)** decides what to do
  with it: dial by scheme, hold, dump, smoltcp bridges (`examples/common/`),
  app demos (`http_fetch`, `mesh_tcp`, `irc_watch`, `proto_probe`), debug
  tools (`ping6`, `listen_ping`, `oracle_probe`, `tcp_proxy`, `hs_answer`).
  Future app-layer work lives here: yggdrasilctl-compatible admin adapter
  (thin mapping over lib queries), TUN plumbing (TUN crate stays a
  demo-dep, packets cross via `inbox`/outbox), `main.rs` growing from probe
  into a small client.

## Reference material (executable truth, in order)

- `docs/plans/rust-client/` — gate docs + `00-status.md` (slice checklist, resume here).
- `/tmp/opencode/ygg-ref/yggdrasil-go` — Go node impl; `/tmp/opencode/ygg-ref/ironwood` — routing/session impl (both depth-1 clones).
- `/tmp/opencode/ygg-ref/vectors.txt` — golden wire vectors generated from the Go code via `/tmp/opencode/vecgen-ironwood` (`*_test.go` `TestZZVectors`, plus `TestZZReplay`/`TestZZHandshake` harnesses that verify OUR bytes with Go decoders).
- Local Go oracles (built from HEAD, scratch): test nodes on 127.0.0.1:18233 (admin 19001, meshed via bode), :18234 (19002), :18236 (19004), plus a 0.5.14 node on :18235 (admin 19003). Query with `/tmp/opencode/ygg-go-build/yggdrasilctl -endpoint=tcp://127.0.0.1:1900X <getSelf|getPeers|getTree|getPaths|getSessions>`. The system service node (0.5.14, `Listen: []`) carries live TUN traffic — `curl -g`/`ping` through it cross-checks targets.
- Protocol rule: docs never override wire code. When porting, mirror the Go function (including its quirks) and cite `file:line` in a comment.

## Gotchas

- `register()` once per link, `serve()` per slice. Registering per slice re-sends SigReq + replays announces every 250ms (~800 dupes/run) and the peer answers each one — looks exactly like a protocol storm in frame counters.
- `SigRes.psig` and announce `sig` cover node + parent + req + **port** — signing the bare req bytes verifies against nothing (caught by `announce_chain_verifies`).
- Session payloads need the `typeSessionTraffic` (1) leading byte (`Core.WriteTo` adds it, `Core.ReadFrom` dispatches on it) — Go silently drops anything else, including valid IPv6 starting with 0x60. Wrap in `session_send`, strip on inbox delivery (live-fetch outage, guarded by `packet_type_constants_match_go`). Same framing for `typeSessionProto` (2): `proto_send` wraps, `handle_proto_bytes` dispatches.
- Pre-session send buffer is a SINGLE slot, last write wins — Go `_bufferAndInit` does `buf.data = msg` unconditionally. Queueing 4 proto requests before the session opens delivers only the last; stagger behind `has_session` (caught live by `proto_probe`: only GETTREE arrived).
- Bloom hashes must be bit-identical Murmur3-x64-128 `sum256` (`bloom.rs`), not any standard murmur3 crate default — verified by `bloom_vector_matches_go`.
- DHT rumors rendezvous by TRANSFORMED key (`xkey`), not dest key — a notify from the full key must match a lookup for a partial key. Keying rumors by dest silently drops all resolutions.
- `serve()` answers keepalive to every non-keepalive frame (Go `peerMonitor` semantics); the link drops in ~3s without it. (Known deviation: Go uses a 1s timer cancelled by sends; we reply immediately — harmless chatter.)
- WS links REQUIRE the `ygg-ws` subprotocol both ways (Go closes violators); binary messages are a byte stream, one message per `flush`. (Known deviation: Go answers `GET /health` with 200 OK; we only upgrade WebSocket on that port.)
- Single link per `Router::serve` today; multi-peer needs a connection map (`write_to_peer` is the seam). `prio`/`order` tiebreaks are wired for it.
- Live-test peers: `tcp://bode.theender.net:42069` (reliable); `yggdrasil.su:62486` throttled us after heavy dialing. Stagger dials; `dial_retry` in the mesh test.
- Env-gated debug tap: `ROOTS_DBG_DUMP` in `src/main.rs` prints `Router::dump()` (a `String`; the lib never writes to stderr — fatal `connect/register/link` errors in binaries are the only `eprintln!` paths).

## Commands

- `cargo build` / `cargo run -- <peer-uri> [hold_secs]`
- `cargo run -q --example http_fetch -- <ipv6> [peer-uri]` (page fetch demo, needs internet)
- `cargo test` (unit; live tests excluded)
- `cargo test --test mesh_ping -- --ignored --nocapture` (live, ~3 min, needs internet)
- `cargo test --test reconnect -- --nocapture` (~13s, loopback)
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt` before finishing (`cargo fmt --check` must pass)
