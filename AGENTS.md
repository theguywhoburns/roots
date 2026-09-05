# AGENTS.md

Rust client for the Yggdrasil encrypted IPv6 mesh, interoperable with the Go implementation. Single package, no workspace, CI, or release process yet.

## Toolchain

- Nightly Rust pinned in `rust-toolchain.toml` (`channel = "nightly"`, edition 2024). Do not downgrade or add a separate toolchain file.
- Toolchain is provisioned by devenv (`devenv.nix`: `languages.rust` with `toolchainFile`). Enter it via `direnv allow` / `devenv shell`; plain `cargo` works once inside.
- Components available: `rustfmt`, `clippy` (`profile = "minimal"` — anything else needs `rustup component add`).
- No `python3` on PATH; use `perl` for one-off text munging. A Go toolchain lives at `/tmp/opencode/go/bin/go` (1.24.6; 1.25.5 at `/tmp/opencode/go125/go/bin/go`, needed for `yggdrasil-go` HEAD) plus reference clones under `/tmp/opencode/ygg-ref/` — see below.

## Layout

- `src/lib.rs` — library root (`Client`, re-exports). `src/main.rs` — thin demo probe (dial + router status), not the product.
- `src/address.rs` — key→IPv6 derivation. `src/handshake.rs` — link `meta` codec. `src/link.rs` — `Transport` trait + TCP dial/listen/handshake, backoff + `?maxbackoff=`/`?sni=` URI opts. `src/tls.rs` — `Tls` transport (rustls/ring, NoVerify like Go InsecureSkipVerify, rcgen self-signed listener). `src/frame.rs` — ironwood link framing + uvarint/path helpers.
- `src/router.rs` — spanning-tree router (owns all protocol state). `src/bloom.rs`, `src/pathfind.rs`, `src/session.rs`, `src/traffic.rs` — `impl Router` protocol extensions + wire types.
- `src/router.rs` API notes: `register()` is once per LINK, `serve()` drives slices of it; `resolve()` maps IPv6 addr→node key over DHT; `session_send` wraps the `typeSessionTraffic` byte, inbox strips it; `has_path/has_session/path_details` + `dump()` are diagnostics.
- `examples/` (dev-deps only, lib never sees them): `http_fetch` (smoltcp TCP GET), `mesh_tcp` (bilateral TCP, both ends ours), `irc_watch` (smoltcp IRC: register/LIST/JOIN #en, verified live), `ping6`, `listen_ping`, `oracle_probe` (one payload + ticks), `tcp_proxy` (logging MITM proxy), `hs_answer` (cross-impl handshake helper).
- `tests/`: `mesh_ping.rs` (`#[ignore]`, A↔B ICMPv6 via public peer), `reconnect.rs` (drop→redial delivery), `tcp_loopback.rs` (pure smoltcp driver check, no mesh).
- Build artifacts in `/target` (gitignored). Do not commit.

## Reference material (executable truth, in order)

- `docs/plans/rust-client/` — gate docs + `00-status.md` (slice checklist, resume here).
- `/tmp/opencode/ygg-ref/yggdrasil-go` — Go node impl; `/tmp/opencode/ygg-ref/ironwood` — routing/session impl (both depth-1 clones).
- `/tmp/opencode/ygg-ref/vectors.txt` — golden wire vectors generated from the Go code via `/tmp/opencode/vecgen-ironwood` (`*_test.go` `TestZZVectors`, plus `TestZZReplay`/`TestZZHandshake` harnesses that verify OUR bytes with Go decoders).
- Local Go oracles (built from HEAD, scratch): test nodes on 127.0.0.1:18233 (admin 19001, meshed via bode), :18234 (19002), :18236 (19004), plus a 0.5.14 node on :18235 (admin 19003). Query with `/tmp/opencode/ygg-go-build/yggdrasilctl -endpoint=tcp://127.0.0.1:1900X <getSelf|getPeers|getTree|getPaths|getSessions>`. The system service node (0.5.14, `Listen: []`) carries live TUN traffic — `curl -g`/`ping` through it cross-checks targets.
- Protocol rule: docs never override wire code. When porting, mirror the Go function (including its quirks) and cite `file:line` in a comment.

## Gotchas

- `register()` once per link, `serve()` per slice. Registering per slice re-sends SigReq + replays announces every 250ms (~800 dupes/run) and the peer answers each one — looks exactly like a protocol storm in frame counters.
- `SigRes.psig` and announce `sig` cover node + parent + req + **port** — signing the bare req bytes verifies against nothing (caught by `announce_chain_verifies`).
- Session payloads need the `typeSessionTraffic` (1) leading byte (`Core.WriteTo` adds it, `Core.ReadFrom` dispatches on it) — Go silently drops anything else, including valid IPv6 starting with 0x60. Wrap in `session_send`, strip on inbox delivery (live-fetch outage, guarded by `packet_type_constants_match_go`).
- Bloom hashes must be bit-identical Murmur3-x64-128 `sum256` (`bloom.rs`), not any standard murmur3 crate default — verified by `bloom_vector_matches_go`.
- DHT rumors rendezvous by TRANSFORMED key (`xkey`), not dest key — a notify from the full key must match a lookup for a partial key. Keying rumors by dest silently drops all resolutions.
- `serve()` answers keepalive to every non-keepalive frame (Go `peerMonitor` semantics); the link drops in ~3s without it. (Known deviation: Go uses a 1s timer cancelled by sends; we reply immediately — harmless chatter.)
- Single link per `Router::serve` today; multi-peer needs a connection map (`write_to_peer` is the seam). `prio`/`order` tiebreaks are wired for it.
- Live-test peers: `tcp://bode.theender.net:42069` (reliable); `yggdrasil.su:62486` throttled us after heavy dialing. Stagger dials; `dial_retry` in the mesh test.
- Env-gated debug taps exist (`ROOTS_DBG_DUMP` in main, `dump()` on Router); lib has no other `eprintln!` paths.

## Commands

- `cargo build` / `cargo run -- <peer-uri> [hold_secs]`
- `cargo run -q --example http_fetch -- <ipv6> [peer-uri]` (page fetch demo, needs internet)
- `cargo test` (unit; live tests excluded)
- `cargo test --test mesh_ping -- --ignored --nocapture` (live, ~3 min, needs internet)
- `cargo test --test reconnect -- --nocapture` (~13s, loopback)
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt` before finishing (`cargo fmt --check` must pass)
