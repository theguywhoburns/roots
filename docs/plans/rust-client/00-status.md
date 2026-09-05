# Status: rust-client (connect to existing Yggdrasil peers)

- Gate 1 — Product: APPROVED 2026-09-04
- Gate 2 — Architecture: APPROVED 2026-09-04
- Gate 3 — Program Design: APPROVED 2026-09-04
- Gate 4 — Slice plan: APPROVED 2026-09-04

## Slices
- [x] Slice 1 — tracer: lib skeleton + `address` + `Meta` codec + TCP `connect` vs PUBLIC `tcp://` peer (outbound handshake, `Transport` trait for compile-time protocols). DONE 2026-09-04: 11 unit tests green, live handshake vs `yggdrasil.su:62486` + `bode.theender.net:42069` (remote keys match public-peers list, Go sends frames).
- [x] Slice 2 — inbound `listen`/`accept` + link liveness (frame codec + keepalive). DONE 2026-09-04: 17 unit tests green; 30s hold vs `yggdrasil.su:62486` shows live `sigreq`/`announce`/`bloom` frames, keepalive replies keep the link up.
- [x] Slice 3 — router core (sigreq/sigres/announce, parent select, self-announce). DONE 2026-09-04: 23 unit tests green; live vs `yggdrasil.su:62486`: parent=Go peer, root=`ygg-hel-1` (`0230:…`), depth 3, 4 known nodes.
- [x] Slice 4 — pathfinder + sessions + traffic (E2E encrypted delivery). DONE 2026-09-04: wire types verified vs Go golden vectors; 38 unit tests green incl. loopback session delivery; `tests/mesh_ping` passes LIVE (A↔B ICMPv6 echo both ways via `bode.theender.net:42069`, traffic frames flowing).
- [x] Slice 5 — `tls://` dial+listen (same handshake over TLS, unauth certs like Go) + generalize router stack over `Transport`. DONE 2026-09-04: 41 unit tests green (TLS loopback handshake+frames, scheme parsing); live vs `tls://bode.theender.net:42169` (pinned key matched): parent=peer, root=`ygg-hel-1`, depth 4, router fully converged over TLS.
- [x] Slice 6 — reconnect with backoff (`?maxbackoff=`, Go `links.add` semantics) + serve re-queue so drops don't lose app payloads. DONE 2026-09-04: 44 unit tests green (backoff sequence, Go-duration parser, maxbackoff URI rules); `tests/reconnect.rs` passes (server drops link 1, client redials after backoff, payload delivered on link 2).
- [x] Slice 7 — demos (`examples/http_fetch.rs` page fetch, `examples/irc_watch.rs` ILITA IRC session) + `Router::resolve()` (addr→key, node + subnet addresses). DONE 2026-09-06: fetched `http://[21e:a51c:…]/` live (HTTP 200, 80694 bytes); joined #en/#ru on irc.acetone.i2p via public mesh (LIST + 66 users, PING/PONG alive, observed live by repo owner as `rootsff3e`). Root cause of the outage along the way: missing `typeSessionTraffic` leading byte (Go drops unknown session packet types silently) — regression test `packet_type_constants_match_go` + wrap/strip in `session_send`/inbox.
- [x] Slice 8 — session-protocol responders + requesters (`src/proto.rs`: nodeinfo + debug getSelf/getPeers/getTree, `examples/proto_probe.rs`). DONE 2026-09-06: 51 unit tests green (4 new: loopback nodeinfo/debug round-trips, Go constant pins, nodeinfo size cap); live vs stock Go oracle BOTH directions — our requests parsed Go's nodeinfo/getSelf/getPeers/getTree, and Go's admin `getNodeInfo`/`debug_remoteGetSelf` returned OUR `{"roots":"proto-probe"}` nodeinfo + key. Gotcha found along the way: pre-session send buffer is single-slot last-wins (faithful to Go `_bufferAndInit`), so requests must stagger behind `has_session`.
- [ ] Slice 9+ — `ws`/`quic`, TUN, admin, multi-peer conn map, Go-style lazy keepalive (we reply eagerly — harmless chatter)

## Remaining work (as of 2026-09-06)
- Code cleanup: DONE 2026-09-06 — `MeshPhy` + `smol_now` + iface/socket helpers factored into `examples/common/` (used by `http_fetch`/`mesh_tcp`/`irc_watch` + `tests/tcp_loopback.rs` via `#[path]`); `Router::dump()` returns `String` instead of printing (lib has zero `eprintln!` paths; `ROOTS_DBG_DUMP` gating lives in `src/main.rs` only); `prio`/`order` reported in `dump()` so no `allow(dead_code)`; `src/main.rs` TCP/TLS branches deduped via generic `run()`; removed leftover `DBGLU`/`DBG learned path` stderr taps.
- Slice 9+: `ws`/`quic` transports, TUN, admin socket, multi-peer conn map, Go-style lazy keepalive (we reply eagerly — harmless chatter).

## Notes for a fresh session
- Go ref cloned at /tmp/opencode/ygg-ref/yggdrasil-go (depth 1, HEAD 422836e). Trust it over docs.
- Roots repo is greenfield binary crate `roots`, nightly, edition 2024.
- Goal: Rust library exposing a client that peers with existing (Go) nodes.
- Acceptance: connect to PUBLIC peers (not just localhost Go), and adding new protocols is easy — transports are compile-time primitives (trait impls, no runtime registration).
- **register() is once per LINK, serve() per slice.** Calling register per slice re-sends SigReq+replays every 250ms (~800 dupes/run, answered as a "storm" by the peer). Same trap applies to any future poll-based driver (see `poll_once` plan).
- Live-test peers: `tcp://bode.theender.net:42069` reliable for peering; `yggdrasil.su:62486` throttled us. Local oracles: stock Go HEAD test nodes on 127.0.0.1:18233 (admin 19001), :18234 (19002, peers node1), :18236 (19004, peers node2); 0.5.14 node on :18235 (admin 19003). System service node (0.5.14, addr 200:b995:…) has TUN — curl/ping via it to cross-check targets.
- Go toolchain: /tmp/opencode/go (1.24.6) + /tmp/opencode/go125 (1.25.5). Vecgen: /tmp/opencode/vecgen-ironwood (`TestZZVectors`, `TestZZReplay`, `TestZZHandshake`, `TestZZDumpAnn`). Golden vectors: /tmp/opencode/ygg-ref/vectors.txt.
