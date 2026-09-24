# Slices: go-client-parity

Build order below. Each slice ends in a state you can run, and every slice
writes the `docs/protocol/` page for the format it just made provable — a page
written later, from memory, rots.

Three ordering rules that are not obvious from the list:

- **The safety net is first.** Slice 1 is the three-node loopback mesh test that
  Gate 1 made a prerequisite. It passes against today's code because today's
  code already does these things — and from Slice 4 onward it is the test that
  catches a bad refactor. Nothing structural lands until it exists.
- **Nothing structural until the oracle is proven.** Slice 2 establishes the
  capture harness against the installed Go 0.5.14 binary. Every vector claim in
  the rest of the plan depends on that mechanism working, and it costs one
  afternoon to find out now instead of at Slice 13.
- **Nothing privileged, until everything else is proven.** TUN is dead last
  (Slice 14) because it needs `CAP_NET_ADMIN` and is a *userland* feature, not a
  library one: no library capability may be gated on a privilege we cannot get
  in CI or in this sandbox. That is why Slice 12 splits the resolve-and-hold
  seam (library, unprivileged, tested) away from the device plumbing (client,
  root, manual).

## The slices

- [x] **Slice 1 — three-node loopback mesh (`tests/mesh3.rs`).** A—B—C over
      loopback TCP, all three routers ours: C resolves A's address through B,
      an A↔C session payload is delivered by B as transit, and after B's link to
      A dies the surviving leg keeps serving. No Go process anywhere.
      *Proves:* the metric denominator's supporting claim — that routing, DHT
      and sessions actually work across a hop, which every single-link test so
      far has assumed. This is the outstanding prerequisite checkbox.
      **Done 2026-09-24:** 2.3 s, 5/5 clean runs, inside `cargo test --locked`
      so CI covers it. Both load-bearing phases are mutation-proven — deleting
      the `links.remove` eviction in `serve_links` fails phase 4, deleting the
      transit write in `traffic.rs::handle_inbound_traffic` fails phase 3.
      **Finding:** `known_nodes()` is not network size. Announces carry ancestry
      only (Go `network/router.go:321`), so in this line A and C each hold 2
      infos and only B holds 3 — the ends never learn each other from the tree.
      Recorded in `docs/architecture-map.md` and `AGENTS.md`.

- [x] **Slice 2 — the capture harness and the first Go `meta` bytes.**
      `examples/go_capture.rs`: write a JSON config, start
      `/run/current-system/sw/bin/yggdrasil -useconf`, dial its `Listen` port
      with our `Tcp`, tee raw bytes both directions, decode the `meta`, exit.
      `tests/go_vectors.rs` holds the hex with a provenance comment;
      `go_meta_handshake_bytes_match_captured` asserts our encoder emits
      byte-identical TLVs and both signature branches (empty password and keyed)
      for the same key. `docs/protocol/10-envelope.md` + `20-handshake.md`
      written from the capture, with the real bytes at real offsets.
      *Proves:* the worst coverage hole (12 of 22 → 14 of 22) is closable here,
      and closes repeatably.
      **Done 2026-09-24:** both `meta` branches are byte-identical to Go 0.5.14
      (123 B, TLVs at 6/12/18/54, signature at 59), a re-run reproduces them
      exactly, and three real Go frames (`SigReq`, `BloomFilter`, `Announce`)
      pin the envelope. `tests/go_vectors.rs` is 3 tests inside
      `cargo test --locked`, pure committed hex — no Go, no namespace, no
      network in CI. Mutation proof: setting `PROTOCOL_MINOR = 6` fails both
      meta tests at offset 15 (the minor value byte); reverted, and the only
      `src/` change left is one roots-`meta`-size assert in `handshake.rs`.
      `docs/protocol/README.md` + `10-envelope.md` + `20-handshake.md` written
      from these bytes.
      **Three traps found, all handled by the harness now** (detail in
      `00-status.md`): Go panics without a private namespace, a fresh netns has
      `lo` down, and a link carrying the listener's own key dies silently as
      `ErrLinkToSelf`. **Gate 3 deviation:** the frames path is a bare
      `TcpStream` plus our own `meta` exchange, not `link::dial` + a read loop,
      and no MITM relay turned out to be needed — `go_relay.rs` is not built.

- [x] **Slice 3 — workspace split; `Client` loses its loop.** `[workspace]
      members = ["client"]` in the root manifest, `[[bin]]` deleted from it,
      `src/main.rs` → `client/src/main.rs`, `run_peer` and `drive` deleted from
      `src/lib.rs`, their redial loop reborn as `client/src/node.rs`. `tun` +
      `serde_json` move from `[dev-dependencies]` to the client's `[dependencies]`.
      *Proves:* `cargo test --workspace` green with Slice 1 still passing, and
      `cargo tree -p roots` shows no client-only dependency. The library no
      longer constructs a `Router` for anyone.
      **Done 2026-09-24:** `cargo test --workspace` green — 71 lib unit tests,
      `mesh3` 2.30 s, `tcp_loopback`, `go_vectors` 3, and `reconnect` 11.0 s now
      running as a client test; `cargo fmt --check`, `cargo clippy --workspace
      --all-targets --locked -- -D warnings` (re-checked with the client targets
      forced dirty) and `cargo metadata --locked` all clean. `cargo tree -p roots
      -e normal` = 15 crates, none client-only. Boundary verified mechanically:
      every remaining `Router::new` in `src/` is below its file's
      `#[cfg(test)] mod tests` line; `client/src/node.rs` is the only non-test
      site. **Deviation:** `tun`/`serde_json` stayed in the root
      `[dev-dependencies]` — root `examples/tun_ping.rs`, `admin.rs` and
      `proto_probe.rs` still need them and only move in Slices 7 and 14, so
      deleting them here would have broken the build; the client declares just
      `roots`, `tokio`, `ed25519-dalek`, `rand`, `hex`. CI gained `--workspace`
      on clippy and test (from a non-virtual root cargo otherwise skips the
      client), and `cargo run` needs `-p roots-client`.

- [ ] **Slice 4 — `LinkSet` owns its links; sends say whether they landed.**
      The lifetime parameter goes away (entries hold `AnyConn`), `inbound` moves
      onto `AnyConn` from `complete_dial`/`complete_accept`, per-link `up`/`rx`/
      `tx` appear, every set-level read goes through `LinkSet::read_frame`, and
      `write` splits into hard `write` (missing link = `Err`) and `write_via`
      (missing link = `Ok(false)` + `dropped_no_link`). Plus the
      `FRAME_KINDS`/`FrameType::ALL` const assertion, since this slice is
      already inside the file. ~15 call sites updated.
      *Proves:* four new tests, and the two silent-failure footguns Gate 2 named
      stop being silent. This is the enabler for the queue in Slice 5; it is the
      scariest diff in the plan, which is why Slice 1 exists.

- [ ] **Slice 5 — one task, one `Router`, a command queue.** `client/src/links.rs`
      (`link_id` dedup exactly as Go's `links.add` — duplicate returns
      `AlreadyConfigured` after kicking the live link) and `Node::run` draining
      `Cmd::{Dial,Drop,Accept,Packet,Quit}` between 50 ms serve slices. Listeners,
      persistent dials and admin all talk through the channel; nobody else
      touches the router.
      *Proves:* a client-crate integration test that starts a `Node`, adds two
      peers over `Cmd`, waits for convergence, then `Drop`s one and asserts the
      other survived — the shape every later client feature needs, without a
      single `Mutex` in `src/`.

- [ ] **Slice 6 — config that Go accepts.** `client/src/config.rs`: the
      Go-shaped `Config` struct with Go's JSON key names, `defaults()`
      mirroring `src/config/defaults_linux.go`, `load`/`generate`, and the
      `-genconf` / `-useconf` / `-json` flags, and the config-to-`LinkOptions`
      wiring — `allowed_keys` is already enforced in `src/link.rs:450-453`, so
      `AllowedPublicKeys` becomes a key in a list rather than a feature.
      *Proves:* `roots -genconf | yggdrasil -useconf -address` prints a real
      Yggdrasil address — the installed Go binary parses what we emit. A
      cross-implementation check with no compiler and no network.

- [ ] **Slice 7 — admin framing parity (tcp + unix, keepalive, error text).**
      `serve_admin` dispatches on scheme like Go (`unix:///…` is Go's Linux
      default, which is how we were wrong to be TCP-only), decodes a stream of
      JSON values, honours `keepalive`, echoes the whole request struct back
      including `keepalive`, and copies Go's error strings.
      *Proves:* `yggdrasilctl` — the real one, installed — pointed at our
      socket answers `list` and `getSelf` over both transports; plus
      `admin_keepalive_honours_second_request` and
      `admin_unix_socket_matches_tcp`.

- [ ] **Slice 8 — `getPeers` says what Go says.** `sort` argument with Go's
      three stable orderings, and the full `PeerEntry` field set fed by Slice 4:
      `up`, `inbound`, `cost` (via `peer_cost`, Go's floor-at-1 millisecond
      number), `uptime`, `bytes_recvd`/`bytes_sent`, `rate_recvd`/`rate_sent`,
      `latency`, `last_error`/`last_error_time`.
      *Proves:* the three sort modes each order a crafted 3-link fixture
      differently, and a live `yggdrasilctl getPeers` against a real node lists
      fields side by side with Go's output on the same page of docs.

- [ ] **Slice 9 — remote queries and `removePeer` stop lying.** Remote
      (`getNodeInfo`, `debug_remoteGet*`) route through `next_hop(key)` instead
      of `links.peers().next()`, and `removePeer` removes only the redial
      entry — Go's comment is explicit: "The peer is not disconnected
      immediately."
      *Proves:* a two-destination test where the wrong-hop choice is
      distinguishable, and `getPeers` still shows a removed-but-live link as up.

- [ ] **Slice 10 — multicast in the library (codec + state machine).**
      `src/multicast.rs`: `Advertisement` encode/decode with Go's
      >=-not-==-length quirk, `membership_hash`, `link_id`, and `Multicast` —
      `set_interfaces`/`announce`/`receive`/`listener_up` returning `Command`s,
      with the 0→15 s per-iface ramp, the exact major **and** minor gate, the
      not-self rule, and hash verification against the receiver's own password.
      No sockets, no `spawn`.
      *Proves:* eight pure unit tests including
      `multicast_ignores_minor_version_mismatch` and `multicast_beacon_ramps_to_cap`.

- [ ] **Slice 11 — multicast in the client (sockets) + a Go-captured beacon.**
      UDP6 `SO_REUSEADDR` bind, `JoinGroup` per link-local address per tick, the
      interface scan and regex match, `Command` → syscalls → `Node`, plus
      `examples/go_capture.rs` extended to sniff a real Go beacon and commit it
      as `GO_MULTICAST_BEACON`. `docs/protocol/a0-multicast.md` from that.
      *Proves:* two nodes on this host discover each other with no config and no
      admin command — the first feature that works with zero operator input.

- [ ] **Slice 12 — resolve-and-hold, the library half.**
      `Router::send_or_resolve` + `pending_routes` over the existing
      `rumors[].pending` flush. No device, no privileges: the test is a
      loopback mesh where the first payload to an unknown destination is
      `Queued`, a lookup goes out, and the notify's arrival delivers it with no
      second call from us.
      *Proves:* the TUN blocker is a queueing seam, not a TUN feature — and the
      seam is verifiable by `cargo test` on an unprivileged box. The client half
      is Slice 14.

- [ ] **Slice 13 — finish the wire table.** Vectors for the remaining
      round-trip-only kinds (tree `SigReq`/`SigRes`/`Announce`, session
      `ack`/`key`, debug payloads) via a `go_relay.rs` MITM between two local Go
      nodes, the pages that document them, and the Gate 1 coverage table
      refreshed to 22 of 22.
      *Proves:* the number in the README is measured, not asserted.

- [ ] **Slice 14 — OPTIONAL: TUN bridge in the client (dead last, userland).**
      Marked optional on approval (2026-09-24): a kernel TUN interface is not a
      library goal and not part of the library — it is one client feature that
      happens to need root. The plan is complete and the product ships without
      it. Doing it at all means `client/src/tun.rs` on its own interface name
      (the host's service node owns `tun0` and the `200::/7` route), wired to
      `Cmd::Packet` and `router.inbox`. It is the only slice that needs `CAP_NET_ADMIN`, so it is
      the only slice that cannot run in CI or in this sandbox — everything
      upstream of it is provable without root, deliberately.
      *Proves:* `ping6` to a mesh address across a kernel TUN interface our
      client created, first packet landing after a queued lookup instead of
      being dropped. Manual, as root, by you — recorded in
      `docs/protocol/`-adjacent notes with the exact command.

## Not slices

Deliberately excluded, recorded so nobody reopens them mid-plan: the missing
`unix://` / `socks://` link transports (real gaps, separate feature), crate
publication, and running Go in CI.

## Stop points

Every slice ends with `cargo fmt --check`, `cargo clippy --workspace
--all-targets --locked -- -D warnings`, `cargo test --workspace --locked` green
(`--workspace` since Slice 3) plus whatever the slice added, and a commit shown
to you. Slices 3, 4 and 5 are the ones worth re-steering after:
they are where the workspace and the link-ownership shape become real, and a
wrong call there costs the most to undo later.
