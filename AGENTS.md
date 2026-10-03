# AGENTS.md

Rust client for the Yggdrasil encrypted IPv6 mesh, wire-interoperable with the
Go implementation. Two packages: root `roots` (lib = the product) and `client/`
(`roots-client`, bin `roots` = the node). Goals are interop and a *documented*
wire; there is no release process, and CI is three local commands.

## Read these instead of this file

- `docs/architecture-map.md` — current module graph, state ownership, frame
  dispatch table, and **the invariant list ("things that break silently")**.
  Read it before editing anything in `src/`.
- `docs/plans/go-client-parity/00-status.md` — the live plan: slice checklist,
  resume point, and the findings of every finished slice. `04-slices.md` holds
  the next slice's spec and each slice's proof. `docs/plans/rust-client/` is the
  closed library plan.
- `docs/protocol/README.md` — which of the 22 wire formats have a page and which
  only a vector. **Change a codec and you change its page in the same commit.**
- `TODO.md` — three open questions, each with the measurement behind it.
- `docs/plans/*/02-architecture.md` are frozen approval records and are stale.

## Toolchain and environment

- Nightly Rust is pinned in `rust-toolchain.toml` (edition 2024) and provisioned
  by devenv (`devenv.nix` → `direnv allow`). Only `rustfmt` + `clippy` are
  installed (profile `minimal`); anything else needs `rustup component add`.
- **No `python3`** on PATH (use `perl`) and **no `go`**. The installed Go 0.5.14
  binaries (`/run/current-system/sw/bin/yggdrasil`, `yggdrasilctl`) are how wire
  bytes get *captured*; regenerating vectors from Go source needs
  `languages.go` added to `devenv.nix` first (yggdrasil-go wants go ≥ 1.25).
- `reference/yggdrasil-go` (v0.5.14, `422836e`) and `reference/ironwood`
  (`d50055b`, exactly what the Go node pins) are shallow, read-only submodules
  and the executable source of truth — trust them over any doc, including this
  file. `git submodule update --init --depth 1` on a fresh checkout; bump the
  gitlink, never edit or commit inside them.
- Rule when porting: mirror the Go function including its quirks, and cite
  `file:line` in the comment. Docs never override wire code.
- The Go node **panics at startup without TUN privilege**, a fresh netns has
  **`lo` down**, and a link dialled with the **listener's own key** is accepted
  then silently closed (`ErrLinkToSelf`). Every capture and proof therefore runs
  under `unshare -Un --map-root-user`; `examples/go_capture.rs` handles all
  three internally (it dials with a second identity to get frames).
- The host's own yggdrasil **service** node is live (0.5.14, no admin socket) and
  `tun0` owns `200::/7`; re-read its address with `ip -6 addr show dev tun0`,
  never hardcode. It is useful as a traffic carrier, and any TUN run must claim
  its own interface name.

## Commands

- `cargo build --workspace`; run the node: `cargo run -q -p roots-client -- [peer-uri] [hold_secs] [resolve-ipv6]`
  (plain `cargo run` from the root **fails**: that package is lib-only).
- `cargo test --workspace` — ~25 s, 181 tests, loopback only.
  Narrow it: `cargo test -p roots --lib <filter>`, `cargo test -p roots --test mesh3`,
  `cargo test -p roots-client --test peer_rows -- --nocapture`.
- `cargo test -p roots --test mesh_ping -- --ignored --nocapture` — live, needs
  internet, ~3 min, dials `tcp://bode.theender.net:42069`.
- `cargo run -q --example http_fetch -- <ipv6> [peer-uri]` (and the other demos
  in `examples/`); `ROOTS_DBG_DUMP=1` makes the probe path print `Router::dump()`
  (the library never writes to stderr itself).
- `cargo clippy --workspace --all-targets --locked -- -D warnings`, then
  `cargo fmt` — those plus the test command are exactly what CI runs
  (`.github/workflows/ci.yml`: fmt, clippy, test, on `ubuntu-latest`, pinned
  nightly, no Go, no peers, no submodules). Anything a slice needs proven must be
  reproducible by those three.
- Re-capture the Go vectors: `unshare -Un --map-root-user cargo run -q --example go_capture -- --frames`
  (needs the Go binary + the namespace, never a Go compiler, never CI); paste the
  hex into `tests/go_vectors.rs` and update `docs/protocol/20-handshake.md`.
- Config interop proof, unprivileged and offline: `./target/debug/roots -genconf | yggdrasil -useconf -address`
  and `yggdrasil -genconf -json | ./target/debug/roots -useconf -address`; for a
  fixed identity feed the same `{"PrivateKey": …}` to both and compare
  `-address`, `-subnet`, `-publickey` (one flag per run — the first wins).
- Admin/`getPeers`/multicast/TUN proofs, each in its own netns and each
  **rebuilding the binary first** (a stale `target/debug/roots` fakes a green
  run): `unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/{7-admin,7-admin-raw,8-getpeers,9-multicast,10-tun}.sh`
  (each re-execs itself into the namespace, so `sh proof/N.sh` is enough).
  `yggdrasilctl` selects the socket with `-endpoint` (no `-admin_socket`; with
  none set it talks to the host's service node). `10-tun.sh` is the only one that
  needs `CAP_NET_ADMIN` *and* two namespaces, so it builds a veth pair and moves
  an end into each child by pid — `ip netns add` needs a writable `/run/netns`
  that a `unshare -Urn` does not have (measured: `Permission denied`).

## Boundaries

- The **library** talks wire and owns state: crypto, `meta`, the five
  transports, framing, tree/DHT/bloom/session/proto, read-only snapshots. It
  never prints, never opens a TUN, never serves admin, and **never builds a
  `Router` for a caller**. Check that mechanically:
  `grep -n "mod tests" src/*.rs` (every `Router::new` in `src/` must sit
  *below* its file's test module) and `cargo tree -p roots -e normal` (must
  list no `smoltcp`, `tun` or `serde_json`).
- **`client/`** is the only package that drives a `Router`. `Node::run` in
  `client/src/node.rs` is the one production loop: it owns `Router` + `LinkSet` +
  the mailbox, so there are no locks — and therefore **nothing off-task may
  touch them**. Listeners, the admin socket, and future multicast/TUN code send
  a `Cmd`; redial has exactly one owner (`Links::start_due`). Dialling is the
  sole off-task exception and earns it by reading no router state.
  `client/src/main.rs` builds one too, but only in the demo probe (no config).
- Cargo forbids `[[bin]]` from using `[dev-dependencies]`, which is why the
  workspace exists. `smoltcp` stays in the root manifest for `examples/common/`
  (shared by `ping6`, `mesh_tcp`, `http_fetch`, `irc_watch` and the live
  `mesh_ping` test); `tun` moved to `client/` with Slice 14, the last thing that
  opened a device.
- Root `examples/` and `tests/` are demo/debug scaffolding around the lib. When
  one turns out to be node behaviour it **moves into `client/src/` and the
  example is deleted** (Slice 7 deleted `examples/admin.rs`, Slice 14 deleted
  `examples/tun_ping.rs`; `examples/common/` is the last one, and only then can
  `smoltcp` leave the root manifest).
- **The library never opens a TUN.** `tun` is a `roots-client` dependency and the
  device is a field on `Node`, because the bridge reads the router's session
  inbox and calls `send_or_resolve` — `&mut Router` and `&mut LinkSet`, which is
  the one thing in the client that must not have a lock. So a slice that needs a
  device proves its *logic* with `tokio::io::duplex` (see the
  `AsyncReadWrite` seam in `client/src/tun.rs`) and its *device* with
  `proof/10-tun.sh`.

## Silent-failure traps

Full statements, with the Go line each mirrors, are in the architecture map.

- **One `LinkSet` per link collection, reused across `serve` slices.** Rebuild
  it per slice and the per-link send clocks reset: lazy keepalives never fire and
  the peer read-times-out the link at ~4 s. `register()` is once per link;
  per-slice registration replays SigReq + announces every tick, which the peer
  answers as a protocol storm.
- Every `dispatch_frame` arm ends with `keepalive_if_idle`; a new arm without it
  kills its link in ~4 s. `serve_links` slices reads to 100 ms **only** when it
  multiplexes 2+ links — a single link blocks for the whole slice budget.
- **Router books outlive links.** Nothing prunes `tree.peers`/`tree.infos`/
  `bloom.on_tree` on link death (Go's `removePeer` does), so any send addressed
  *from router state* must be soft `write_via` or iterate `links.peers()`; hard
  `write` is only for a link the caller just held.
- `LinkSet` is one entry per **link** and `LinkId` is the addressing unit, so a
  second link to a key we already hold is a second entry, not a displacement. A
  peering dialled both ways gives two live rows, one per direction, and does not
  flap — measured against a live Go node (`proof/8-getpeers.sh` phase C). Never
  assume a `LinkId` you hold stays live: `stats(id) == None` means *that
  connection* is gone, not that the peer is. Read the peer off the row.
- Session and proto payloads need their leading type byte (1 = traffic, 2 =
  proto); Go silently drops anything else, IPv6 included, and **exactly one
  layer adds it** — adding a second is just as fatal and looks right. The
  pre-session send buffer is a **single slot, last write wins** — stagger behind
  `has_session`.
- A TUN device is addressed `/128`, so a mesh address has **no route** until
  somebody adds one (a mesh address comes from a key, not an advertisement).
  Without the *reverse* route the far end's kernel receives your ping, cannot
  route its own reply, and drops it — so the sender sees 100% loss while the
  receiver's log shows the request arriving perfectly.
- Announces carry **ancestry only**, so `known_nodes()` is not network size and
  `tree.infos` cannot find a non-relative (DHT/blooms must).
- Byte-exactness: bloom hash is Murmur3-x64-128 `sum256` (not a stock crate
  default); DHT rumors key by the **transformed** key; `SigRes.psig` and the
  announce `sig` cover node + parent + req + **port**; link counters use
  `frame::wire_len()` in both directions.
- `ws://` requires the `ygg-ws` subprotocol both ways, and a `QuicStream` must
  hold its endpoint + connection handles or the link dies mid-flight.
- Admin: every body is a `struct`, never `json!` (`serde_json::Map` is a
  `BTreeMap`, so a map body prints alphabetically where Go prints declaration
  order); erase the types with the closed `enum Body` — `Box<dyn Serialize>` is
  not object-safe; validate `arguments` before dispatch; sort with the local
  `sort_stable`, never `sort_by` (Go's comparator truncates floats and is not a
  total order, so `sort_by` panics on large row counts).
- The admin socket answers **all 14 of Go's commands**. An unknown action must
  answer Go's verbatim `unknown action '…', try 'list' for help`.
- A **payload from the app is a session message, not a traffic frame.** Ironwood
  layers app → session → pathfinder → link, and the far end dispatches on the
  session's leading type byte and drops anything else — silently, with the
  counter still moving. Reaching `pathfinder_send` from application code is the
  bug: measured as 100% ICMP loss over a link that was `up: true` on both ends.
  Application payloads go through `send_or_resolve`; `net_send` is the only
  caller of `pathfinder_send`, and a held payload carries the flag saying which
  layer it belongs to.
- Config is a wire format: Go's key set *and order*, struct-level
  `#[serde(default = "defaults")]` (Go parses the document on top of a generated
  config), a recursive `strip_nulls` (a JSON `null` is an absent key at every
  depth), `-genconf` blanks `AdminListen` so `omitempty` drops it, and addresses
  print through `Ipv6Addr` because that is Go's text form.
- `AllowedPublicKeys` gates **inbound only**, an empty list admits everyone, and
  a refusal is invisible to the peer (Go checks after writing its own `meta`, so
  the dialer's handshake "succeeds").
- `Cmd::Drop` cancels the redial but **keeps** the live link — a divergence we
  own, not Go's behaviour (Go closes the connection); Slice 9 owns the decision.
- To assert a failing write use `tokio::io::duplex` and drop the far half: a real
  loopback socket absorbs a 512-byte write and returns `Ok`.

## Testing notes

- `tests/mesh3.rs` (A—B—C loopback, ~2.3 s) is the refactor safety net, but it
  passes under reversions of the soft-send and parent-liveness guards. Their only
  coverage is `router_books_can_name_a_peer_with_no_link` and
  `fix_refuses_a_parent_with_no_link` — do not delete them as redundant. `fix`'s
  parent-liveness branch is unreachable in a converged loopback star (the client
  is the largest key), so such a test must be hand-built from `tree.infos` /
  `responses` / `peers`; no socket timing produces it.
- **One `cargo test` at a time.** A second suite, or a proof script that runs
  `cargo build`, starves `mesh3`'s 50 ms-tick convergence and fails it. Re-run
  alone before believing a failure.
- Most client tests are mutation-pinned (the reverts and the test each one killed
  are tabulated per slice in `docs/plans/go-client-parity/04-slices.md`). Prefer
  adding a revert-and-run step to a new behaviour over asserting it by review.
- Live peers: `tcp://bode.theender.net:42069` is reliable; `yggdrasil.su:62486`
  throttled us. Live tests are `#[ignore]`d and never run in CI.
