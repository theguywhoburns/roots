# Status: go-client-parity

Feature: make `roots` the library its README promises — a Rust Yggdrasil node
others can embed, with the wire protocol documented well enough to be a
reference — and bring the stitched-in client up to parity with Go's `yggdrasil`
binary so the client is a specimen of the library, not part of it.

- Gate 1 — Product: APPROVED 2026-09-24 (metric refined at Gate 2: 12 of 22 formats guarded today)
- Gate 2 — Architecture: APPROVED 2026-09-24 (option B: `roots` + `client` workspace)
- Gate 3 — Program Design: APPROVED 2026-09-24
- Gate 4 — Slice plan: APPROVED 2026-09-24 (14 slices; Slice 14 marked optional — TUN is userland, not a library goal)

## Prerequisite groundwork (not a gate — decided in chat 2026-09-24)

Verification today is attestation: 71 tests exist, none run automatically, and
every interop claim lives in prose. Agreed scope:

- [x] Static CI — `.github/workflows/ci.yml` written 2026-09-24: `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` on `ubuntu-latest` with the pinned nightly (clippy and test gained `--workspace` in Slice 3 so the client package is covered too). No Go, no submodules, no live peers. All three commands verified green locally (71 unit + 2 loopback integration tests, ~25 s); **not yet observed running on a runner** — first push confirms it.
- [x] Three-node local mesh test — done as Slice 1 (`tests/mesh3.rs`, 2026-09-24): Rust↔Rust↔Rust A—B—C over one loopback listener, asserting tree convergence, a DHT resolve across the hop, transit forwarding through a node that cannot consume the traffic, dead-link eviction, and a session that survives it. Runs inside `cargo test --locked`, so CI covers it.
- [x] Go oracle is available **without a Go toolchain**: `/run/current-system/sw/bin/yggdrasil` (0.5.14, the exact version `reference/yggdrasil-go` pins) takes a JSON config on stdin (`-useconf`, `-genconf -json`). **It does not run unprivileged as written here** — corrected 2026-09-24 during Slice 2: startup ends in `panic: failed to create TUN: operation not permitted` (`cmd/yggdrasil/main.go:282`), so every capture runs inside `unshare -Un --map-root-user`, where TUN creation succeeds in a private net namespace with no real interfaces — and where `lo` starts *down*, which the harness fixes itself. Working command in `docs/protocol/20-handshake.md`. Vectors come from *capturing* it, not from transcribing Go tests. A Go **compiler** is still absent and still only needed for the ironwood `vecgen` harness.
- [ ] Later: same CI workflow shape with a real Go oracle job, scheduled rather than per-push, on the machine that gets `languages.go`.

## Slices

Plan approved 2026-09-24 — details and proof in `04-slices.md`.

- [x] Slice 1 — three-node loopback mesh test (the outstanding prerequisite; the refactor safety net) — DONE 2026-09-24, `tests/mesh3.rs`, 2.3 s, 5/5 clean runs
- [x] Slice 2 — capture harness + first Go `meta` bytes (12/22 → 14/22) — DONE 2026-09-24, `examples/go_capture.rs` + `tests/go_vectors.rs` (3 tests), `docs/protocol/10-envelope.md` + `20-handshake.md`
- [x] Slice 3 — workspace split; `run_peer`/`drive` evicted from `Client` — DONE 2026-09-24, `client/` member (`roots-client`, bin `roots`), `client/src/node.rs`, `client/tests/reconnect.rs`; the lib builds no `Router` outside `#[cfg(test)]`
- [x] Slice 4 — `LinkSet` owns `AnyConn`; hard/soft sends; frame-kind const assert — DONE 2026-09-24, see the "Done 2026-09-24" block under Slice 4 in `04-slices.md` for the mutation-attribution table
- [ ] Slice 5 — one-task node loop + `link_id` dedup command queue
- [ ] Slice 6 — Go-shaped config (proven by Go's own binary parsing it)
- [ ] Slice 7 — admin framing: `unix://`, `keepalive`, Go error strings
- [ ] Slice 8 — `getPeers` content parity: three sort modes + full field set
- [ ] Slice 9 — remote queries via `next_hop`; `removePeer` stops lying
- [ ] Slice 10 — multicast codec + state machine in the library (no sockets)
- [ ] Slice 11 — multicast sockets in the client + captured Go beacon
- [ ] Slice 12 — `send_or_resolve` resolve-and-hold seam (library only, no privileges)
- [ ] Slice 13 — remaining wire vectors + 22/22 coverage refresh
- [ ] Slice 14 — client TUN bridge (dead last: root/`CAP_NET_ADMIN`, userland not library)

## Notes for a fresh session

- **Product identity, settled 2026-09-24:** `roots-rs` is a reimplementation of
  the Go implementation whose second goal is to *document the actual protocol*.
  The library is the product. The client exists to mirror Go's client so the two
  can be compared; Slice 3 (2026-09-24) moved it out of the library into the
  `client/` workspace member (`roots-client`), with root `examples/` left as
  demo scaffolding around the lib. Do not design library APIs around the
  client's convenience.
- Multicast autopeering is **in scope**, as a real Gate 2 slice. Go's
  `src/multicast/` has no counterpart here; the "multicast" hits in
  `src/pathfind.rs` / `src/bloom.rs` are ironwood's DHT flooding gate, unrelated.
- **Gate 3 decisions, drafted 2026-09-24** (detail in `03-program-design.md`):
  workspace member is `client/` under the existing root package (no `crates/`
  move, so every documented path survives); `LinkSet` stops borrowing and owns
  `AnyConn` (this is what makes a command queue possible without locks);
  multicast is a **pure state machine in the library** (`announce`/`receive` →
  `Vec<Command>`) with all syscalls in the client; vectors are **captured from
  the installed 0.5.14 binary** (`examples/go_capture.rs` dials a local Go
  listener, `examples/go_relay.rs` MITMs two), never transcribed from Go tests;
  Go's Linux default `AdminListen` is a **unix socket**, so admin parity now
  includes `unix://`.
- CI must not depend on a Go toolchain: none is installed, `languages.go`
  deliberately stays out of `devenv.nix`, and the oracle **binary** is a Nix
  store path that CI has no reason to have. Vectors are committed hex, so CI
  stays hermetic either way.
- `docs/architecture-map.md` is the current module graph. `02-architecture.md` in
  the `rust-client` plan folder is a frozen Slice 1–2 record and stale.
- The earlier belief that `tree.peers` / `bloom.*` / `tree.sent` "only grow" was
  wrong and has been corrected in the architecture map: node-keyed state does
  expire; only per-link-peer state survives a dead link, on purpose.
- **Slice 1 finding — the tree does NOT distribute the whole tree.** Go
  `_sendAnnounces` (ironwood `network/router.go:321`, comment: "insanely
  delicate … Change nothing here") sends only the ancestry of self plus the
  ancestry of that one peer. In a line A—B—C where B is root, A and C each hold
  two `tree.infos` and never learn each other; only B holds three. The first
  draft of `tests/mesh3.rs` asserted `known >= 3` on all three nodes and failed
  for exactly this reason. Consequence for every later slice: anything that
  needs a node to know a non-relative (admin `getTree` on a big mesh, the
  multicast interface set, `next_hop`) must go through the DHT or the bloom
  filters, not through `tree.infos`.
- The mesh test's two distinctive claims are **mutation-proven**, not assumed:
  deleting the `links.remove` eviction in `serve_links` fails its phase 4, and
  deleting the transit write in `traffic.rs::handle_inbound_traffic` fails its
  phase 3. Both mutations were reverted; `git diff` on `src/` is clean.
- **Slice 2 findings — the oracle mechanism works, three traps in it.**
  - The Go node **panics at startup without privileges** (`failed to create
    TUN: operation not permitted`, `cmd/yggdrasil/main.go:282`). Run captures in
    `unshare -Un --map-root-user`; inside it Go makes a TUN in a private net
    namespace that has no real interfaces, peers over loopback, and never
    touches the host. The status bullet that claimed "runs unprivileged with no
    TUN" was wrong and is corrected above.
  - **A link dialed with the listener's own keypair dies silently.** Go checks
    the remote `meta` public key against its own and returns `ErrLinkToSelf`
    (`link.go:661-663`, `:158`), so the handshake completes, Go closes, and no
    frame ever arrives. That cost an hour of empty captures. `go_capture.rs`
    therefore uses a second identity (`OUR_SEED`) for the `--frames` window and
    Go's seed only to re-sign its own `meta`. **This also invalidates Gate 3's
    capture design**: the plan assumed "`link::dial` handles the handshake, then
    a plain read loop" for the `--frames` path, but `link::dial` consumes the
    remote `meta` inside the handshake and hands back no raw bytes, which is
    exactly what a capture needs. The harness therefore holds a bare
    `TcpStream`, performs the `meta` exchange itself (`read_meta`, then writing
    our re-encoded bytes), and reads envelope frames with `read_frame_raw`. The
    MITM variant (`go_relay.rs`) is unnecessary for this: tee-ing one raw socket
    in both directions is enough, and Slice 2 shipped without it. See
    `examples/go_capture.rs`.
  - `?password=` is capped at `blake2b.Size` = 64 (`link.go:200-205`), which is
    our `MAX_PASSWORD_LEN`; empty and absent are the same unkeyed branch, now
    proven against Go's own bytes rather than asserted.
  - Two more traps, both fixed in the harness rather than remembered: a fresh
    netns has **`lo` down**, so every loopback connect is `ENETUNREACH` (the
    harness runs `ip link set lo up`, which is what its in-namespace
    `CAP_NET_ADMIN` is for), and an orphaned Go child **inherits our stdout**,
    so a panicking capture leaves `go_capture | tail` hanging forever instead of
    reporting the failure (`Go` is now a Drop guard that kills and reaps).
- **Open risk recorded in `docs/protocol/20-handshake.md`:** our vendor and
  features tags are 4 and 5 — the *next* numbers after Go's `iota` block, not
  reserved out-of-band numbers. If upstream adds a real tag 4 or 5 first, Go
  applies its length check to our value and refuses the link. Re-check those two
  numbers whenever `reference/yggdrasil-go` is bumped.
- **Gate 2 findings, decided in the draft (2026-09-24):**
  - `Client`/`Client::run_peer` (`src/lib.rs:47-155`) is node policy inside the
    library and is the one real boundary violation (evicted to
    `client/src/node.rs` in Slice 3). Rule going forward: the
    library never constructs a `Router` for the caller.
  - Cargo forbids `[[bin]]` from using `[dev-dependencies]`, and the client needs
    `serde_json`/`tun`/`smoltcp`. That forces A/B/C — the draft recommends **B: a
    `roots` + `roots-client` workspace**, which supersedes AGENTS.md's "no
    workspace" line and needs its own explicit approval.
  - Wire coverage is **12 of 22 kinds guarded with Go bytes**. The worst hole is
    the `meta` handshake: version, pubkey, priority, vendor/features and the
    keyed-hash signature are only tested by our own encoder agreeing with itself.
    `reference/yggdrasil-go/src/core/version.go` + `version_test.go` make closing
    it mechanical.
  - Admin parity is 12 of Go's 15 commands by name, but several diverge in
    content: `getPeers` ignores Go's three sort modes (`""`/`uptime`/`cost`,
    `admin/getpeers.go:68-76`) and hardcodes `up: true`/`inbound: false` and
    omits `bytes_recvd`/`bytes_sent`/`rate_*`/`uptime`/`last_error*`,
    `keepalive` is never read so the connection dies after one reply, remote
    queries go to `links.peers().next()` instead of resolving the target key, and
    `removePeer` drops the live link (Go: "The peer is not disconnected
    immediately" — `core/api.go:207-211`). Go's `DisallowUnknownFields` call is
    inert, so our leniency about unknown fields already matches.
  - Two library seams are required before TUN or a multi-listener client can
    work: a message-driven single-task command queue in front of `LinkSet`, and a
    public resolve-and-hold entry point over the existing `rumors[].pending` slot.
  - Multicast: group `[ff02::114]:9001`, 104-byte unsigned advertisement
    (major/minor/pubkey/port + 64-byte keyed blake2b-512 membership hash — the
    same construction as our `handshake::keyed_hash`), discovered peers dialed as
    ephemeral `tls://` links that never back off or redial, dedup by
    (uri-minus-query, source interface), interface set rescanned every beacon
    tick. Darwin AWDL needs cgo; everything else is unprivileged.
- **Slice 3 findings — the split is real, the dependency half is deferred.**
  - `cargo run` from the root now **fails**: the root package is lib-only, so the
    bin lives in the other package (`cargo run -q -p roots-client -- <uri>`;
    `cargo run --bin roots` from the root also errors and names the package).
    Anything that scripted the old form — AGENTS.md, `docs/protocol/*`, shell
    history — must say `-p roots-client`.
  - From a non-virtual workspace root `cargo test`/`cargo clippy` only select the
    root package, so CI now runs `--workspace` for both. Without it the client's
    `run_peer` and the reconnect test would go unlinted and unrun. `cargo fmt
    --check` needs no change: from the root it already walks every member.
  - **Deviation from the approved slice text:** the plan moved `tun` +
    `serde_json` from the root `[dev-dependencies]` into the client's
    `[dependencies]` in this slice. Not possible yet — root `examples/`
    (`tun_ping`, `admin`, `proto_probe`) still use them and only leave in Slices
    7 and 14. The client therefore declares only what it actually uses (`roots`,
    `tokio`, `ed25519-dalek`, `rand`, `hex`), and the dev-dep deletion completes
    with those moves. The invariant the slice was for still holds and is
    measurable now: `cargo tree -p roots -e normal` lists 15 crates, none of them
    client-only policy deps.
  - Boundary proof, mechanically: every `Router::new` left in `src/` sits after
    its file's `#[cfg(test)] mod tests` line (`router.rs` 113, `proto.rs` 238,
    `tree.rs` 587 — first uses at 125, 276, 681). `client/src/node.rs` is the
    only non-test site.
  - `client/src/lib.rs` exists solely so `client/tests/reconnect.rs` can call
    `roots_client::node::run_peer`; it is one `pub mod node;`. When Slices 5–7
    add `config`/`links`/`admin` modules they go in that list.
- **Slice 4 findings — the liveness half is proven by reverting it, not by mesh3.**
  - Every behaviour the slice changed was reverted **one at a time** and the
    test that then failed was named; the full table is in `04-slices.md`. Two of
    the three router-state liveness fixes (`send_all_reqs` iterating the live
    set, bloom maintenance using a soft send) are pinned **only** by
    `router_books_can_name_a_peer_with_no_link`, and the `_fix` parent-liveness
    guard only by `fix_refuses_a_parent_with_no_link`. `tests/mesh3.rs` passes
    under all three reversions — it is the safety net for link death, not for
    these. Do not delete those two tests as "redundant with mesh3".
  - **`fix`'s guarded branch is unreachable in a converged loopback star.** The
    client is the largest key, so `root_and_dists(self)` never offers a root
    better than self and the candidate scan skips its own children (Go
    `router.go:607-628` does the same). Any future parent-liveness test has to
    be hand-built the way `fix_refuses_a_parent_with_no_link` is; no socket
    timing produces the scenario.
  - **Found and deliberately NOT fixed:** nothing prunes `tree.peers` /
    `tree.infos` / `bloom.on_tree` when a link dies, where Go's `removePeer`
    (`router.go:147`) prunes peers/sent/ports/requests/responses/resSeqs/ancs/
    cache plus bloom info. The slice's rule is that stale books may name a key
    with no link, so every send addressed from router state must be soft
    (`write_via`) or iterate the live set. `a_stale_parent_is_kept_and_the_serve_
    survives_it` is the tripwire for that; real pruning belongs to the
    router-state lifecycle (hardening) slice, not here.
  - Test-fixture mechanics worth keeping: assert write failure with
    `tokio::io::duplex` and drop the far half — a real loopback socket absorbs a
    512-byte write and returns `Ok`, which made the first version flaky.
    `Transport::Stream: 'static` is required so `AnyConn` can own it.
  - CI trio green at 81 unit + 6 integration tests (~14 s): `cargo fmt --check`,
    `cargo clippy --workspace --all-targets --locked -- -D warnings`,
    `cargo test --workspace --locked`.
