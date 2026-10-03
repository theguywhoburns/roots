# Status: go-client-parity

Feature: make `roots` the library its README promises — a Rust Yggdrasil node
others can embed, with the wire protocol documented well enough to be a
reference — and bring the stitched-in client up to parity with Go's `yggdrasil`
binary so the client is a specimen of the library, not part of it.

- Gate 1 — Product: APPROVED 2026-09-24 (metric refined at Gate 2: 12 of 22 formats guarded today — **that figure is the gate's, and it counts Go's own test expectations; see "Slice 13" below for the measured split**)
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
- [x] Slice 5 — one-task node loop + `link_id` dedup command queue — DONE 2026-09-24, `client/src/links.rs` + `client/src/node.rs` (`Cmd`/`Node::run`), `client/tests/node_loop.rs`; `run_peer` deleted, `reconnect.rs` moved onto `Node`; mutation table in `04-slices.md`
- [x] Slice 6 — Go-shaped config (proven by Go's own binary parsing it) — DONE 2026-09-24, `client/src/config.rs` + `client/src/main.rs` flags + `client/tests/allowlist.rs` + `tests/go_vectors.rs` address/subnet string vectors; `src/address.rs` `Display` fixed to Go's text form
- [x] Slice 7 — admin framing: `unix://`, `keepalive`, Go error strings — DONE 2026-09-24, `client/src/admin.rs` + `client/src/listen.rs` + `boot()` in `client/src/main.rs` + `client/tests/admin_loopback.rs` (6 tests) + `docs/protocol/21-admin.md` + `proof/7-admin.sh`/`7-admin-raw.sh`/`7-admin-inbound.sh`; `examples/admin.rs` deleted; proven against a live Go 0.5.14 node and stock `yggdrasilctl` over tcp **and** unix, mutation table in `04-slices.md`
- [x] Slice 8 — `getPeers` content parity: three sort modes + full field set — DONE 2026-09-25, `LinkId` + `stats(id)` + `update_rates` + `AnyConn::remote_addr` in `src/link.rs`, SigReq/SigRes latency stamps in `src/tree.rs`, `LinkKind::Incoming` rows in `client/src/links.rs`, the 16-field body and Go's three `sort` modes in `client/src/admin.rs`; `client/tests/peer_rows.rs` (3 tests) + `proof/8-getpeers.sh` (five phases, `7-admin-inbound.sh` superseded); mutation tables and the crossed-peering flap in `04-slices.md`
- [x] Slice 9 — remote queries via `next_hop`; `removePeer` stops lying — DONE 2026-09-28, `Cmd::Remote`/`RemoteQuery` + the node's pending-request table in `client/src/node.rs`, the four commands in `client/src/admin.rs`, `Router::forget_link`, `Links::live_id`, `client/tests/remote_queries.rs` (5 tests). The plan's wrong-hop complaint was already fixed by the crossed-peering refactor (the `links.peers().next()` scope argument is gone from the whole session/pathfind chain); what was missing was the commands. **`removePeer` now closes the link**, matching Go's `links.remove` (`core/link.go:433-438`) — Slice 5's divergence rested on the comment at `core/api.go:207-211`, which reading Go disproves. Also `?password=` is percent-decoded, which multicast needs.
- [x] Slice 10 — multicast codec + state machine in the library (no sockets) — DONE 2026-09-28, `src/multicast.rs`, 8 tests, 20/20 mutation reversions killed
- [x] Slice 11 — multicast sockets in the client + captured Go beacon — DONE 2026-09-29, `client/src/multicast.rs` + `getMulticastInterfaces` + `proof/9-multicast.sh`. **Five bugs found by running two nodes, none of which reading Go would have found**: the `if_inet6` scope column, a named zone not resolving through `getaddrinfo`, rustls refusing a zoneless IP as a server name, one socket being unable to say which interface a datagram arrived on, and a beacon gated on a port nothing ever reported. Details in the commit message and below.
- [x] Slice 12 — `send_or_resolve` resolve-and-hold seam (library only, no privileges) — DONE 2026-09-28, `Router::send_or_resolve` + `Route` in `src/driver.rs`, `pending_routes`/`next_hop` in `src/views.rs`, `tests/resolve_queue.rs` (3 tests), 5/5 reversions killed. Three places the plan doc was wrong (`via` is a `LinkId` not a key; the flush is one layer deeper than cited; `Route` is ours, not Go's).
- [x] Slice 13 — remaining wire vectors + a 22/22 coverage refresh. **Partly
  done, and the refresh was worth more than the vectors.** `SigRes` and
  `SigRes.psig` are now captured from the installed binary — `examples/go_capture.rs
  --frames` grew a `SigReq` + `Announce` exchange for exactly this — and
  `SigReq`/`Announce`/`BloomFilter` are *decoded and asserted* rather than only
  envelope-checked, in `go_tree_payloads_match_captured`. Plus a page,
  `docs/protocol/30-tree.md`. The finding is in the section below.
- [x] Slice 14 — client TUN bridge (dead last: `CAP_NET_ADMIN`, cannot run in CI)
  — DONE 2026-09-29, `client/src/tun.rs` + `Node::open_tun`/`Cmd::Tun` in
  `client/src/node.rs` + `getTun` in `client/src/admin.rs` + `proof/10-tun.sh`
  (green, both directions) + `examples/tun_ping.rs` deleted and `tun` moved to
  `client/Cargo.toml`. **The device found a library bug that no unit test could:**
  `send_or_resolve` was reaching below the session layer, so a TUN payload left
  unboxed and with no type byte and was silently dropped by the far end —
  100% ICMP loss over a link that was `up: true` on both ends. Fixed in
  `53c6d36`; the test that should have caught it was reading plaintext off a
  wire tap, which no working mesh ever sends. Details below.

## Slice 13 — the coverage count was wrong, and measuring it was the work

The number this project has carried since Slice 2 is "14 of 22 formats guarded
by captured Go bytes". It was never refreshed, and it was counting things it
should not have. Slice 13's real output is a table that labels every format with
the provenance it actually has (`docs/protocol/README.md`), and the honest split
of the 22 is:

**9 captured · 6 transcribed · 3 round-trip or semantics only ·
4 unguarded**

Three findings are worth keeping:

1. **"Guarded" had been counting Go's own test expectations.** The address
   vectors are byte-identical to
   `reference/yggdrasil-go/src/address/address_test.go`, and
   `examples/go_capture.rs`'s own header says transcribed expectations "prove
   nothing about our bytes". So the count was crediting the wrong oracle. The
   vectors are still worth having; they are labelled now.
2. **A captured bloom payload was sitting in `tests/go_vectors.rs` guarding
   nothing.** `FRAME_BLOOM` was used only by the envelope test, which never
   called the bloom decoder. One assertion converts it, and it pins the flag
   *block order* — which nothing else did, because swapping the two blocks is
   self-consistent. That swap is now killed by
   `the_flag_layout_is_flags_then_data`.
3. **The bloom's bit order *within* a byte could not be captured from this
   harness — and then it could, once the harness was fixed.** Go's first filter
   was empty, and an all-ones flag block has every position set, so MSB-first and
   LSB-first encoders produce identical bytes — measured, by reversion, against a
   comment that claimed otherwise. At the time the harness could not get a
   non-empty filter at all, and the honest answer was a generator vector.

   The reason it could not is `_fixOnTree` (`ironwood/network/bloomfilter.go:145-174`),
   which puts a peer on the routing tree only if it is Go's parent or Go is its
   parent. A node announcing **itself as its own parent** — what the harness
   sent, because that is the shape a node with no upstream uses — satisfies
   neither arm, sits off the tree, and is skipped by every multicast
   (`:306-308`). So Go's filter stayed empty and said nothing about bit order.

   Announce Go as our parent instead, reuse the `SigRes` Go already sent us for
   the `psig`, and Go advertises a filter with 8 data words in it, 96 bytes,
   deterministically. `the_flag_bit_order_matches_a_go_payload` now pins the bit
   order against the **installed binary**; three mutants killed, including the
   `0x80 >>` versus `1 <<` swap that no earlier vector could touch.

   The lesson is the one from phase C: a documented gap is sometimes a harness
   defect wearing a protocol costume. "Go will not re-advertise a non-empty
   filter" was true of the *harness*, not of Go.

Still open, and each is a *capture* rather than a typing job: **session `ack`**
has no captured bytes, which means answering Go's `init` from
`examples/go_capture.rs` — the payload is sealed to *our* key, so the harness
holds it, but Go never opens one here; the **keyed** multicast hash branch rests
on CPython rather than on Go, because every beacon we have — including the one
`proof/9-multicast.sh` now captures from a Go node beaconing on a veth — takes
the unkeyed branch; and 17 of the 22 formats still have no page.

Session *rotation* is no longer on that list and never should have been written
that way: there is no `key` message in ironwood 0.5.14, so "rotation is
exercised by no test" was never a capture gap. It was a typing gap, and it is
now closed — three tests in `src/session.rs`, four of four mutants killed, plus
the finding that a one-sided rotation is a window in which only the rotated
direction carries traffic. Go's own source carries a `// TODO test this` beside
that arm, so the claim it makes is the claim Go can make.

## Slice 14 — what a real device found

The TUN is the first thing here that touches a kernel, and the first thing that
found bugs by *being wrong visibly* rather than by being wrong silently.

1. **`send_or_resolve` shipped the payload in the clear** (`53c6d36`). Ironwood
   layers app → session → pathfinder → link, and `ipv6rwc` calls `core.WriteTo`,
   not the pathfinder. Reaching `pathfinder_send` from application code put an
   IP packet where a sealed session blob belongs: no box, no type byte, dropped
   by `handle_session_bytes` with the frame counter still moving. The empty test
   suite could not see it because `tests/resolve_queue.rs` proved delivery by
   byte-scanning a link tap — and a plaintext tap passes *precisely because of*
   the bug. It now reads the destination's session inbox, which is the only
   place a delivered payload is readable, and is a stronger claim besides.
2. **`fe80::/10` was not `fe80::/10`.** The first mask tested the second byte's top
   two bits for `00`, which excludes *every* link-local address. The boundary
   test (`fe80` in, `febf` last in, `fec0` first out) is what caught it.
3. **A node's own subnet is not a forward filter.** The device filtered on
   `subnet_for_key` and so rejected every peer address — the filter's own
   documentation said "what the operator configured", and no operator
   configuration produces it. `0200::/7` is the rule, and it covers routed
   subnets for free because a subnet prefix is `03…` and a node address is
   `02…`.
4. **`flush` reported a held packet it had already dropped**, and the doc said
   the caller put it back. The caller does not; there is no caller. A failed
   write is an error (the device is gone) and the tail goes back on the way out.
5. **`pump` allocated `MTU + 64` bytes every tick** — 64 KiB twenty times a
   second at a config's default `IfMTU`. The buffer is a field now.
6. **A mesh address has no route.** A TUN is addressed `/128`, so without a
   hand-added route the kernel cannot even start: the sender's ping leaves,
   arrives, and the *far* kernel drops its own reply because it cannot route
   back. Both directions of the route are installed before the first ping in
   `proof/10-tun.sh` for that reason — and the symptom, "100% loss with the
   receiver's log looking perfect", is worth writing down.
7. **A link-local peering URI's zone names the *local* interface**, and both
   ends need *different* addresses. Getting either wrong fails indistinguishably
   — `getaddrinfo: Name or service not known` for a crossed zone, `connection
   refused` from your own listener for a duplicated address. The multicast proof
   never hit either, because a multicast group is addressed to a group.

## Slice 11 — what running two nodes found

Recorded because the argument generalises: **the socket half of a protocol cannot
be reviewed, only run.** All five were silent — no error, no log, a node that
simply reported no peers.

1. `/proc/net/if_inet6`'s scope is **column 4**; column 2 is the ifindex. Reading
   column 2 for `04` matches only interfaces whose index is 4, so on this host
   multicast did nothing at all.
2. A named IPv6 zone does not resolve through `getaddrinfo`
   (`Name or service not known`), so a discovered peer could not be dialled. The
   library now parses a bracketed IPv6 literal and connects to the `SocketAddrV6`
   directly — which also fixes a zoneless IPv6 literal, which was equally broken.
3. `rustls`'s `ServerName` is a type, not a string: it rejects both `fe80::1` and
   `fe80::1%eth0`. Go's rule that an address is not a name maps exactly onto
   rustls's `ServerName::IpAddress`, which sends no SNI.
4. One socket cannot say which interface a datagram arrived on (tokio surfaces no
   `IPV6_PKTINFO`). Guessing from the *source* address is wrong invisibly: the
   source identifies the **far** end. One socket per interface answers by
   construction, and `SO_REUSEADDR` is what lets them share the group port.
5. A beacon gated on a bound port that only the `Bind` arm reported, and `Bind`
   stops being emitted once the address is set — a silent deadlock with no
   symptom but a node that never beacons.

Two more, folded in: interface state is keyed by name, so two link-local
addresses on one interface made each look stale to the other and the listener
rebound for ever; and the `JoinGroup` error must be discarded, because Linux
answers `EADDRINUSE` to a second join of a group the socket is already in, so the
error is the *normal* answer on every tick after the first.

**The host cannot prove multicast.** `enp3s0` and `wlp0s20f3` are both on
192.168.0.0/24 and a `ff02::114` datagram sent on one never reaches a socket
joined on the other — measured with two plain UDP sockets and no Yggdrasil code in
the path, so it is the network and not us. `proof/9-multicast.sh` therefore builds
its own segment (a veth pair under `unshare -Urn`) rather than hoping for the
host's, and says why in its header.


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
    immediately" — `core/api.go:207-211`). *Corrected by Slice 8: that comment is
    wrong about Go — `links.remove` closes the connection too
    (`link.go:433-438`), measured — so keeping the link is our divergence, not
    Go's behaviour.* Go's `DisallowUnknownFields` call is
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
- **Slice 5 findings — the loop is the only policy home now, and later slices
  must use it.**
  - `client/src/node.rs` owns `Router` + `LinkSet` + the mailbox; `client/src/links.rs`
    owns peer configuration, dedup, backoff and the last error. **Slice 7's admin
    socket must not touch either directly** — it sends `Cmd`s and reads
    `Node::peers().report()`. That is what "no `Mutex` in `src/`" buys, and it is
    the shape the mutation table above pins. *Superseded by Slice 7: the socket
    sends `Cmd::Report` and gets a `Node::snapshot()`; `Links::report()` never
    shipped, because a second view of the same state in the library was the wrong
    half of the split.*
  - Dialling is the one piece of node work that runs off-task, and it is safe
    precisely because `connect_any` + the `meta` handshake touch no router state.
    Anything new that must touch router state goes through `Cmd`, not a task.
  - Liveness is reconciled by diffing entry `live` keys against
    `LinkSet::peers()` once per tick. `serve` evicting silently (Slice 4) is what
    makes a dead link become a redial, so the two slices are load-bearing for
    each other: do not add a link-death callback to the library to "make this
    explicit".
  - CI trio green at 88 unit + 7 integration tests (~31 s wall): `cargo fmt
    --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
    `cargo test --workspace --locked`.
- **Slice 6 findings — config is a wire format, and the address text was the bug.**
  - **The library had a real parity bug, found by a Go fixture rather than by
    review.** `Address`/`Subnet`'s `Display` emitted zero-padded groups
    (`0201:…`, `200:13e1:0000:…`); Go prints through `net.IP.String()`, which
    drops leading zeros and collapses the longest run of ≥2 zero groups to `::`.
    `src/address.rs` now formats via `std::net::Ipv6Addr`, whose `Display` is the
    same RFC 5952 rule, and `Subnet`'s appends `/64` like `net.IPNet.String()`.
    Every `-address`/`-subnet`/`-publickey` output downstream inherits the fix —
    including the probe's own `local/remote/parent/root` lines
    (`client/src/main.rs:18`), which printed `0200:…` before this slice.
    `Router::dump` prints hex keys, not addresses, so it is unaffected.
    Pinned by two searched Go-captured vectors in `tests/go_vectors.rs` whose
    text contains a collapsed run *and* a single interior zero group, which is
    what a naive implementation gets wrong.
  - **The pipe proof is symmetric and needs no privileges.** Beyond the planned
    `roots -genconf | yggdrasil -useconf -address`, the same config fed to both
    `-useconf` implementations yields byte-identical `-address`, `-subnet` and
    `-publickey`. Go returns from the identity flags at `main.go:147-165`, before
    the TUN `panic`, so this runs on a bare machine — worth reusing as the shape
    of proof for later config work.
  - **Three Go behaviours had to be copied, not invented.** (a) `ReadFrom`
    generates first and parses *on top* (`config.go:114-119`), so
    `#[serde(default = "defaults")]` on the struct — not on each field — is what
    makes an absent key keep its default; (b) encoding/json leaves the
    destination untouched for a JSON `null`, at every depth, hence the recursive
    `strip_nulls` before deserialising — without it `{"IfMTU":null}` is a type
    error where Go shrugs; (c) `-genconf` blanks `AdminListen` before marshalling
    (`main.go:121`) so the `omitempty` tag drops it — a generated config that
    *does* carry `AdminListen: "unix:///var/run/yggdrasil.sock"` would be a
    different key set from Go's and fails the byte-shape test.
  - **Known divergences, all deliberate and recorded in `03-program-design.md`:**
    JSON only (no HJSON writer, no BOM/UTF-16 sniff at `config.go:102-110`), so
    `-json` is accepted and means nothing; no `-normaliseconf`, `-exportkey`,
    `-autoconf`, `-logto`, `-user`; unknown flags are rejected with Go's own
    `flag` wording because a silently ignored `-suseconf` typo is the worst
    failure mode an operator can have; `KeyMismatch` (seed ≠ public half) is an
    error where Go takes `PrivateKey[32:]` unchecked; running a node from a
    config was Slice 7's follow-up and landed there — `boot()` runs the node
    where Go does, and `exit(2)` is now reserved for what Go's `flag` package
    reserves it for: an undefined flag.
  - **`AllowedPublicKeys` was already enforced and never exercised.** The gate at
    `src/link.rs:580-585` predates the plan (whose citation `:450-453` has
    drifted); `client/tests/allowlist.rs` is its first test, and it pins both
    halves of Go's comment "This does not affect outgoing peerings" — dropping
    `is_inbound` fails the refusal assert, applying the gate both ways fails the
    dial assert. A refusal is invisible to the peer that caused it (Go's check
    runs after the listener writes its own `meta`), which the test asserts as
    `outbound.is_ok()`.
  - **A live check found a fall-through bug the tests could not.** The first
    `config_stage` returned `None` for `-useconffile` with no identity flag, which
    sent `roots -useconffile /etc/yggdrasil.conf` into the demo probe — and the
    probe dials a hard-coded default peer, so loading a config would have started
    dialling out. Go's load cases (`main.go:105-119`) have no `return`, so it runs
    a node there; ours now reports the identity and exits. Two things that follow
    for Slice 7: our `defaults()`
    sets `Listen: []`, so even a running node would be dial-only with nothing
    inbound, and `IfName: "auto"` is carried but unused because `client/` has no
    TUN code at all yet (the field exists so the key set matches Go's).
  - CI trio green at **97 unit + 10 integration tests** (~35 s wall).
- **Slice 7 findings — the framing was right and the *field order* was wrong.**
  - **A `serde_json::Value` body is an alphabetically-sorted body.** `Map` is a
    `BTreeMap` while the `preserve_order` feature stays off, so every reply built
    with `json!` printed `address` before `build_name` where Go's
    `encoding/json` prints struct order. The unit tests could not see it (they
    parsed the reply and checked the values); only the byte diff against a live Go
    node did. Rule for every later admin body: a `struct`, never a map.
  - **`Box<dyn Serialize>` is not implementable.** `Serialize::serialize` is
    generic over the serializer, so the trait is not object-safe; `RawValue`
    would keep order but not indentation (`write_raw_fragment` has only a default
    impl), and `preserve_order`/`erased_serde` are both new dependencies for one
    field. The closed `enum Body` with a hand-written delegating `Serialize` is
    what `03-program-design.md` now shows.
  - **The proof shape changed: run the *other implementation*, not just our own
    tests.** `docs/plans/go-client-parity/proof/7-admin.sh` starts two Go nodes
    and two of ours in one netns with the same key and diffs six commands across
    both transports, then asks stock `yggdrasilctl` in table mode — which decodes
    into Go's structs and would print empty cells for a wrong field name. Two
    gotchas it encodes: the flag is `-endpoint` (with none set, yggdrasilctl reads
    the *platform default config file* and talks to the host's service node), and
    `kill`ing the nodes needs their PIDs because an orphaned Go child inherits the
    script's stdout.
  - **`getTree` and `getSelf.routing_entries` differ because Go seeds its tree
    with itself** (own key as parent, `sequence: 1`), so a Go node reports 1
    routing entry before any peer exists and ours reports 0. Both count
    `len(router.infos)`, and once a link is up the two answers match row for row,
    so this is one missing self-entry rather than a different measure. That is
    router-state work, not framing — recorded for Slice 8, which owns what these
    bodies say.
  - **One deviation found in the library while pinning URI errors:** Go collects
    repeated `?key=` into a set (`link.go:179-191`); we keep a single
    `pinned_key` and the last value wins. Harmless for a dial with one peer, and
    now stated in AGENTS.md rather than discovered by an operator.
  - **Go decodes a command's arguments before the command runs; we did not.** The
    raw byte diff (`proof/7-admin-raw.sh`, now 22 cases) showed
    `{"request":"getSelf","arguments":"notanobject"}` succeeding on our socket
    where Go answers `json: cannot unmarshal string into Go value of type
    admin.GetSelfRequest`. `decode_args` is now the gate, and it runs *before*
    `dispatch`, so a request refused for its argument types never reaches the
    link layer — the assertion that pins the ordering is "a request refused for
    its argument types still added a peer". `list` is exempt because its handler
    discards its input, and `"arguments": null` is a no-op in Go rather than an
    error.
  - **A link we accept is invisible, and the *reason* is structural.**
    `proof/7-admin-inbound.sh` dials one way then the other: Go lists a link it
    accepted (its `remote` is rewritten to the peer's socket address,
    `link.go:519-525`) while our `getPeers` answers `{"peers": []}`. With both
    directions up, our one row reports the accepted link's `inbound: true` against
    the *dial's* URI, because `LinkSet` keys by node public key and the second
    link replaces the first. Recorded in Slice 8's scope, with that script as the
    tripwire; it needs a library decision, not just a client one.
  - **Proof scripts must rebuild, always.** The first re-run of the raw diff after
    fixing the password leak still showed the leak, because the script only built
    `target/debug/roots` when the binary was missing. All three Slice 7 scripts now
    run `cargo build -q -p roots-client` unconditionally.
  - CI trio green at **98 unit + 16 integration tests** (~40 s wall; the admin
    file carries 6 of them, and `mesh_ping` stays `#[ignore]`d).
    `examples/admin.rs` (643 lines) and the root `serde_json` dev-dependency are
    gone with it; `client/` is the only place a config-driven node runs.
- **Slice 8 findings — a row is a peering, and it names a connection.** Full
  detail and all three mutation tables are in the Slice 8 Done block of
  `04-slices.md`; these are the things a fresh session must not re-derive.
  - **The seam is `roots::LinkId`** — a per-connection counter, minted where the
    connection is built, impossible to fabricate. A `getPeers` row holds one and
    asks `links.stats(id)` with it, which is Go's `conns[conn]` join
    (`core/api.go:73-103`) with the pointer replaced. Two rules follow and both
    are load-bearing: `stats(id) == None` means *this row lost the slot*, not
    "the peer is gone"; and nothing a caller holds may assume its id outlives a
    displacement.
  - **Reading Go instead of trusting its comments changed three conclusions.**
    `removePeer` **does** close the live link (`link.go:433-438`, measured on a
    Go pair) — our keep-the-link `Cmd::Drop` is a divergence we own, and Slice 9
    now carries it as a decision rather than a parity fix; passing an inbound
    row's URI to `removePeer` **panics** Go (nil `cancel`, `link.go:434`), which
    is not worth reproducing; and a crossed peering **flaps on Go too** — the
    first draft of phase C asserted "Go holds both directions up", which the
    measurement disproved.
  - **`cost` and `latency` are filled and cited, not claimed.** One loopback pair
    disagreed by ~100×, and the reason is that neither is an RTT. Open question
    recorded in `TODO.md`.
  - **A Go comparator that truncates a float is not a total order**, so
    `sort_by` — which verifies comparators and panics — cannot implement it: 300
    rows of the fixture panic, 200 never do. `sort_stable` in
    `client/src/admin.rs` is Go's `slices.SortStableFunc`, not a workaround for
    slowness.
  - CI trio green at **111 unit + 20 integration tests** (~35 s wall).
