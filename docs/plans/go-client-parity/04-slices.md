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

- [x] **Slice 4 — `LinkSet` owns its links; sends say whether they landed.**
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
      **Done 2026-09-24:** nine new or rewritten tests; the CI trio green
      (81 unit + 6 integration, ~14 s). Every behaviour this slice changed is
      pinned by reverting it, one at a time, and naming the test that fails:

      | Reverted fix | Killed by |
      |---|---|
      | `_sendReqs` iterates the live set (`router.go:189`) | `router_books_can_name_a_peer_with_no_link` |
      | bloom fan-out is a soft send (`bloomfilter.go:277`) | `router_books_can_name_a_peer_with_no_link` |
      | `_fix` asks the live set for parent liveness (`router.go:229`) | `fix_refuses_a_parent_with_no_link` |
      | a link error aborts the serve only when the set is empty | `only_an_empty_set_makes_a_link_error_fatal` |
      | a refused write retires its link | `a_failed_write_retires_the_link` |
      | hard send reports a missing link (`Err(NoLink)`) | `linkset_write_reports_missing_peer`, `a_failed_write_retires_the_link`, `dropped_no_link_counts_soft_sends` |

      - **Two changes the design did not anticipate**, both needed to make the
        eviction claim true: `LinkSet::send` retires an entry whose
        `write_frame` fails, and `Router::fatal_link_error(&links, &err)` gates
        the five `serve_links` error sites. Without them a link that was dead
        but not yet evicted aborted every survivor with
        `Io(ConnectionReset)`. Go needs neither: each peer owns a reader
        goroutine (`peers.go:228`) and write errors are discarded outright
        (`peers.go:189`).
      - **`tests/mesh3.rs` passes under all three router-state liveness
        reversions.** The tolerance above absorbs them, and no loopback scenario
        reaches the window — which is why the two targeted tests exist rather
        than a mesh variant. The same is true of the retirement test's socket:
        loopback TCP absorbs writes to a closed peer until the reset lands, so
        `a_failed_write_retires_the_link` uses `tokio::io::duplex` with the far
        half dropped, which fails for certain.
      - **Divergence found, deliberately not fixed:** nothing prunes
        `tree.peers`, `tree.infos` or `bloom.on_tree` when a link dies, so a
        node keeps a parent it has no link for. Go prunes all of it in
        `removePeer` (`router.go:147`). Slice 4 makes the stale key tolerable;
        `a_stale_parent_is_kept_and_the_serve_survives_it` pins the current
        shape as a tripwire for the router-state lifecycle slice.
      - `TreeState::send_all_reqs` and `Router::use_response` became
        `pub(crate)` so a fixture can drive them; counters are wire bytes
        (`frame::wire_len`) in both directions.

- [x] **Slice 5 — one task, one `Router`, a command queue.** `client/src/links.rs`
      (`link_id` dedup exactly as Go's `links.add` — duplicate returns
      `AlreadyConfigured` after kicking the live link) and `Node::run` draining
      `Cmd::{Dial,Drop,Accept,Packet,Quit}` between 50 ms serve slices. Listeners,
      persistent dials and admin all talk through the channel; nobody else
      touches the router.
      *Proves:* a client-crate integration test that starts a `Node`, adds two
      peers over `Cmd`, waits for convergence, then `Drop`s one and asserts the
      other survived — the shape every later client feature needs, without a
      single `Mutex` in `src/`.
      **Done 2026-09-24:** `client/tests/node_loop.rs` (5.5 s, loopback) holds all
      four claims; `client/src/links.rs` adds 7 unit tests for the parts a live
      loop cannot reach (bad URI, stale dial token, ephemeral forget, kick).
      `run_peer` is gone and `tests/reconnect.rs` now drives the same `Node`, so
      there is exactly one redial path in the tree. The CI trio is green
      (88 unit + 7 integration, ~31 s). Each behaviour was reverted one at a time
      to name what fails:

      | Reverted behaviour | Killed by (all in `node_loop`) |
      |---|---|
      | `link_id` dedup — a duplicate stacks a second dial (`link.go:236-245`) | `assertion failed: the duplicate dial never connected` (`accepted` 2 ≠ 1) |
      | `Drop` keeps the link that is already up (`api.go:207-211`) | `timed out after 15s waiting for the dropped peer's live link still carries traffic` |
      | `Drop` cancels the redial loop | `assertion failed: a dropped peer must not be dialled again` (`accepted` 2 ≠ 1) |
      | a dead link is survivable, not fatal | `the node loop ends cleanly: Io(UnexpectedEof)` |

      - **The single-task invariant is kept by moving only the dial off-task.**
        `Links::start_due` spawns `client.connect_any(&uri)` — connecting and the
        `meta` handshake touch no router state — and the task reports back over a
        package-private `LinkEvent` channel with the token it was given. A result
        whose token matches no entry is dropped, which is Go's "if a peering has
        come up in this time, abort this one" (`link.go:366-373`).
      - **Liveness is a diff, not a callback.** `serve` evicts a dead link
        silently (Slice 4), so `note_liveness` compares each entry's `live` key
        against `LinkSet::peers()` once per tick: a vanished link becomes a
        backoff bump and, for an ephemeral entry, deletion — Go's goroutine-exit
        `delete(l._links, info)`.
      - **Kick timing is a deviation, recorded in Gate 3:** a duplicate dials
        again on the next tick instead of interrupting a backoff sleep, which
        saves one channel per entry and costs at most 50 ms.
      - `Error::is_link()` (library) is the one API addition: the node loop needs
        Go's "link gone" vs "node broken" split without reaching into the
        `Error` enum's variants.

- [x] **Slice 6 — config that Go accepts.** `client/src/config.rs`: the
      Go-shaped `Config` struct with Go's JSON key names, `defaults()`
      mirroring `src/config/defaults_linux.go`, `load`/`generate`, and the
      `-genconf` / `-useconf` / `-json` flags, and the config-to-`LinkOptions`
      wiring — `allowed_keys` is already enforced in `src/link.rs:580-585`
      (line drifted from the `:450-453` this slice was planned against), so
      `AllowedPublicKeys` becomes a key in a list rather than a feature.
      *Proves:* `roots -genconf | yggdrasil -useconf -address` prints a real
      Yggdrasil address — the installed Go binary parses what we emit. A
      cross-implementation check with no compiler and no network.
      **Done 2026-09-24:** the pipe runs green **both directions**, and the
      reverse direction is stronger than the plan asked for — for one and the
      same config, `yggdrasil -useconf` and `roots -useconf` print the same
      `-address`, the same `-subnet` and the same `-publickey`:

      ```sh
      cargo build -q -p roots-client
      R=./target/debug/roots; Y=/run/current-system/sw/bin/yggdrasil
      $R -genconf | $Y -useconf -address        # Go parses what we emit
      $Y -genconf -json | $R -useconf -address  # we parse what Go emits
      K=$(grep -o 'cea91b87[0-9a-f]*' client/src/config.rs | head -1)
      CFG="{\"PrivateKey\":\"$K\"}"             # the committed Go fixture key
      for f in address subnet publickey; do echo "$($Y -useconf -$f <<<"$CFG")"; done
      for f in address subnet publickey; do echo "$($R -useconf -$f <<<"$CFG")"; done
      ```

      Both loops print the same three lines: `201:c6de:e01b:c88a:8ee1:5666:52d7:d1e7`,
      `301:c6de:e01b:c88a::/64`, `4e4847f90ddd…1bb4ae`.
      No privileges needed: Go returns from the identity flags at
      `main.go:147-165`, before it touches a TUN.
      9 unit tests in `config.rs`, 2 in `client/tests/allowlist.rs`, 1 new
      vector test in `tests/go_vectors.rs`; the CI trio is green
      (97 unit + 10 integration, ~35 s). Each behaviour was reverted one at a
      time to name what fails:

      | Reverted behaviour | Killed by |
      |---|---|
      | Address/subnet text is Go's `net.IP.String()` (`src/address.rs`) | `go_address_and_subnet_strings_match_captured` — left `"0200:13e1:0000:aec8:…"`, right `"200:13e1:0:aec8:…"` |
      | A JSON `null` means *absent*, at every depth (`strip_nulls`) | `absent_and_null_keys_keep_defaults_and_present_ones_replace_them` — `nulls are legal: Json("invalid type: null, expected u64")` |
      | `AllowedPublicKeys` gates the inbound side only (`is_inbound`, `src/link.rs:580`) | `allowed_public_keys_gate_inbound_links_only:53` — the unlisted peer is not refused |
      | …and the same guard applied to *both* directions | the same test at `:81` — `an allowlist of my own must not block my dial: KeyNotAllowed` |
      | `-genconf` blanks `AdminListen` before marshalling (`main.go:121`) | `generated_config_has_go_keys_and_defaults:493` — our output gains a key Go's has omitted |
      | A `PrivateKey` that is not Go's 64 bytes is refused (`KeyBytes`, `config.go:253`) | `a_key_that_is_not_gos_shape_is_refused:631` |
      | `PrivateKeyPath` overrides the inline key (`config.go:130-135`) | `private_key_path_overrides_the_inline_key:666` |
      | `-useconf` beats `-useconffile` (`main.go:105-118`) | `config_flags_parse_like_gos_flag_package:695` |

- [x] **Slice 7 — admin framing parity (tcp + unix, keepalive, error text).**
      `serve_admin` dispatches on scheme like Go (`unix:///…` is Go's Linux
      default, which is how we were wrong to be TCP-only), decodes a stream of
      JSON values, honours `keepalive`, echoes the whole request struct back
      including `keepalive`, and copies Go's error strings.
      *Proves:* `yggdrasilctl` — the real one, installed — pointed at our
      socket answers `list` and `getSelf` over both transports; plus
      `admin_keepalive_honours_second_request` and
      `admin_unix_socket_matches_tcp`.
      **Done 2026-09-24:** `client/src/admin.rs` (the socket),
      `client/src/listen.rs` (Go's `StartupListeners`), `client/src/main.rs`
      `boot()` (a node started from a config, so the socket answers about a real
      running node rather than about an example), `client/tests/admin_loopback.rs`
      (6 tests, 0.31 s), and `examples/admin.rs` deleted — 643 lines of
      hand-rolled adapter replaced by the node's own socket. The CI trio is
      green (98 unit + 16 integration, ~40 s).

      **The proof bar, run for real.** The script is in the repo, so the claim is
      re-runnable and not a screenshot:
      `unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/7-admin.sh`.
      Two Go 0.5.14 nodes and two of ours share one private netns (the namespace
      is not decoration — a Go node panics unless it may create a TUN, and `lo`
      starts *down* in a fresh netns, so the script raises it), all four holding
      the *same* `PrivateKey` — the throwaway fixture already committed in
      `client/src/config.rs`, whose address is `201:c6de:e01b:c88a:…` — so
      `getSelf` is comparable byte for byte. Note the flag:
      `yggdrasilctl -endpoint=tcp://…` — there is no `-admin_socket`, and with no
      `-endpoint` it silently reads the platform default config file and talks to
      the host's service node instead.
      `list getSelf getPeers getTree getPaths getSessions` in `-json` mode
      against `tcp://127.0.0.1:19001` (Go) vs `tcp://127.0.0.1:19101` (ours) and
      `unix:///…/go.sock` vs `unix:///…/ours.sock`, every request following one
      `addPeer uri=tcp://127.0.0.1:1234` that cannot possibly connect:

      | Command | Go vs ours, tcp | ours, tcp vs ours, unix |
      |---|---|---|
      | `getPaths` | **byte-identical** | identical |
      | `getSessions` | **byte-identical** | identical |
      | `getTree` | `[]` vs Go's one self-entry (`sequence: 1`) | identical |
      | `getSelf` | only `build_name`/`build_version` and `routing_entries` 1 vs 0 | identical |
      | `getPeers` | row order and every value agree; we omit `last_error_time` and our `last_error` text is ours | identical |
      | `list` | 8 commands vs Go's 14 — the 6 absent ones are Slice 9/11/14's | identical |

      Then the script's last section runs `yggdrasilctl` in its **default table
      mode** against our node
      — the stronger test, because it decodes the reply into
      Go's own structs and prints an empty cell rather than an error when a field
      name is wrong. `getSelf` fills all six rows, `getPeers` renders
      `State=Down Dir=Out Cost=0` and `Last Error=0s ago: io: Connection refused
      (os error 111)` (the `0s ago` is our missing `last_error_time`, visible),
      `list` shows the `Arguments` column (`uri=…, interface=…`, `sort=…`), and
      `addPeer uri=…` through the real client configures the peer.

      Each behaviour was reverted one at a time to name what fails (18 reverts,
      all in `admin_loopback` unless noted):

      | Reverted behaviour | Killed by |
      |---|---|
      | unix socket mode `0660` (`admin.go:117-120`, `os.Chmod`) | `admin_unix_socket_matches_tcp` |
      | compact instead of `SetIndent("", "  ")` writer | `admin_error_strings_match_go` |
      | a body routed through `serde_json::Value` | `admin_body_field_order_matches_go` |
      | `break` unconditionally after one reply | `admin_keepalive_honours_second_request` |
      | never `break` (the other direction) | `admin_keepalive_honours_second_request` |
      | drop the `arguments: {}` preset on decode | `admin_error_strings_match_go` |
      | echo the action name lowercased | `admin_error_strings_match_go` |
      | reword `failed to find request` | `admin_error_strings_match_go` |
      | `#[serde(skip)] response` (drop the field) | 5 of the 6 tests |
      | `Body::Null` serialising as `0` | `admin_error_strings_match_go` |
      | `links.add` skipping `parse_link_uri` | `admin_error_strings_match_go` |
      | `AlreadyConfigured` returning `Ok(())` | `admin_error_strings_match_go` |
      | `getPeers` reporting the operator's URI instead of `link_id(uri)` | `admin_getpeers_reports_the_link_uri_not_the_operators` — `left: String("tcp://127.0.0.1:43102?password=s3cr3t")` |
      | `decode_args` matching on a name no command has (validates nothing) | `admin_argument_types_match_go` |
      | …refusing `"arguments": null` | the same test, at the null-echo assertion |
      | …skipping the per-field string check | the same test, at `GetPeersRequest.sort` |
      | …validating `list`'s arguments too | the same test, at the `list`-with-junk case |
      | …dispatching *before* validating (same messages, wrong order) | the same test, at `a request refused for its argument types still added a peer` |

      - **Field order was the bug this slice existed to catch, and the unit
        tests missed it.** `serde_json::Map` is a `BTreeMap` (the
        `preserve_order` feature is off on purpose), so every body built with
        `json!` came out alphabetically sorted — `address` before `build_name`.
        Go's `json.RawMessage` keeps struct order, so the only shape that works
        here is a `struct` per body. The live byte diff found it; the
        mutation-proof test (`admin_body_field_order_matches_go`) keeps it fixed.
      - **`Box<dyn Serialize>` — the Gate 3 sketch — does not compile.**
        `Serialize::serialize` is generic over the serializer, so the trait is
        not object-safe (E0038, 31 times). `erased_serde` is not a dependency and
        `serde_json::RawValue` is the wrong tool twice over: `raw_value` is an
        opt-in feature, and `Formatter::write_raw_fragment`
        (`serde_json-1.0.151/src/ser.rs:1929`) has only a default impl that
        writes bytes verbatim, so a raw body inside `to_vec_pretty` is never
        re-indented while Go's `json.Indent` re-indents nested raw JSON. The
        erasure is a closed `enum Body` with a hand-written `Serialize` that
        delegates each arm, which keeps Go's order and needs no new dependency.
      - **There is deliberately no Go *admin* vector file.** A captured Go
        `meta` frame is a byte string that must be reproduced exactly; an admin
        reply is text whose whole content is *this node's* state — its key, its
        tree, its peers — so a golden transcript would pin the state, not the
        framing. The framing is instead pinned by (a) the six tests above,
        (b) `docs/protocol/21-admin.md`, written from the transcript this slice
        captured, and (c) the diff command in the table above, which any session
        with the installed binaries can re-run.
      - **Arguments are decoded before the command runs, and we were skipping
        that step.** Go's handler wrapper unmarshals `arguments` into the
        command's own request struct and returns the failure verbatim
        (`admin.go:162-169`), so `{"request":"getSelf","arguments":"notanobject"}`
        is `json: cannot unmarshal string into Go value of type
        admin.GetSelfRequest` and `{"uri":123}` on `addPeer` is refused *before*
        the link layer is reached. We handed `arguments` to each command and let
        each one ignore what it did not read, so all five of those requests
        succeeded. `decode_args` is now the gate, with Go's two message shapes
        (the `admin.` prefix on one, its absence on the other, the **JSON tag**
        naming the field on the second) and three accepted shapes: `null`
        (a no-op in Go, echoed as `null` rather than the `{}` preset), unknown
        keys, and anything at all for `list`, whose handler discards its input.
        Found by the raw byte diff; pinned by `admin_argument_types_match_go`.
      - **Our `getPeers` cannot show an accepted link, and the reason is
        structural.** `docs/plans/go-client-parity/proof/7-admin-inbound.sh`
        dials one way, then the other, and prints both sides:
        Go lists a link it accepted (`remote` rewritten to the peer's socket
        address, `link.go:519-525`, so `tcp://127.0.0.1:37336`) while ours is
        `{"peers": []}` — our rows come from the configured peer list, and a link
        that arrived was never in it. Worse, when *both* directions are up our one
        row reports the accepted link's `inbound: true` against the dial's URI,
        because `LinkSet` keys by node public key and the second link replaces the
        first. Both are recorded for Slice 8 with this script as the tripwire.
      - **Keepalive survives errors.** Go's loop breaks on `!req.KeepAlive` and
        nothing else (`admin.go:354`), so a failed request on a keepalive
        connection gets its error reply and the connection stays open. Ours
        matches, which is why `admin_error_strings_match_go` runs five kept-alive
        requests — four of them errors — down one connection after checking six
        one-request connections.
      - `Cmd::Report` + `Node::snapshot()` replaced `Links::report()`: the socket
        asks the node task for a `Snapshot` (key, routing-entry count, tree,
        paths, sessions, one `PeerRow` per link) instead of the library keeping a
        second view of the same state.
      - **`getTree`/`getSelf`'s self-entry is a router gap, not a framing gap.**
        Go seeds its tree with its own key (`parent` = self, `sequence` 1), so
        `routing_entries` is 1 before any peer arrives; ours is empty until
        somebody announces. Recorded for Slice 8, whose subject is exactly what
        these bodies say. Once a link *is* up the two agree: in the inbound
        experiment both nodes answer `routing_entries: 2` and the same two
        `getTree` rows in the same key order, so the gap is only the
        no-peer-at-all case.
      - Known gaps, none of them framing: `getPeers` omits `latency` (raw SigReq
        round trip — Slice 8), `rate_recvd`/`rate_sent`, `last_error_time`, and
        lists only configured dials (the accepted-link bullet above);
        `getSessions` omits `bytes_recvd`/`bytes_sent`/`uptime`; `getPeers`'
        `sort` value is read but ignored, though its *type* is now checked
        (Slice 8); the echoed `arguments` is re-sorted where Go's `RawMessage`
        preserves the wire order; our `last_error` text and startup logging are
        worded differently from Go's.
      - **Every `admin.go` line cite in the slice's code, tests and docs was
        re-checked against the submodule** (`reference/yggdrasil-go` at
        `422836e`) and four had drifted or pointed at the wrong statement: the
        `os.Chmod` guard is `:117-120` (was `:212`), the unknown-action lookup is
        `:334-336` (was `:341-348`), the `keepalive` break is `:354` (was `:357`),
        and the bind-failure `os.Exit(1)` is `:130-132` (was `:132-134`, which is
        the *log line*). Worth the ten minutes: a wrong cite in a doc whose whole
        job is citing bytes is worse than no cite.

- [ ] **Slice 8 — `getPeers` says what Go says.** `sort` argument with Go's
      three stable orderings, and the full `PeerEntry` field set fed by Slice 4:
      `up`, `inbound`, `cost` (via `peer_cost`, Go's floor-at-1 millisecond
      number), `uptime`, `bytes_recvd`/`bytes_sent`, `rate_recvd`/`rate_sent`,
      `latency`, `last_error`/`last_error_time`. Plus the **row set**, which
      Slice 7 pinned and could not fix: a link we *accept* gets no row today
      because our rows come from the configured peer list, while Go inserts
      accepted links into `_links` and names the row by the peer's socket
      address (`link.go:519-525`, `536-565`) — and with both directions to one
      node up, our single row reports the accepted link's `inbound` against the
      dial's URI, because `LinkSet` keys by public key. The fix has a library
      half (a set that holds two links to one key, or per-link direction) and a
      client half (rows from links, not from config).
      Tripwire: `proof/7-admin-inbound.sh`.
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
