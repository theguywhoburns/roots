# Protocol reference

Plain descriptions of the bytes on the wire, written so that someone who has
neither Go nor Rust source can implement a peer. This documentation is a
product goal, not a by-product: `roots` exists to document the protocol as
actually deployed, so a page here is a claim we are prepared to test.

Rules for these pages:

- Write from **captured bytes**, never from memory or from Go's test files. If
  a layout is not proven by a vector in `tests/`, the page says so.
- Give every field an offset or a length. "A few bytes" is not a spec.
- Cite the Go source that backs each claim (`file:line` under
  `reference/yggdrasil-go` or `reference/ironwood`), and name the test that
  guards it.
- Record deviations from Go explicitly, including our own extra fields. A
  reader must be able to tell which behaviour is upstream and which is ours.

## Pages

| page | format | status | guarded by |
|------|--------|--------|-----------|
| [10-envelope.md](10-envelope.md) | link frame envelope: uvarint size, packet type, all 10 types | **captured** from Go 0.5.14 | `go_link_frame_envelope_matches_captured` (4 frames), `frame_kinds_match_table_len` |
| [20-handshake.md](20-handshake.md) | `meta` handshake: TLVs, keyed-hash signature, version check, flow | **captured** from Go 0.5.14, both password branches | `go_meta_handshake_bytes_match_captured`, `go_meta_password_binds_the_signature` |
| [21-admin.md](21-admin.md) | admin socket: JSON value stream, `request`/`response` envelope, `keepalive`, all 14 commands | **captured** from Go 0.5.14 over TCP and `unix://`, 22 raw edge cases | `admin_unix_socket_matches_tcp`, `admin_body_field_order_matches_go`, `admin_keepalive_honours_second_request`, `admin_error_strings_match_go`, `admin_getpeers_reports_the_link_uri_not_the_operators`, `admin_argument_types_match_go`, `admin_gettun_on_a_node_with_no_tun_omits_the_name_and_the_mtu` |
| [30-tree.md](30-tree.md) | `SigReq` / `SigRes` / `Announce`, and both signature preimages | **captured** from Go 0.5.14, preimages verified | `go_tree_payloads_match_captured` |
| [50-path.md](50-path.md) | `PathLookup` / `PathNotify` / `PathBroken`, `xkey` | **transcribed** from a Go generator | `lookup_vector_matches_go`, `notify_vector_matches_go`, `broken_vector_matches_go` |
| [60-traffic.md](60-traffic.md) | the `Traffic` frame and forwarding | **transcribed** from a Go generator | `traffic_vector_matches_go`, `a_path_is_refreshed_by_a_frame_we_cannot_read`, `a_forwarded_frame_does_not_refresh_the_forwarders_path` |
| [70-session.md](70-session.md) | session `init` / `ack`, the type bytes, the e2c map | `init` **captured** from a live Go node; `ack` never sent by Go (the page says why); type bytes and e2c map from Go's source | `a_captured_go_session_init_opens_and_verifies`, `an_ack_differs_from_an_init_only_in_its_type_byte`, `go_init_decrypts_with_b_key`, `session_handshake_roundtrip`, `packet_type_constants_match_go`, `e2c_pub_matches_go` |
| [a0-multicast.md](a0-multicast.md) | multicast advertisement + membership hash + the config row | **captured** (a beacon a Go node sent) + a non-Go KAT | `a_captured_go_beacon_decodes_and_verifies`, `a_captured_go_beacon_is_rejected_only_where_go_rejects_it`, `advertisement_roundtrips_and_rejects`, `multicast_hash_over_peer_key` |
| — | address derivation (`src/address.rs`) | **transcribed** from `address_test.go`; the *text* Go prints is captured | `addr_vector_matches_go`, `subnet_vector_matches_go`, `getkey_lossy_vectors_match_go`, `go_address_and_subnet_strings_match_captured`, `validity` |
| — | `BloomFilter` wire encoding | **captured**, including the flag bit order — a non-empty filter, 96 bytes | `a_go_bloom_payload_round_trips_through_our_codec`, `the_flag_bit_order_matches_a_go_payload`, `go_tree_payloads_match_captured`, `bloom_vector_matches_go`, `the_flag_layout_is_flags_then_data` |
| — | session rotation (there is no `key` message) | three tests; the nonce-wraparound branch is untested | `a_rotated_session_still_delivers_the_way_it_rotated`, `a_one_sided_rotation_carries_one_way_only`, `a_session_that_did_not_rotate_yet_keeps_its_key_sequences` |
| — | `typeSessionProto` nodeinfo / debug | semantics only | `nodeinfo_size_cap_matches_go`, `debug_round_trips` |

Numbering follows the plan's list (`02-architecture.md`, "Documentation
artifact"), so the gaps are visible: `00-overview`, `40-bloom`, `80-address` and
`90-proto` are not written. `30-tree` is deliberately ahead of `40-bloom` — the
tree payload is captured and therefore the more useful page first.

## The count, and what it means

**Ten of 22 formats are guarded by bytes captured from the installed Go 0.5.14
binary**: the envelope, the two `meta` rows and the four tree rows in
`tests/go_vectors.rs`, plus the multicast beacon and the non-empty bloom filter
in `src/multicast.rs` and `src/bloom.rs`. A beacon is
a UDP datagram rather than a link frame, so it is captured by a different harness
and lives beside the codec that decodes it. That is the number this file's own
rule supports — *a page here is a claim we are prepared to test*, and a vector is
only worth pasting if it came from the binary rather than from Go's tests.

The number this file used to claim, **14**, was frozen at Slice 2 and never
refreshed. It counted the two `meta` rows, the envelope, the tree rows and the
address vectors — and the last of those is transcribed from
`reference/yggdrasil-go/src/address/address_test.go`, which is precisely the
thing `examples/go_capture.rs`'s own header calls out as proving "nothing about
our bytes". So the old count was crediting Go's own test expectations.

The table above labels every row with the provenance it actually has, because a
table that says "guarded" for a round-trip test is the same failure in a
different font. Four things are worth naming:

- **There is no session `key` message, and the inventory row is wrong about
  one.** Ironwood declares four session types — Dummy, Init, Ack, Traffic
  (`encrypted/session.go:27-32`) — and there is no fifth. Rotation on nonce
  wraparound sends **nothing**: the keys are swapped locally and the peer learns
  of it from the next traffic frame's first uvarint, which is why that header
  carries two key sequences (`session.go:303-311`). So "session `key`" is
  rotation *state*, not a message. Rotation now has three tests (four mutants
  killed); the nonce-wraparound branch of `encrypt`, which is Go's *other*
  rotation trigger, does not.
- **Session `init` is now captured** from a live Go node, and reaching it took
  four things that each failed silently. Session **`ack`** still has no captured
  bytes, and now for a real reason rather than a hopeful one: Go sends nodeinfo
  only in reply to an admin `getNodeInfo` — `_sendReq` has exactly one caller in
  the whole module (`core/nodeinfo.go:160`) — and by then it has nothing left to
  say, because it already answered the request that opened the session. What is
  pinned instead is that `ack` and `init` are the same wire format, differing
  only in the leading type byte. `70-session.md` lists all four steps.
- **`GroupPassword` is a config key we accept and ignore**, and a node with one
  set will not verify our `init` or `ack`. That is a real interop hole rather
  than a documentation gap; see `TODO.md`.
- **The bloom's bit order within a flag byte** was the one format question no
  vector could answer, because every filter we had was degenerate for it: Go's
  first was empty, and an all-ones flag block cannot tell MSB from LSB. It is now
  captured. Getting a *non-empty* filter out of Go needed the harness to become
  a real tree peer — announce Go as our parent rather than ourselves as our own
  parent, because `_fixOnTree` only puts a peer on the tree if it is Go's parent
  or Go is its parent, and a self-parented peer satisfies neither arm and is
  skipped by every multicast. `30-tree.md` has the source and the captured bytes.
- **Multicast** now has a captured beacon — `proof/9-multicast.sh` runs a Go node
  beaconing on a veth with our node as the only listener, and checks the length,
  the advertised key, the bound port and that our decoder *accepts* it. A beacon
  of the right length that the decoder refuses would be a layout mismatch, and the
  length alone would have passed. What is still missing is the **keyed** branch:
  every beacon we have takes the unkeyed one, so the group-password hash is
  checked against CPython and nothing else.
- **Address derivation** is a `V` in the frozen inventory table and a
  transcription in fact. The vectors are real Go bytes and they are worth having;
  they are just not bytes we *captured*, and an `address_test.go` line is a
  weaker oracle than a running node.

So: **22 of 22 is not reached, and the honest split of the 22 is 10 captured, 5
transcribed, 3 round-trip or semantics only, and 4 unguarded.** There is no
"partial" left: the last one was the bloom, which was captured for its block
order and transcribed for its bit order until the non-empty filter closed it.
Reaching it means captures, not typing, and each one needs the Go binary inside
`unshare -Urn` — never CI. The admin socket is not one of the 22: it never
crosses a link, but `21-admin.md` is written to the same rules because
`yggdrasilctl` interoperability is a claim just as testable as a frame layout.

Eight of the formats have a page and fourteen do not. A page is written from a
format's *evidence*, not from its absence: `30-tree.md` exists because the tree
payload is captured, and `60-traffic.md` exists because the layering fact it
leads with is the one that caused a bug. The blank pages are the work list, and
the gap is deliberate rather than lazy — writing `80-address.md` from
transcribed vectors would be a page that reads like evidence and is not.
`docs/plans/go-client-parity/04-slices.md` tracks which slice owns which row.
