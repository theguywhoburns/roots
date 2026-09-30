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
| — | address derivation (`src/address.rs`) | **transcribed** from `address_test.go`; the *text* Go prints is captured | `addr_vector_matches_go`, `subnet_vector_matches_go`, `getkey_lossy_vectors_match_go`, `go_address_and_subnet_strings_match_captured` |
| — | `SigReq` / `SigRes` / `Announce` payloads | **captured** from Go 0.5.14 | `go_tree_payloads_match_captured` |
| — | `SigRes.psig` and the announce `sig` preimage | **captured**, and the preimage is verified | same |
| — | `BloomFilter` wire encoding | **captured** (which block is which) + **transcribed** (bit order within a byte) | `go_tree_payloads_match_captured`, `bloom_vector_matches_go`, `the_flag_layout_is_flags_then_data` |
| — | `PathLookup` / `PathNotify` / `PathBroken` | **transcribed** from a Go generator | `lookup_vector_matches_go`, `notify_vector_matches_go`, `broken_vector_matches_go` |
| — | `Traffic` | **transcribed** from a Go generator | `traffic_vector_matches_go` |
| — | session `init` | **transcribed** from a Go generator | `go_init_decrypts_with_b_key` |
| — | session `ack` | round-trip only | `session_handshake_roundtrip` |
| — | session `key` (rotation) | **nothing** | — |
| — | inner type bytes (traffic 1 / proto 2) | constants from Go's source | `packet_type_constants_match_go`, `packet_type_constants_match_go_core_types` |
| — | ed25519→X25519 map | **transcribed** from a Go generator | `e2c_pub_matches_go` |
| — | `typeSessionProto` nodeinfo / debug | semantics only | `nodeinfo_size_cap_matches_go`, `debug_round_trips` |
| — | multicast advertisement + membership hash | round-trip only, plus a non-Go KAT | `advertisement_roundtrips_and_rejects`, `multicast_hash_over_peer_key` |

## The count, and what it means

**Seven of 22 formats are guarded by bytes captured from the installed Go 0.5.14
binary**, and every one of them is in `tests/go_vectors.rs`: the envelope, the
two `meta` rows, and the four tree rows. That is the number this file's own rule
supports — *a page here is a claim we are prepared to test*, and a vector is
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

- **Session `ack` and `key` have no captured bytes at all**, and `key` — the
  rotation path, `Session::maybe_rotate` — is not exercised by any test at all.
  A session rides *inside* a `Traffic` frame (there is no session frame type:
  the pathfinder is below the session layer, so the traffic frame's payload *is*
  the session message), which means capturing one means answering Go's `init`.
  The harness can: the payload is sealed to *our* key and we hold it. Go just
  never opens one here, because the only thing it wants to say is nodeinfo and
  that arrives through a `key` rotation first. That is the next capture.
- **The bloom's bit order within a flag byte** is pinned by a generator vector,
  not by the binary. Go's first filter is empty, and an all-ones flag block
  cannot tell MSB from LSB — measured, by reversion.
- **Multicast** has a round-trip test and a blake2b known-answer check that has
  nothing to do with Go, and no captured beacon. `04-slices.md` promised a
  `GO_MULTICAST_BEACON` constant; it does not exist.
- **Address derivation** is a `V` in the frozen inventory table and a
  transcription in fact. The vectors are real Go bytes and they are worth having;
  they are just not bytes we *captured*, and an `address_test.go` line is a
  weaker oracle than a running node.

So: **22 of 22 is not reached, and the honest split of the 22 is 7 captured, 6
transcribed, 1 partial, 4 round-trip or semantics only, and 4 unguarded.**
Reaching it means captures, not typing, and each one needs the Go binary inside
`unshare -Urn` — never CI. The admin socket is not one of the 22: it never
crosses a link, but `21-admin.md` is written to the same rules because
`yggdrasilctl` interoperability is a claim just as testable as a frame layout.

The blank pages are the work list: each gets written when a slice captures real
Go bytes for it. `docs/plans/go-client-parity/04-slices.md` tracks which slice
owns which row.
