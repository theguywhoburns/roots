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
| [10-envelope.md](10-envelope.md) | link frame envelope: uvarint size, packet type, all 10 types | captured from Go 0.5.14 | `go_link_frame_envelope_matches_captured` |
| [20-handshake.md](20-handshake.md) | `meta` handshake: TLVs, keyed-hash signature, version check, flow | captured from Go 0.5.14, both password branches | `go_meta_handshake_bytes_match_captured`, `go_meta_password_binds_the_signature` |
| — | address derivation (`src/address.rs`) | proven by vectors, undocumented | `addr_vector_matches_go`, `subnet_vector_matches_go`, `getkey_lossy_vectors_match_go`, `go_address_and_subnet_strings_match_captured` (the *text* Go prints for `-address`/`-subnet`) |
| — | `SigReq` / `SigRes` / `Announce` payloads | undocumented | `announce_chain_verifies`; envelope only so far |
| — | bloom filter (`BloomFilter`) | undocumented | `bloom_vector_matches_go` |
| — | `PathLookup` / `PathNotify` / `PathBroken` | undocumented | `lookup_vector_matches_go`, `notify_vector_matches_go`, `broken_vector_matches_go` |
| — | `Traffic` | undocumented | `traffic_vector_matches_go` |
| — | session layer (init, rotate, crypto_box) | undocumented | `go_init_decrypts_with_b_key` (init only), rest round-trip only |
| — | `typeSessionProto` nodeinfo / debug | undocumented | live probe (`examples/proto_probe`) |

Of the 22 wire formats in the Gate 2 inventory, 14 are now guarded by captured
Go bytes; `02-architecture.md` in the plan folder holds the table and
`00-status.md` the current count.

The blank pages are the work list: each gets written when a slice captures real
Go bytes for it. `docs/plans/go-client-parity/04-slices.md` tracks which slice
owns which row.
