# no_std core separation — feasibility, then a slice plan

Goal: `roots-core`, a `#![no_std]`, no-`alloc`, buffer-external, streamed
implementation of the wire and state layers; `roots` stays the `std` wrapper that
owns every buffer, socket, timer and collection.

This file records what was **measured** while preparing the work, and the slice
order that follows from it. It is a plan, not a status: nothing here is built
yet.

## The three questions that decide whether this is possible at all

All three were answered by building probe crates, not by reading documentation.
Each is reproducible with the commands shown.

### 1. Can `#![no_std]` be enforced without a cross toolchain? Yes — but only half of it is free.

Only the host target is installed here (`rustc --print sysroot` lists
`x86_64-unknown-linux-gnu` and nothing else), so the obvious worry is that a
`no_std` claim is unverifiable in CI until someone adds
`thumbv7em-none-eabi`.

It is verifiable, because `#![no_std]` removes `std` from the prelude
regardless of target. Probe:

```rust
#![no_std]
pub fn bad() -> std::collections::HashMap<u8, u8> { std::collections::HashMap::new() }
```

```
error[E0433]: cannot find module or crate `std` in this scope
```

…on the **host** target, no cross toolchain. `Vec` and `String` are likewise
absent from the prelude, so an unwanted allocation is a compile error rather than
a review comment.

**But the no-*alloc* half is weaker than that, and the first version of this
document overstated it.** Three probes, in order:

| what | result |
|---|---|
| `no_std`, bare `Vec` | 3 errors — `Vec` not in scope |
| `no_std`, `std::` path | 3 errors — `std` not in scope |
| `no_std` + `extern crate alloc;` + `alloc::vec::Vec` | **0 errors — compiles** |

That third row is the hole. One line — `extern crate alloc;` — re-opens
everything the first two rows closed, and it compiles silently. So:

- **`no_std` is compiler-enforced**, unconditionally, forever.
- **no-`alloc` is enforced only while nobody writes `extern crate alloc;`.**

Two gates close the second one, and neither is a lint:

1. `unused_extern_crates = "deny"` in `[workspace.lints.rust]`. An
   `extern crate alloc;` that nothing uses is denied — which covers the realistic
   case, someone importing it while building a codec. Once something *does* use
   it the lint is silent, by design: it is an allowlist lint, not a policy.
2. `cargo tree -p roots-core -e normal` in CI. `alloc` cannot appear in a
   dependency edge without somebody having enabled it, so this catches the
   deliberate case that the lint cannot. It is the same check `AGENTS.md`
   already prescribes to keep `smoltcp` and `tun` out of the library, so it is
   not a new habit.

What would *not* work, and why it is worth saying: building for a bare-metal
target does not help either. `alloc` exists as a crate on every target; a
missing global allocator only fails at link time, and a library is an rlib, so
nothing links. There is no rustc flag for "no allocator, please" — the property
is a code-review property wearing a compile-error costume, and the costume only
covers one of the two doors.

**Consequence for CI:** add a `roots-core` build and it *is* the no_std gate —
no new job, no toolchain, no network. Add the `cargo tree` line and the no-alloc
gate is two commands rather than a review.

### 2. Do the crypto dependencies survive `default-features = false`? Yes.

This was the real risk, because `curve25519-dalek` advertises `alloc` and
`precomputed-tables` in its **default** feature set:

```toml
default = ["alloc", "precomputed-tables", "zeroize"]
```

`alloc` only arrives via `precomputed-tables`, and `src/session.rs` uses
`curve25519_dalek` for exactly one thing — `CompressedEdwardsY::decompress()`
then `to_montgomery()`, pure field arithmetic, no tables. So the whole
cryptographic stack builds with no `alloc`:

```toml
ed25519-dalek    = { version = "2", default-features = false, features = ["rand_core"] }
blake2           = { version = "0.10", default-features = false }
sha2             = { version = "0.10", default-features = false }
curve25519-dalek = { version = "4",  default-features = false }
crypto_box       = { version = "0.9", default-features = false }
hex              = { version = "0.4", default-features = false }
```

`cargo tree -e normal` over that set shows no `std` and no `alloc` edge.

And it is not merely *compiling* — it is **right**. `ed_to_curve_pub` in a
`#![no_std]` crate, no `extern crate alloc`, still reproduces the transcribed Go
vector:

```
test t::e2c_pub_matches_the_transcribed_go_vector ... ok
```

(`PUBA` → `E2C_PUBA`, `0ebf980a…`, from `src/session.rs`.)

The one casualty worth naming: `hex::encode` returns `String` and is
`alloc`-gated, as is `hex::decode`. The buffer-external forms
`hex::encode_to_slice` / `hex::decode_to_slice` are not. This is a preview of the
whole refactor — see slice 2.

### 3. Which dependencies have no `no_std` story at all? The transports.

These stay in `roots` permanently and are not negotiable, because they *are* the
wrapper: `tokio`, `rustls`, `tokio-rustls`, `tokio-tungstenite`, `quinn`,
`futures-util`, `rcgen`. `thiserror` works without `std` (it is a derive macro,
and `std` in `error.rs` is only `std::io::Error` for the `Io` variant).

## What the separation actually costs, per module

Measured, by counting real uses with doc comments and test modules excluded.
"alloc" is `Vec`/`String`/`Box`/`HashMap`/`format!`/`to_vec`/`to_string`.

| module | lines | std surface | alloc | verdict |
|---|---:|---|---|---|
| `address` | 242 | `fmt`, `net` | 0 | **moves**, needs its own IPv6 text formatter |
| `handshake` | 314 | — | 5 | **moves** |
| `frame` | 230 | `time` | 7 | **moves** |
| `traffic` | 212 | `time` | 5 | **moves** |
| `bloom` | 675 | `collections` | 11 | codec **moves**, `BloomState` does not |
| `pathfind` | 702 | `collections`, `time` | 32 | codec **moves**, `PathState` does not |
| `session` | 1300 | `collections`, `mem`, `sync`, `time` | 26 | codec **moves**, `SessionState` does not |
| `tree` | 996 | `cmp`, `collections`, `time` | 34 | codec **moves**, `TreeState` does not |
| `proto` | 436 | `time` | 13 | **moves** |
| `peer` | 146 | `time` | 0 | **moves** once `Instant` is a value |
| `supervisor` | 87 | `time` | 3 | stays — it is a redial policy over timers |
| `views` | 289 | `time` | 24 | **moves**; it is read-only projection |
| `router` | 1192 | `io`, `sync`, `time` | 21 | split |
| `multicast` | 1162 | `collections`, `iter`, `mem`, `net`, `time` | 31 | codec **moves**, sockets do not |
| `link` | 1797 | `collections`, `fmt`, `fs`, `future`, `io`, `net`, `pin`, `str`, `sync`, `time` | 37 | **stays** — it is the transport |
| `quic`, `tls`, `ws` | 1115 | `io`, `net`, `pin`, `sync`, `task`, `time` | 25 | **stay** — transports |
| `error` | 55 | `io` | 1 | split: core error + wrapper `Io` |
| `traits` | 26 | — | 7 | **moves** |

Roughly **9 000 lines move and 2 900 stay**, but the line count understates it:
the moving part is the part where every allocation is currently invisible
(`to_vec()` on a 32-byte key, `Vec::new()` inside a decode), and the staying
part is where the allocations are already explicit.

### The three things that must be abstracted, not moved

These are the whole design. Everything else is bookkeeping.

**1. `std::time::Instant` (12 modules, 100 references) → a `Clock` trait.**

`Instant` is not just `now()`. It is a *comparable value* stored in five
`HashMap`s (`tree.infos` deadlines, `link.last_write`, `pathfind.entries`,
`session.sessions`, `peer.LinkState.srrt`) and subtracted from
(`srrt - srst` is the entire basis of `getPeers.latency`; `rotated_at.elapsed()`
gates session rotation). So the core needs a time *value* it can store and
compare, not a callback.

The seam: `roots_core::clock::Instant`, a `u64` of whatever unit the caller
picks, plus `trait Clock { fn now(&self) -> Instant }`. `std::time::Instant`
becomes the wrapper's implementation. This is the largest single change and it
is why slice 1 is only the *pure* modules.

A subtlety worth deciding early, because it changes the numbers: `latency` is
`srrt - srst` over *stored* timestamps, so the core's integer representation
must not silently lose the sub-millisecond precision Go's `time.Duration` has.
Slice 4 measures this rather than assuming it.

**2. Owned `Vec` fields in wire structs → borrowed or caller-buffered.**

The codecs parse untrusted input, so they cannot borrow from it (`decode_exact`
takes `&[u8]` and returns owned data today). Four shapes, in increasing order of
intrusion:

| shape | example | cost |
|---|---|---|
| `&'a [u8]` out-param | `fn decode_exact(buf: &[u8], out: &mut Self) -> Result<(), Error>` | smallest; needs `Default` |
| caller buffer | `payload: &'a [u8]` + `payload_len: usize` | moderate |
| caller-owned `Vec` in the struct | `Traffic<'a> { payload: &'a [u8] }` borrowed | moderate |
| fixed-capacity array | `path: [u64; MAX_PATH]` | removes all alloc; needs a documented bound |

`Traffic` is the interesting one: it has `path: Vec<u64>`, `from: Vec<u64>` and
`payload: Vec<u8>`, and `payload` is by far the largest. In practice the path is
0–2 hops (`_getRootAndPath` walks ancestors), so a fixed-capacity array is the
honest encoding — and Go's own `MAX_PATH_SIZE` is the precedent to cite.

**3. Five `HashMap`s of state → caller-provided tables.**

`tree` has six (`peers`, `links`, `infos`, `deadlines`, `responses`, `sent`),
plus `pathfind` 2, `session` 2, `bloom` 3, `link` 1. These are not "convert to a
no_std map" work; they are the reason the user's observation is the right
framing:

> we can afford no alloc simply thanks to making the wrapper handle all the
> buffers and etc, everything dynamic can be simply streamed

The core does not need to *store* these. It needs to answer questions about
them, and it can be handed a `&mut` view of caller-owned storage. The two
directions are different problems and want different solutions:

- **Read-mostly and bounded** — `tree.infos`, `tree.deadlines`, `pathfind.rumors`:
  a fixed-capacity open-addressed table with a documented overflow behaviour.
  `infos` already expires, so "capacity exceeded" degrades to "forgot a node",
  which the protocol tolerates.
- **Caller-owned and genuinely unbounded** — `tree.peers`, `session.sessions`,
  `link.links`: the wrapper keeps the `HashMap` and passes the core a trait
  object or a slice-of-values. This is the "wrapper handles all the buffers" case
  literally.

Guessing here would be the expensive mistake: an overflow policy that drops a
*session* is a silent security-relevant failure, while one that drops a *deadline*
is routine. Slice 3 does the read-mostly ones, slice 5 the caller-owned ones, and
each states its overflow behaviour as a Go citation rather than a preference.

## Slice order, and why this order

Each slice is independently revertible and leaves the suite green, which is the
repo's standing rule ("a proof that encodes the current behaviour stops telling
you when the behaviour is wrong").

**Slice 1 — `roots-core` crate skeleton + the pure modules.**
`address`, `handshake`, `frame`, `error` (core part). These four have 841 lines,
almost no state, and the only obstacles are `std::net::Ipv6Addr` in `address` and
`String` in two error variants. Move them, keep `roots` re-exporting them so
**nothing else changes** — no call site edits at all. That is the proof the
boundary is real.

*Why first:* it is the only slice where "did it work" is answered by the
compiler rather than by a test, and it de-risks the dependency question (Q2)
before any state is touched.

**Slice 2 — the buffer-external codec pass, still inside `roots`.**
`Vec<u8> -> Vec<u8>` becomes `(&mut [u8]) -> usize` for every codec, with the
wrapper owning the scratch buffer. Do this *before* the crate split so the diff
is mechanical and every wire test can run against both shapes at once. Doing it
across a crate boundary and a signature change simultaneously would make a
failure ambiguous between the two.

*Why second:* this is the bulk of the mechanical work and it is where the wire
vectors keep us honest. A codec regression here is caught by
`tests/go_vectors.rs` — real Go bytes — which is the strongest oracle available.

**Slice 3 — `Clock`.**
`Instant` becomes a core value type; `std::time::Instant` becomes the wrapper's
impl. Unlocks `peer`, `traffic`, `proto`, `views`, and the read-mostly tables.
Then the first expiry tests can move across.

*Why third:* it is a prerequisite for every remaining stateful module and it is
independent of the table work, so it parallelises cleanly.

**Slice 4 — the read-mostly tables.**
`tree.infos`, `tree.deadlines`, `pathfind.rumors`, `bloom.on_tree`. Fixed
capacity, documented overflow, Go-cited. `tests/mesh3.rs` is the safety net here
— it is the only test that exercises convergence, and AGENTS.md already warns it
is timing-sensitive, so **one suite at a time**.

*Why fourth:* these have benign overflow, so they are the right place to learn
the table API before the dangerous ones.

**Slice 5 — the caller-owned tables.**
`tree.peers`, `session.sessions`, `pathfind.entries`. Wrapper keeps `HashMap`,
core gets a view. This is the slice where "buffer-external" stops being a
vocabulary and becomes the actual mechanism.

*Why last of the state work:* it is the only one where a mistake loses live
sessions, so it should be written once the vocabulary is proven.

**Slice 6 — split `router` and `driver`.**
`Router` becomes a thin aggregate over core state; `driver` keeps its name in the
wrapper because `serve_links` is inherently I/O-shaped (it awaits reads and
writes). The interesting cut is `dispatch_frame`, which today takes `&mut LinkSet`
purely so its handlers can write replies — see slice 7.

**Slice 7 — `dispatch_frame` becomes stream-shaped.**
Today every handler that provokes a reply awaits `links.write(...)` directly, so
dispatch and I/O are fused. Returning a small `Vec<Out>` (or, once slice 2 lands,
writing into a caller buffer) is what lets the core own the state machine and the
wrapper own the socket — which is the actual goal of the whole exercise, and the
reason it is worth doing at all.

*Why last:* it is the largest behavioural change, it touches every frame type,
and it should be done once the state underneath is already in its final shape.

## What is deliberately *not* in scope

- **`roots-client`.** Already `std`, already the only thing that drives a
  `Router`. Unchanged.
- **The transports.** `link`, `quic`, `tls`, `ws` stay in `roots` permanently.
- **`multicast`'s sockets.** The codec moves; the `UdpSocket` loop does not.
- **`GroupPassword`.** Still unimplemented (see `TODO.md`), and it will be *less*
  invasive after this work: the preimage parameter threads into `encrypt_msg`,
  which slice 2 has already made buffer-external.

## Two risks worth naming before slice 1

**`no_std` is enforced by `std` being *absent from the prelude*, not by a lint.**
That is robust, but it means the gate is only as good as the crate's own
`#![no_std]`. A `roots-core` that declares it and then `extern crate std;` inside
a module would compile. The mitigation is to keep the dependency list minimal and
let `cargo tree` in CI be the second gate — which is what AGENTS.md already
prescribes for `smoltcp`/`tun`.

**`Instant` as an integer is a silent-precision hazard.** Every protocol number
that crosses a link is fixed-width and byte-exact, and `latency` is the one
reported field whose *value* is compared between implementations. A coarse tick
would still round-trip and still pass every wire test while making
`docs/protocol/21-admin.md` wrong. Slice 4 must therefore pin the unit and
resolution explicitly, and the `latency`/`cost` question in `TODO.md` should be
re-measured *after* slice 3, because a changed time representation can plausibly
move those numbers by the order of magnitude currently unexplained.