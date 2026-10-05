#![no_std]
//! `roots-core`: the `no_std`, no-`alloc` half of a Yggdrasil node.
//!
//! This crate holds the parts of `roots` that talk **wire** and own **state**:
//! the link `meta` handshake, the frame envelope, the tree/path/session codecs,
//! key and address derivation. What it does not hold is equally deliberate —
//! no sockets, no timers, no threads, no filesystem, no TUN, no admin socket,
//! and **no allocator**.
//!
//! # Why there is no allocator
//!
//! Not asceticism. A core that cannot allocate cannot *own* anything, and
//! everything it does own therefore has to be supplied by the caller: buffers
//! come in as `&mut [u8]`, and tables are passed in rather than created. That
//! turns three otherwise-hidden costs into the caller's explicit decisions —
//! how big a scratch buffer, what happens when a table is full, what a payload's
//! lifetime is — and all three are questions a `std` caller was already asking
//! in a different voice.
//!
//! The plan, the measurements behind it, and the slice order are in
//! `docs/plans/no-std-core/00-plan.md`.
//!
//! # This is enforced — but only half of it, and the other half is on purpose
//!
//! **`no_std` is compiler-enforced.** `#![no_std]` removes `std` from the
//! prelude *on every target*, so naming `std::` anywhere in this crate is a
//! compile error — on the host target too, which is why CI can be the gate
//! without a bare-metal toolchain. Only `x86_64-unknown-linux-gnu` is installed
//! in this repo's toolchain, deliberately: nothing here should need more.
//!
//! **No-`alloc` is enforced only while nobody writes `extern crate alloc;`.**
//! That is worth being precise about, because it is the difference between a
//! property and a habit, and because the obvious version of this claim is
//! false. Measured, in that order:
//!
//! | probe | result |
//! |---|---|
//! | `#![no_std]` + bare `Vec` | 3 errors, `Vec` not in scope |
//! | `#![no_std]` + `std::` path | 3 errors, `std` not in scope |
//! | `#![no_std]` + `extern crate alloc;` + `alloc::vec::Vec` | **0 errors** |
//!
//! So one line re-opens everything the first two rows close, and it compiles
//! silently. Two gates cover that, and neither is a lint:
//!
//! * `unused_extern_crates = "deny"` ([`workspace.lints.rust`]) fires on an
//!   `extern crate alloc;` that nothing uses — the realistic case, someone
//!   importing it while writing a codec.
//! * `cargo tree -p roots-core -e normal` in CI catches the deliberate case the
//!   lint cannot, because `alloc` cannot appear in a dependency edge without
//!   somebody having enabled it.
//!
//! Note what does *not* work, in case it is proposed: building for a bare-metal
//! target. `alloc` exists as a crate on every target, and a missing global
//! allocator only fails at link time — which never happens for a library,
//! because a library is an rlib. There is no flag for "no allocator, please".
//!
//! So: an unwanted allocation in this crate cannot happen by accident, and the
//! two deliberate ways to do it are both visible in CI. That is the honest
//! claim, and it is weaker than "it cannot compile" — which is why it is written
//! down rather than asserted.
//!
//! # What belongs here
//!
//! | in `roots-core` | in `roots` (the `std` wrapper) |
//! |---|---|
//! | wire formats and their codecs | sockets, listeners, dialing |
//! | state machines over caller-supplied tables | the `HashMap`s themselves |
//! | key derivation, hashing, signatures | the clock, backed by `Instant` |
//! | address *bytes* | address *text* (`Display`, `FromStr`) |
//! | — | TUN, admin socket, multicast sockets |
//!
//! The line is **does this need to own a buffer, a socket or a clock**. It is
//! not a line about size, portability or elegance, and it does not move when
//! the code gets smaller.
//!
//! # Working with caller buffers
//!
//! Codecs here never return an owned buffer. They write into one the caller
//! supplies and report how much they used:
//!
//! ```ignore
//! let mut buf = [0u8; MAX_META];
//! let n = meta.encode(secret, password, &mut buf)?;
//! ```
//!
//! Decoding is the mirror image, and takes untrusted input, so it cannot borrow
//! from it — a `Meta` returned by value owns its `vendor` bytes, and that
//! ownership is a `&[u8]` into the caller's frame buffer plus a length. See
//! [`meta`] for the shape and for why borrowed-not-owned is the safe default
//! here.

pub mod address;
pub mod clock;
pub mod error;

pub use address::{Address, Subnet, addr_for_key, subnet_for_key};
pub use clock::{Clock, FnClock, Instant};
pub use error::Error;

/// The crate version, for `getSelf`-style reporting.
///
/// Present because a node reports its own build, so a core that cannot answer
/// the question is a core that has forced the wrapper to hardcode it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
