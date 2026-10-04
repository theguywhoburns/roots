//! The wrapper's error type: everything `roots_core::Error` can say, plus the
//! things that need a system to happen.
//!
//! # Why this is a wrapper and not a re-export
//!
//! `roots-core` cannot describe an I/O failure: `std::io::Error` needs `std`,
//! and this crate is `no_std`. But every real send can fail with one, and an
//! `Io` variant that is *absent* rather than *unreachable* is how a `no_std`
//! boundary leaks — a caller in `roots` writing `match e { CoreError::NoLink =>
//! .. }` would be told at compile time that something is missing, which is the
//! good case, and a caller writing `CoreError::Timeout` would never learn that a
//! socket can also time out, which is the bad one.
//!
//! So the split is: **core owns the protocol refusals, the wrapper owns the
//! system failures, and this type is where the two meet.** It is a newtype
//! rather than a re-export so that a `std` caller matching errors sees one
//! exhaustive type containing both halves.
//!
//! # What this costs, and why it is worth it
//!
//! The alternative — re-exporting `roots_core::Error` and adding no `Io`
//! variant — is strictly worse and not obviously so at first. Every `?` on a
//! socket read in this crate would have to map `io::Error` onto a core variant,
//! and the only honest mapping is `NoLink`, which says "there is no live link to
//! this peer" when what actually happened is "the peer reset the connection".
//! Those are different facts: the first is a routing decision, the second is an
//! event, and only the second justifies [`Error::is_link`] returning `true`.
//!
//! Losing that distinction is how a reconnect loop ends up treating a refused
//! connection like a routing dead end.
//!
//! # Conversions
//!
//! [`From<CoreError>`] is total and infallible — every protocol refusal is a
//! wrapper error — and [`From<std::io::Error>`] maps to [`Error::Io`]. Both are
//! one-way on purpose: there is no `From<Error> for CoreError`, because dropping
//! the `Io` variant would discard the reason the error happened, and a caller
//! that wants the core half should match on it rather than launder it.

use std::io;

pub use roots_core::error::Error as CoreError;

/// A failure in the `std` wrapper, from any layer.
///
/// `Core(CoreError)` rather than a flattened enum with 17 variants: the core
/// error will *gain* variants as slices 2–7 move modules across, and duplicating
/// that list here would mean every addition is a second edit in a crate that
/// exists precisely to add things elsewhere. The `is_link` forwarding below is
/// the one place that has to know the shape, and it says so.
#[derive(Debug)]
pub enum Error {
    /// A protocol-level refusal, decided entirely by the bytes on a link.
    ///
    /// See [`CoreError`] for the variants and what each one means.
    Core(CoreError),
    /// A socket, listener or filesystem operation failed.
    ///
    /// The `std` half of the type, and the reason this exists.
    Io(io::Error),
    /// A peer URI could not be parsed.
    ///
    /// Carries the offending text because `addPeer` puts it straight into the
    /// admin socket's `error` field, where `yggdrasilctl` displays it — so an
    /// operator needs to see *which* URI failed, not that one did.
    ///
    /// This is why the core error has no `BadUri` variant: parsing a URI needs
    /// an allocator for the string, and URI parsing is a wrapper concern
    /// (`link::parse_link_uri`) that the core never performs.
    BadUri(String),
    /// `max_backoff` was too large, or not a duration.
    ///
    /// Wrapper-only because it is read out of a config file, which is a
    /// wrapper-owned input. The string is Go's, verbatim, for the same
    /// `yggdrasilctl` reason as every other refusal.
    BadMaxBackoff(String),
}

impl Error {
    /// True for the errors that mean **"this link is gone"** rather than "this
    /// node is broken".
    ///
    /// A node loop keeps serving its surviving links and redials on these, and
    /// stops on anything else — so the classification decides whether one dead
    /// peer takes the node down with it.
    ///
    /// Three of the four arms are the wrapper's own business, and only the last
    /// is delegated: `Io` is the common case (a peer that vanishes), `NoLink` is
    /// the routing case, and `BadUri` is a misconfiguration that redialing cannot
    /// fix. The core's own `is_link` answers the protocol half.
    ///
    /// Go gets this for free from structure — a dead peer's reader goroutine
    /// returns and `removePeer` cleans up (`peers.go:228`) — which is why one dead
    /// link never stops its siblings there.
    pub fn is_link(&self) -> bool {
        match self {
            Error::Io(_) => true,
            // Everything else defers to the core, **which is the whole point of
            // the delegation**: slices 2–7 will move modules across and the core
            // error will gain variants, and if the wrapper classified them this
            // arm would have to be updated in step. Delegating means a new core
            // variant is classified by whoever wrote it, in the crate that owns
            // the reason — and a variant nobody has classified yet is refused by
            // the compiler here rather than silently defaulting to `false`.
            //
            // The `false` arms below are therefore the only ones written out, and
            // they are the wrapper's own variants: a URI that will not parse and a
            // backoff that will not parse are operator errors, where retrying
            // produces the same refusal forever. Treating those as dead links is
            // how a node ends up in a silent redial loop against its own
            // configuration.
            Error::BadUri(_) | Error::BadMaxBackoff(_) => false,
            other => other.core().map(|c| c.is_link()).unwrap_or(false),
        }
    }

    /// The protocol refusal underneath, if this is one.
    ///
    /// A convenience for the many call sites that only care about *why* the
    /// handshake was refused and treat every wrapper failure alike — mostly the
    /// handshake path, where an `Io` and a `Core` are the same event.
    pub fn core(&self) -> Option<&CoreError> {
        match self {
            Error::Core(e) => Some(e),
            _ => None,
        }
    }
}

// The core's 16 variants, re-exposed as associated constants.
//
// These exist so that the ~120 `Err(Error::Core(CoreError::InvalidLength))`-shaped sites in
// this crate keep compiling unchanged after `error` moved to `roots-core`.
// The alternative was to edit all of them to `Error::Core(CoreError::X)`,
// which is a large mechanical diff that a reviewer has to read past to find
// the one line that matters — and the *reason* for the wrapper is precisely
// that the core half is not the whole story, so burying every protocol
// refusal under `Core(..)` at every construction site makes the code harder
// to read, not easier.
//
// What this does **not** do is make them patterns. `Error::NoLink =>` in a
// `match` resolves to the associated const, which is not a valid pattern, so
// a match must write `Error::Core(CoreError::NoLink)`. That is acceptable
// because there are no such matches today, and it is also the more honest
// spelling: writing `Core(..)` in a pattern says "this is a protocol
// refusal, and I have decided that is the same as an I/O failure here",
// which is a decision worth making visibly.
//
// The lowercase names are deliberate and linted: these are value constructors
// spelled like variants, and `#[allow(non_upper_case_globals)]` is the price
// of not editing 120 call sites. Clippy's `non_upper_case_globals` would
// otherwise fire on every one of them.
#[allow(non_upper_case_globals)]
impl Error {
    #[allow(non_upper_case_globals)]
    pub const InvalidPreamble: Self = Self::Core(CoreError::InvalidPreamble);
    #[allow(non_upper_case_globals)]
    pub const InvalidLength: Self = Self::Core(CoreError::InvalidLength);
    #[allow(non_upper_case_globals)]
    pub const BadPassword: Self = Self::Core(CoreError::BadPassword);
    #[allow(non_upper_case_globals)]
    pub const SelfDial: Self = Self::Core(CoreError::SelfDial);
    #[allow(non_upper_case_globals)]
    pub const KeyNotAllowed: Self = Self::Core(CoreError::KeyNotAllowed);
    #[allow(non_upper_case_globals)]
    pub const PinnedMismatch: Self = Self::Core(CoreError::PinnedMismatch);
    #[allow(non_upper_case_globals)]
    pub const PasswordTooLong: Self = Self::Core(CoreError::PasswordTooLong);
    #[allow(non_upper_case_globals)]
    pub const UnrecognisedSchema: Self = Self::Core(CoreError::UnrecognisedSchema);
    #[allow(non_upper_case_globals)]
    pub const PinnedKeyInvalid: Self = Self::Core(CoreError::PinnedKeyInvalid);
    #[allow(non_upper_case_globals)]
    pub const PriorityInvalid: Self = Self::Core(CoreError::PriorityInvalid);
    #[allow(non_upper_case_globals)]
    pub const PasswordInvalid: Self = Self::Core(CoreError::PasswordInvalid);
    #[allow(non_upper_case_globals)]
    pub const MaxBackoffInvalid: Self = Self::Core(CoreError::MaxBackoffInvalid);
    #[allow(non_upper_case_globals)]
    pub const BadSubprotocol: Self = Self::Core(CoreError::BadSubprotocol);
    #[allow(non_upper_case_globals)]
    pub const Timeout: Self = Self::Core(CoreError::Timeout);
    #[allow(non_upper_case_globals)]
    pub const NoLink: Self = Self::Core(CoreError::NoLink);

    /// The one core variant that carries data, so it cannot be a constant.
    ///
    /// A function rather than a variant-shaped const because the payload is
    /// the two version numbers, and a caller writing
    /// `Error::bad_version(theirs, ours)` is saying something a const could
    /// not.
    pub const fn bad_version(theirs: u16, ours: u16) -> Self {
        Self::Core(CoreError::BadVersion(theirs, ours))
    }
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Core(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// A `std::error::Error` impl for `CoreError` **cannot exist**, and the reason is
/// worth stating because it is not an oversight:
///
/// * `core::error::Error` is unstable, so the `no_std` crate cannot name it;
/// * `std::error::Error` lives in `std`, which `roots-core` cannot name;
/// * and the orphan rule then forbids *this* crate from adding it, because both
///   the trait and the type are foreign here.
///
/// All three, together, mean the only way for a core error to be a
/// `std::error::Error` is to be wrapped. Which is what [`Error::Core`] is, and
/// so a caller who wants the trait goes through this type — and the `source()`
/// below is where the wrapped error is reachable.
///
/// The upshot is a small, deliberate asymmetry: a bare `CoreError` is not a
/// `std::error::Error`, but everything reachable through `roots::Error` is. The
/// alternative — a `roots-core` feature that adds `std` — would put an
/// *optional* `std` in a crate whose entire claim is that it has none, and would
/// make the no-alloc gate conditional on a cargo flag.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Delegate rather than re-wording: the core strings are Go's
            // verbatim, and a wrapper that paraphrased them would show an
            // operator different text than the one pinned in `21-admin.md`.
            Error::Core(e) => core::fmt::Display::fmt(e, f),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::BadUri(u) => write!(f, "bad peer URI: {u}"),
            Error::BadMaxBackoff(m) => write!(f, "max backoff duration invalid: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            // A `CoreError` cannot itself be a `std::error::Error`: `core` cannot
            // name the unstable trait, `roots-core` cannot name `std`, and the
            // orphan rule stops this crate from supplying it. See the note above
            // `impl Display`. So the chain stops at the core error rather than
            // descending into it — the message is on the `Display` above, which is
            // where a reporter reads it anyway.
            Error::Core(_) | Error::BadUri(_) | Error::BadMaxBackoff(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two halves classify independently, and this is the test that says so.
    ///
    /// The mutation it kills is folding `Io` into "not a link error" — which
    /// compiles, reads as defensible ("only routing failures are recoverable"),
    /// and would turn every peer disconnection into a node shutdown. Go's own
    /// reader goroutine treats a dead socket as routine (`peers.go:228`), so the
    /// opposite is the correct answer.
    #[test]
    fn an_io_error_is_a_dead_link_and_a_bad_uri_is_not() {
        let io = io::Error::new(io::ErrorKind::ConnectionReset, "peer went away");
        assert!(
            Error::Io(io).is_link(),
            "a reset socket is the commonest dead link there is"
        );
        assert!(
            !Error::BadUri("gopher://nope".into()).is_link(),
            "redialing a URI that will not parse cannot succeed"
        );
        assert!(
            !Error::BadMaxBackoff("forever".into()).is_link(),
            "and neither can an unusable backoff"
        );
        assert!(Error::Core(CoreError::NoLink).is_link());
        // A protocol refusal is not a dead link: the peer is talking nonsense,
        // which no amount of redialing fixes.
        assert!(!Error::Core(CoreError::InvalidLength).is_link());
        assert!(!Error::Core(CoreError::BadPassword).is_link());
    }

    /// `core()` sees through the wrapper, and sees nothing when there is no core
    /// error to see.
    ///
    /// The mutation is an `is_some()` that ignores the `Io` arm, which would
    /// report a routing failure for every connection reset.
    #[test]
    fn core_reaches_only_the_protocol_half() {
        assert_eq!(
            Error::Core(CoreError::SelfDial).core(),
            Some(&CoreError::SelfDial)
        );
        assert!(
            Error::Io(io::Error::other("x")).core().is_none(),
            "an I/O failure is not a protocol refusal, however it is reported"
        );
        assert!(Error::BadUri("x".into()).core().is_none());
    }

    /// `Display` must not paraphrase the core's strings.
    ///
    /// Go's own text is what an operator sees, and it is pinned in
    /// `roots_core::error`'s test against `core/link.go:149-157`. If the wrapper
    /// reworded it — say, prefixing "link: " — every one of those assertions
    /// would still pass while the admin socket showed something else.
    #[test]
    fn display_delegates_to_the_core_text() {
        assert_eq!(
            Error::Core(CoreError::SelfDial).to_string(),
            "node cannot connect to self",
            "Go's wording, unprefixed"
        );
        assert_eq!(
            Error::Core(CoreError::UnrecognisedSchema).to_string(),
            "link schema unknown"
        );
        // The wrapper's own variants name themselves, because there is no Go text
        // for them: `BadUri`'s content is the caller's URI.
        assert_eq!(
            Error::BadUri("tcp://[bad".into()).to_string(),
            "bad peer URI: tcp://[bad",
            "and the URI has to survive into the message, or the operator cannot tell which one failed"
        );
    }

    /// `source()` chains to the inner error, so an error reporter can walk it.
    #[test]
    fn source_reports_the_underlying_error() {
        // A core error does NOT descend: it cannot be a `std::error::Error` (see
        // the note above `impl Display`), so the chain stops there. The message
        // is on `Display`, which is where every caller reads it.
        let e = Error::Core(CoreError::Timeout);
        assert!(std::error::Error::source(&e).is_none());
        let e = Error::Io(io::Error::other("boom"));
        assert!(std::error::Error::source(&e).is_some());
        // A `BadUri` has no inner error: the string *is* the whole story, and
        // inventing a source for it would suggest there is something to look at.
        assert!(std::error::Error::source(&Error::BadUri("x".into())).is_none());
    }
}
