//! A fixed-capacity, allocation-free map for the core's read-mostly tables.
//!
//! # What this is for
//!
//! The core cannot allocate, so it cannot own a `HashMap`. For the tables that
//! are **read-mostly and bounded** — the ones where exceeding capacity degrades
//! to "forgot something" rather than "lost something" — the answer is a
//! capacity the caller declares up front, and an *insertion that can fail*.
//!
//! The tables this replaces, and what overflow costs in each case:
//!
//! | table | on overflow |
//! |---|---|
//! | `bloom.on_tree` | a peer is not advertised to the tree, so it stops being routed to. Annoying, recoverable |
//! | `tree.deadlines` | **a node never ages out**, so `r.infos` grows without bound and `_fix` walks dead entries forever. Not benign |
//! | `tree.infos` | a node is forgotten; it re-announces. Benign, because announces are periodic |
//! | `pathfind.rumors` | a pending lookup is dropped, so a resolution never completes. Visible, recoverable |
//!
//! Two of those four are benign, which is why they go first. The two that are
//! not are the reason [`insert`](Table::insert) returns a `Result` rather than
//! silently dropping: **a caller that cannot see an overflow will not decide what
//! to do about it**, and the decision differs per table.
//!
//! # The `Copy` bound is not a preference
//!
//! `K: Copy, V: Copy` looks like an arbitrary limitation and is not. An inline
//! table has to initialise every slot, and there is no way to do that in `no_std`
//! for a type that is not `Copy`:
//!
//! ```compile_fail
//! # use core::option::Option;
//! struct NotCopy([u8; 40]);
//! fn make<const N: usize>() -> [Option<NotCopy>; N] { [None; N] }
//! ```
//!
//! ```text
//! error[E0277]: the trait bound `NotCopy: Copy` is not satisfied
//! ```
//!
//! and `[Option<T>; N]: Default` does not exist either. Without `unsafe` — which
//! this crate denies — there is no inline non-`Copy` storage.
//!
//! So this table serves `on_tree` (`bool`) and `deadlines` (`Instant`), and
//! **cannot** serve `tree.infos` or `pathfind.rumors`, whose values contain a
//! `Vec`. Those need the other design: the caller keeps its own storage and the
//! core gets a view of it, which is a different shape with different rules. This
//! is the finding that decides that slice, and it was cheaper to measure than to
//! argue about.
//!
//! # Collisions and tombstones
//!
//! Open addressing with linear probing. Deletion leaves a **tombstone** rather
//! than back-shifting, because back-shifting on a no-alloc table means
//! re-inserting every following cluster entry, and a probe sequence that gets
//! truncated by a naive "stop at the first empty slot" turns a removal into a
//! silent key loss. Tombstones accumulate, [`Table::compact`] reclaims them, and
//! [`Table::len`](Table::len) counts live entries only.
//!
//! # Hashing
//!
//! FNV-1a, in this module, because `core::hash` has no hasher and a `no_std` crate
//! gets no default. It is a poor hash by modern standards and that is fine: the
//! keys are **32-byte public keys**, not attacker-chosen strings, and even a
//! deliberate collision only costs probe length. A cryptographic hash here would
//! be slower and would not make anything safer.

use core::hash::{Hash, Hasher};

/// FNV-1a, 64-bit. See the module docs for why this and not something better.
#[derive(Debug, Clone, Copy)]
pub struct Fnv(u64);

impl Default for Fnv {
    fn default() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// The table is full: `insert` refused, and nothing was written.
///
/// Returned rather than panicking because the caller's correct response depends
/// on which table it is — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableFull;

impl core::fmt::Display for TableFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("fixed-capacity table is full")
    }
}

/// A fixed-capacity open-addressed map. No allocation, no `unsafe`.
///
/// `N` is the capacity. It is a const generic rather than a runtime value
/// Slot states. A tombstone and an empty slot are **different states**, and
/// conflating them is the classic open-addressing deletion bug: an empty slot
/// terminates a probe chain, so reusing one after a deletion loses every key
/// that hashed past it.
const NEVER_USED: u8 = 0;
const LIVE: u8 = 1;
const TOMBSTONE: u8 = 2;

/// A fixed-capacity open-addressed map. No allocation, no `unsafe`.
///
/// `N` is the capacity, a const generic because the whole point is that the
/// storage is inline — a runtime capacity would need a runtime-sized array.
#[derive(Debug, Clone)]
pub struct Table<K, V, const N: usize> {
    slots: [Option<(K, V)>; N],
    state: [u8; N],
    /// Counted so [`Table::len`] can report live entries rather than occupied
    /// slots, and so [`Table::compact`] knows there is work to do.
    tombs: usize,
}

impl<K: Copy, V: Copy, const N: usize> Default for Table<K, V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Copy, V: Copy, const N: usize> Table<K, V, N> {
    /// An empty table. Does not allocate and cannot fail.
    pub const fn new() -> Self {
        Table {
            slots: [None; N],
            state: [NEVER_USED; N],
            tombs: 0,
        }
    }

    /// Live entries. Tombstones are not counted.
    pub fn len(&self) -> usize {
        self.occupied() - self.tombs
    }

    /// Is the table empty?
    ///
    /// "Empty" means **no live entries**, which is what a caller asking "do I have
    /// anything to iterate" wants. A table holding only tombstones is empty and
    /// still occupies its slots, so `len() == 0` is the only correct test.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slots holding something — a live entry or a tombstone.
    ///
    /// Exposed because a table that is `len()`-short of `occupied()` is exactly
    /// when a caller wants to know whether [`compact`](Self::compact) would help.
    pub fn occupied(&self) -> usize {
        self.state.iter().filter(|s| **s != NEVER_USED).count()
    }

    /// Look a key up.
    pub fn get(&self, key: &K) -> Option<V>
    where
        K: Eq + Hash,
    {
        let mut i = self.probe_start(key);
        for _ in 0..N {
            match self.state[i] {
                // A never-used slot ends the chain. A tombstone does **not**: the
                // key it held may have been followed by others that are still live.
                NEVER_USED => return None,
                LIVE => {
                    if let Some((k, v)) = self.slots[i]
                        && k == *key
                    {
                        return Some(v);
                    }
                }
                _ => {}
            }
            i = (i + 1) % N;
        }
        None
    }

    /// Does the table hold this key?
    ///
    /// This is `self.get(key).is_some()`, and that is not a shortcut — it is the
    /// whole implementation, because `get` returns `Option<V>` and `Some(false)`
    /// is still a present key.
    ///
    /// I wrote a comment here claiming it could *not* be written that way, on the
    /// grounds that `V: PartialEq` cannot distinguish "absent" from "present and
    /// equal to the default". That was wrong, and a mutation run is what found it:
    /// rewriting `contains` as `get(key).is_some()` passed, and passing is what a
    /// correct mutation does. The confusion was between `Option::is_some()` and
    /// the value's own truthiness — the first is a presence test, the second would
    /// have been the bug.
    pub fn contains(&self, key: &K) -> bool
    where
        K: Eq + Hash,
    {
        let mut i = self.probe_start(key);
        for _ in 0..N {
            match self.state[i] {
                NEVER_USED => return false,
                LIVE => {
                    if let Some((k, _)) = self.slots[i]
                        && k == *key
                    {
                        return true;
                    }
                }
                _ => {}
            }
            i = (i + 1) % N;
        }
        false
    }

    /// Insert or replace, returning the **previous** value.
    ///
    /// The previous value is what makes this composable with the caller that cares
    /// about change: `bloom.on_tree` sends a blank filter only when a peer *was*
    /// on the tree and now is not, which is `was && !on` on what this returns.
    ///
    /// `Err(TableFull)` means **nothing was written** — not "the old value is
    /// gone", not "the key now maps to the new value". A caller that retries on a
    /// full table must not find a half-applied insert waiting for it.
    ///
    /// A tombstone on the probe chain is **reused** rather than skipped. That is
    /// what stops a churn-heavy caller — a peer flapping on and off the tree —
    /// from leaking a slot per flap until the table is full of nothing and every
    /// insert fails.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, TableFull>
    where
        K: Eq + Hash,
    {
        let mut first_tomb: Option<usize> = None;
        let mut i = self.probe_start(&key);
        for _ in 0..N {
            match self.state[i] {
                LIVE => {
                    if let Some((k, old)) = self.slots[i]
                        && k == key
                    {
                        self.slots[i] = Some((key, value));
                        return Ok(Some(old));
                    }
                    i = (i + 1) % N;
                }
                TOMBSTONE => {
                    first_tomb.get_or_insert(i);
                    i = (i + 1) % N;
                }
                _ => {
                    // End of the chain: the key is absent, so insert at the first
                    // tombstone if there was one, else here.
                    let target = first_tomb.unwrap_or(i);
                    let was_tomb = self.state[target] == TOMBSTONE;
                    self.slots[target] = Some((key, value));
                    self.state[target] = LIVE;
                    if was_tomb {
                        self.tombs -= 1;
                    }
                    return Ok(None);
                }
            }
        }
        // The whole table was walked without finding the key *and* without
        // reaching a never-used slot — which happens exactly when the table is
        // completely full. A tombstone seen on the way is still free space, and
        // refusing here would mean a churn-heavy caller fills the table with
        // tombstones and then gets `Err` for every subsequent insert even though
        // there is room. So the tombstone is used now.
        if let Some(t) = first_tomb {
            self.slots[t] = Some((key, value));
            self.state[t] = LIVE;
            self.tombs -= 1;
            return Ok(None);
        }
        // Every slot is live, there is no tombstone to reuse, and the key is not
        // present. Genuinely full, and nothing was written.
        Err(TableFull)
    }

    /// Remove a key, returning its value.
    ///
    /// Leaves a **tombstone** rather than an empty slot, and that is the whole
    /// point: an empty slot would terminate the probe chain for every key that was
    /// inserted after this one, silently losing them. The failure is not a crash —
    /// it is a key that was never removed becoming unfindable.
    pub fn remove(&mut self, key: &K) -> Option<V>
    where
        K: Eq + Hash,
    {
        let mut i = self.probe_start(key);
        for _ in 0..N {
            match self.state[i] {
                NEVER_USED => return None,
                LIVE => {
                    if let Some((k, v)) = self.slots[i]
                        && k == *key
                    {
                        self.slots[i] = None;
                        self.state[i] = TOMBSTONE;
                        self.tombs += 1;
                        return Some(v);
                    }
                    i = (i + 1) % N;
                }
                _ => i = (i + 1) % N,
            }
        }
        None
    }

    /// Reclaim tombstones, so a long-running node's probe chains do not grow
    /// without bound.
    ///
    /// Takes `self` by value and returns a rebuilt table, which is how it avoids
    /// allocating: a fresh inline array is built on the stack and swapped in. The
    /// cost is one `Self` of stack, which is why this is not `&mut self` — and why
    /// a caller that compacts in a loop pays for a `Table` on the stack each time,
    /// which for these sizes is a few hundred bytes.
    pub fn compact(self) -> Self
    where
        K: Eq + Hash,
    {
        if self.tombs == 0 {
            return self;
        }
        let mut fresh = Self::new();
        for i in 0..N {
            if self.state[i] == LIVE
                && let Some((k, v)) = self.slots[i]
            {
                // Cannot fail: `fresh` has the same capacity and at most `len()`
                // entries are being inserted into it.
                let _ = fresh.insert(k, v);
            }
        }
        fresh
    }

    /// Visit every live entry exactly once.
    ///
    /// A callback rather than an iterator because inline storage with tombstones
    /// makes an iterator carry an index and a borrow of `self`, and the one caller
    /// (`bloom_fix`) wants to *mutate* the table while walking it — which an
    /// iterator borrow would forbid silently rather than at compile time.
    pub fn for_each<F: FnMut(K, V)>(&self, mut f: F) {
        for i in 0..N {
            if self.state[i] == LIVE
                && let Some((k, v)) = self.slots[i]
            {
                f(k, v);
            }
        }
    }

    fn probe_start(&self, key: &K) -> usize
    where
        K: Hash,
    {
        let mut h = Fnv::default();
        key.hash(&mut h);
        // `N == 0` is a degenerate table that holds nothing, and it must not
        // divide by zero on the way to discovering that. Every probe loop below
        // is `for _ in 0..N`, so they all exit immediately; returning 0 keeps them
        // well-formed rather than panicking in here.
        if N == 0 {
            return 0;
        }
        (h.finish() as usize) % N
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-byte key shaped like a node public key, so the tests exercise the
    /// real key size rather than a `u8` that probes cleanly by accident.
    fn k(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = n;
        out[31] = n.wrapping_mul(31);
        out
    }

    #[test]
    fn insert_then_get() {
        let mut t: Table<[u8; 32], bool, 16> = Table::new();
        assert!(t.is_empty());
        assert_eq!(t.insert(k(1), true), Ok(None));
        assert_eq!(t.insert(k(2), false), Ok(None));
        assert_eq!(t.get(&k(1)), Some(true));
        assert_eq!(t.get(&k(2)), Some(false));
        assert_eq!(t.get(&k(3)), None);
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
    }

    /// Insert returns the **previous** value, which is what
    /// `bloom.on_tree`'s `was && !on` depends on to decide whether to send a blank
    /// filter.
    #[test]
    fn insert_returns_the_previous_value() {
        let mut t: Table<[u8; 32], bool, 8> = Table::new();
        assert_eq!(
            t.insert(k(1), false),
            Ok(None),
            "a new key has no old value"
        );
        assert_eq!(
            t.insert(k(1), true),
            Ok(Some(false)),
            "an update returns the old"
        );
        assert_eq!(t.get(&k(1)), Some(true), "and stores the new");
        assert_eq!(t.len(), 1, "an update is not a second entry");
    }

    /// A full table refuses, **and refuses without writing anything**.
    ///
    /// The second half is the one that matters. A caller that retries on
    /// `TableFull` must not find a half-applied insert waiting for it, and an
    /// implementation that updated the value before discovering there was no room
    /// would be silently lossy.
    #[test]
    fn a_full_table_refuses_without_writing() {
        let mut t: Table<[u8; 32], u8, 4> = Table::new();
        for i in 0..4u8 {
            assert_eq!(t.insert(k(i), i), Ok(None), "filling slot {i}");
        }
        assert_eq!(t.len(), 4, "the table is full");
        // A new key is refused.
        assert_eq!(t.insert(k(9), 9), Err(TableFull));
        assert_eq!(t.get(&k(9)), None, "and nothing was written");
        // Updating an *existing* key still works: it needs no new slot, and
        // refusing it would make a full table read-only.
        assert_eq!(t.insert(k(2), 200), Ok(Some(2)), "an update needs no room");
        assert_eq!(t.get(&k(2)), Some(200));
    }

    /// Removal must not truncate a probe chain.
    ///
    /// This is the bug the tombstone exists to prevent, and it is worth being
    /// concrete about the failure: without a tombstone, removing the *first* key of
    /// a two-key cluster leaves an empty slot where the second key still lives, and
    /// a later `get` for that second key stops at the empty slot and reports
    /// `None` — a key that was never removed, silently lost.
    ///
    /// The keys are chosen to collide: the test forces a shared probe start by
    /// inserting until it finds a pair, so it is a real cluster rather than a hoped-
    /// for one.
    #[test]
    fn removal_does_not_lose_a_colliding_key() {
        // Find two distinct keys that land in the same slot, so the cluster is
        // real. With capacity 8 that is a handful of tries.
        let mut a = 0u8;
        let mut b = 0u8;
        'outer: for x in 1..=200u8 {
            for y in 1..=200u8 {
                if x == y {
                    continue;
                }
                // An empty table is enough to ask where a key *would* start, so
                // no insert is needed and there is no `Result` to discard.
                let probe = Table::<[u8; 32], u8, 8>::new();
                if probe.probe_start(&k(x)) == probe.probe_start(&k(y)) {
                    a = x;
                    b = y;
                    break 'outer;
                }
            }
        }
        assert_ne!(a, 0, "the test must find a real collision to mean anything");

        let mut t: Table<[u8; 32], u8, 8> = Table::new();
        assert_eq!(t.insert(k(a), a), Ok(None));
        assert_eq!(t.insert(k(b), b), Ok(None), "b lands in a's cluster");
        assert_eq!(t.remove(&k(a)), Some(a));
        // **b is still there.** This is the assertion the tombstone buys.
        assert_eq!(
            t.get(&k(b)),
            Some(b),
            "removing a must not truncate the chain and lose b"
        );
        assert_eq!(t.len(), 1);
        assert!(t.contains(&k(b)));
    }

    /// Tombstones are reclaimed, and a compacted table behaves like a fresh one.
    ///
    /// Without this a long-running node's chains grow for as long as it runs,
    /// and `occupied` would climb while `len` stayed flat — which reads like a
    /// memory leak and is a probe-length problem instead.
    #[test]
    fn compaction_reclaims_tombstones() {
        let mut t: Table<[u8; 32], u8, 8> = Table::new();
        for i in 0..6u8 {
            assert_eq!(t.insert(k(i), i), Ok(None));
        }
        for i in 0..4u8 {
            assert_eq!(t.remove(&k(i)), Some(i));
        }
        assert_eq!(t.len(), 2, "two live entries remain");
        assert!(t.occupied() > t.len(), "and four tombstones occupy slots");

        let t = t.compact();
        assert_eq!(t.len(), 2, "the same two entries");
        assert_eq!(t.occupied(), 2, "with no tombstones");
        for i in 4..6u8 {
            assert_eq!(t.get(&k(i)), Some(i), "and both still findable");
        }
        // And it can be filled again — `compact` returned a new value, so the
        // binding has to be mutable again.
        let mut t = t;
        for i in 6..8u8 {
            assert_eq!(t.insert(k(i), i), Ok(None), "room was reclaimed");
        }
    }

    /// Reusing a tombstone does not grow the table.
    ///
    /// The insert path remembers the first tombstone on the probe chain and writes
    /// there rather than at the end. If it did not, a churn-heavy workload (a peer
    /// flapping on and off the tree) would leak slots until the table was full of
    /// nothing and every insert failed.
    #[test]
    fn a_reused_key_does_not_consume_a_new_slot() {
        let mut t: Table<[u8; 32], u8, 8> = Table::new();
        for i in 0..8u8 {
            assert_eq!(t.insert(k(i), i), Ok(None));
        }
        assert_eq!(t.len(), 8);
        // Churn one key repeatedly. The stored value changes each round, so the
        // `remove` must hand back *that* round's value — asserting a constant
        // here would be asserting the churn did not happen.
        for round in 0..10u8 {
            assert_eq!(
                t.remove(&k(3)),
                Some(3 + round),
                "round {round} removes what the last round stored"
            );
            assert_eq!(
                t.insert(k(3), 3 + round + 1),
                Ok(None),
                "and the re-insert is a fresh key, not an update"
            );
        }
        assert_eq!(
            t.occupied(),
            8,
            "churn must not grow the table; it is the whole reason for tombstones"
        );
    }

    /// `for_each` visits every live entry exactly once, and nothing else.
    ///
    /// `bloom_fix` rebuilds the on-tree flags by walking this, so a missed entry
    /// is a peer that silently stops being routed to.
    #[test]
    fn for_each_visits_live_entries_once() {
        let mut t: Table<[u8; 32], u8, 16> = Table::new();
        for i in 0..10u8 {
            assert_eq!(t.insert(k(i), i), Ok(None));
        }
        t.remove(&k(4));
        t.remove(&k(7));

        let mut seen = [0u8; 16];
        let mut count = 0;
        t.for_each(|_key, v| {
            seen[count] = v;
            count += 1;
        });
        assert_eq!(count, 8, "eight live entries");
        seen[..count].sort_unstable();
        assert_eq!(seen[..count], [0, 1, 2, 3, 5, 6, 8, 9], "and no tombstone");
    }

    /// A capacity of zero is a degenerate but legal table that holds nothing.
    ///
    /// Not a configuration anyone should choose, but it must not panic and must not
    /// silently succeed — `N - x` and `% N` both divide by it, so this is where a
    /// zero-capacity mistake would show up.
    #[test]
    fn zero_capacity_holds_nothing_and_does_not_panic() {
        let mut t: Table<[u8; 32], u8, 0> = Table::new();
        assert_eq!(t.insert(k(1), 1), Err(TableFull));
        assert_eq!(t.get(&k(1)), None);
        assert_eq!(t.remove(&k(1)), None);
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert_eq!(t.occupied(), 0);
        let mut n = 0;
        t.for_each(|_, _| n += 1);
        assert_eq!(n, 0);
    }

    /// The FNV hash must actually spread keys.
    ///
    /// A hash that put every `[u8; 32]` with the same first byte in the same slot
    /// would still pass every other test here, because the collision tests find
    /// their own collisions. This one checks the *distribution*, which is what
    /// keeps probe chains short.
    #[test]
    fn the_hash_spreads_realistic_keys() {
        let mut t: Table<[u8; 32], u8, 64> = Table::new();
        for i in 0..32u8 {
            // Vary the key the way real keys vary: the first byte differs, and so
            // does everything after it.
            let mut key = k(i);
            for (j, b) in key.iter_mut().enumerate().skip(1) {
                *b = i.wrapping_mul(j as u8).wrapping_add(7);
            }
            assert_eq!(t.insert(key, i), Ok(None));
        }
        assert_eq!(t.len(), 32, "all 32 distinct keys stored");
        // No chain longer than 4 for 32 keys in 64 slots: a degenerate hash would
        // put them all in one chain and `occupied` would still be 32 while lookups
        // scanned 32 entries each.
        let mut worst = 0;
        for i in 0..32u8 {
            let mut key = k(i);
            for (j, b) in key.iter_mut().enumerate().skip(1) {
                *b = i.wrapping_mul(j as u8).wrapping_add(7);
            }
            let mut probes = 0;
            let mut idx = t.probe_start(&key);
            while let Some((found, _)) = t.slots[idx] {
                probes += 1;
                if found == key {
                    break;
                }
                idx = (idx + 1) % 64;
            }
            worst = worst.max(probes);
        }
        assert!(worst <= 4, "worst probe chain was {worst}, expected <= 4");
    }

    /// Removing a key that is not there leaves the table exactly as it was.
    ///
    /// The trap is a `remove` that creates a tombstone unconditionally, which would
    /// let a caller probing for a key's absence slowly fill the table.
    #[test]
    fn removing_an_absent_key_is_a_no_op() {
        let mut t: Table<[u8; 32], u8, 8> = Table::new();
        for i in 0..4u8 {
            assert_eq!(t.insert(k(i), i), Ok(None));
        }
        let before = t.occupied();
        for i in 100..110u8 {
            assert_eq!(t.remove(&k(i)), None);
        }
        assert_eq!(
            t.occupied(),
            before,
            "absent keys must not leave tombstones"
        );
        assert_eq!(t.len(), 4);
    }
}
