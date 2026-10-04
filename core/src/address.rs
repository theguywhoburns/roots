//! IPv6 address / subnet derivation from ed25519 node keys.
//!
//! Port of Go `src/address/address.go`. No hashing: the address embeds the
//! bitwise inverse of the public key (minus leading 1s + first 0), prefixed
//! with [`NODE_PREFIX`] (`ones` count in byte 1). Subnets set the low bit.
//!
//! # Why this is in the core and not the wrapper
//!
//! The obvious answer is "address *text* needs `std`, so `Display` goes in the
//! wrapper" — which is what the plan in `docs/plans/no-std-core/00-plan.md`
//! assumed before it was checked. It is not necessary.
//!
//! `std::net::Ipv6Addr` is used here for exactly two things: `.octets()` to get
//! bytes out, and `Display` to render them. Both are available without `std`:
//! `core::net::Ipv6Addr` has `octets()`, and it implements `fmt::Display` under
//! `no_std`. So the formatter stays, is a `core::fmt::Display` impl, and writes
//! into whatever `fmt::Write` the caller supplies — a `String` in the wrapper,
//! a fixed buffer here.
//!
//! That is not a small thing. Address text is **not** internal pretty-printing:
//! `getSelf` returns it as a JSON string, `addPeer` echoes it back, and an
//! operator reads it. Had the split forced text into the wrapper, every caller
//! that wanted an address as a string would have needed the wrapper, and the
//! core could not have named a peer at all.
//!
//! The one thing that genuinely does need an allocator is `FromStr` — parsing
//! text *into* an address needs somewhere to put the intermediate, and more
//! importantly is a user-input path with no place in a core that never sees user
//! input. It stays in `roots`.

use core::net::Ipv6Addr;

/// First byte of every node address (`0200::/7`-ish, bit0 = 0).
pub const NODE_PREFIX: u8 = 0x02;
/// OR-mask turning a node prefix byte into a subnet prefix byte (`03..`).
pub const SUBNET_BIT: u8 = 0x01;
/// Length of an ed25519 public key / node ID in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a full node address in bytes.
pub const ADDR_LEN: usize = 16;
/// Length of a routed /64 prefix in bytes.
pub const SUBNET_LEN: usize = 8;
/// Bytes of prefix before the `ones` count byte.
pub const PREFIX_LEN: usize = 1;
/// Address payload bytes after prefix + `ones` (14 of 16).
pub const ADDR_PAYLOAD_LEN: usize = ADDR_LEN - PREFIX_LEN - 1;
/// Bit offset where address payload starts feeding key bits back.
pub const PAYLOAD_BIT_OFFSET: usize = 8 * (PREFIX_LEN + 1);
/// Total key bits scanned.
pub const KEY_BITS: usize = 8 * KEY_LEN;

/// A full 16-byte node or subnet address.
///
/// Bytes, not text: see the module docs for why the text form can be rendered
/// under `no_std` and therefore lives here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; ADDR_LEN]);

/// A routed /64 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Subnet(pub [u8; SUBNET_LEN]);

/// The node's mesh address, derived from its ed25519 public key.
///
/// No hashing and no allocation — it is a bit-shuffle of the key's inverse — so
/// it is exactly the kind of thing a core should own. Go: `address.GetAddress`
/// (`src/address/address.go`).
pub fn addr_for_key(public_key: &[u8; KEY_LEN]) -> Address {
    let mut inv = [0u8; KEY_LEN];
    for (d, s) in inv.iter_mut().zip(public_key.iter()) {
        *d = !s;
    }
    let mut temp = [0u8; KEY_LEN];
    let mut temp_len = 0usize;
    let mut bits: u8 = 0;
    let mut nbits = 0;
    let mut seen_zero = false;
    let mut ones: u8 = 0;
    for idx in 0..KEY_BITS {
        let bit = (inv[idx / 8] >> (7 - (idx % 8))) & 1;
        if !seen_zero && bit == 1 {
            ones = ones.saturating_add(1);
            continue;
        }
        if !seen_zero {
            seen_zero = true;
            continue;
        }
        bits = (bits << 1) | bit;
        nbits += 1;
        if nbits == 8 {
            nbits = 0;
            if temp_len < temp.len() {
                temp[temp_len] = bits;
                temp_len += 1;
            }
            bits = 0;
        }
    }
    let mut addr = [0u8; ADDR_LEN];
    addr[0] = NODE_PREFIX;
    addr[PREFIX_LEN] = ones;
    let n = temp_len.min(ADDR_PAYLOAD_LEN);
    addr[PREFIX_LEN + 1..PREFIX_LEN + 1 + n].copy_from_slice(&temp[..n]);
    Address(addr)
}

/// The node's routed subnet: its address with the subnet bit set.
pub fn subnet_for_key(public_key: &[u8; KEY_LEN]) -> Subnet {
    let addr = addr_for_key(public_key);
    let mut snet = [0u8; SUBNET_LEN];
    snet.copy_from_slice(&addr.0[..SUBNET_LEN]);
    snet[0] |= SUBNET_BIT;
    Subnet(snet)
}

/// Lossy reverse lookup: only the bits visible in the address are recovered,
/// unknown trailing key bits come back as `1` (zero pre-inversion).
///
/// "Lossy" is the protocol's own word, not a hedge: an address genuinely does
/// not contain the whole key, so this cannot be inverted exactly, and callers
/// that need a partial key must know that.
pub fn key_for_addr(addr: &Address) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let ones = (addr.0[PREFIX_LEN] as usize).min(KEY_BITS);
    for idx in 0..ones {
        key[idx / 8] |= 0x80 >> (idx % 8);
    }
    let key_offset = ones + 1;
    for idx in PAYLOAD_BIT_OFFSET..8 * ADDR_LEN {
        let bit = (addr.0[idx / 8] >> (7 - (idx % 8))) & 1;
        let key_idx = key_offset + (idx - PAYLOAD_BIT_OFFSET);
        if key_idx / 8 >= KEY_LEN {
            break;
        }
        key[key_idx / 8] |= bit << (7 - (key_idx % 8));
    }
    for b in key.iter_mut() {
        *b = !*b;
    }
    key
}

/// The lossy key for a subnet, same caveat as [`key_for_addr`].
pub fn key_for_subnet(snet: &Subnet) -> [u8; KEY_LEN] {
    let mut addr = [0u8; ADDR_LEN];
    addr[..SUBNET_LEN].copy_from_slice(&snet.0);
    key_for_addr(&Address(addr))
}

/// Partial key for DHT lookup of either a node address (`02…/128`) or a
/// routed subnet address (`03…/64`), mirroring Go's
/// `sendToAddress`/`sendToSubnet` split (`ipv6rwc.writePC`).
pub fn lookup_key_for_addr(addr: &Address) -> [u8; KEY_LEN] {
    if addr.is_subnet() {
        let mut raw = [0u8; SUBNET_LEN];
        raw.copy_from_slice(&addr.0[..SUBNET_LEN]);
        key_for_subnet(&Subnet(raw))
    } else {
        key_for_addr(addr)
    }
}

impl Address {
    /// Is this a **node** address, `02…`?
    ///
    /// The mirror of `Subnet::is_valid`, and Go has the same pair
    /// (`address.Address.IsValid`, `address.Subnet.IsValid`), because the two
    /// types are distinguished by exactly that bit and Go's
    /// `ipv6rwc.writePC` asks both in turn to decide node-address-or-subnet.
    pub fn is_valid(&self) -> bool {
        self.0[0] == NODE_PREFIX
    }

    /// Is this a **subnet** address, `03…`?
    ///
    /// The other half of `is_valid`, and the one with several production
    /// callers: `lookup_key_for_addr` picks the lossy key differently for each,
    /// and the address-to-key lookups have to match a subnet against a node's
    /// `/64` rather than its whole address. All of them were writing the byte
    /// test out by hand, which is that many places to forget the `SUBNET_BIT`.
    ///
    /// Note this is *not* `!is_valid()`: an address whose first byte is neither
    /// `02` nor `03` — a documentation prefix, say — is neither a node address
    /// nor a subnet, and only this says so correctly.
    pub fn is_subnet(&self) -> bool {
        self.0[0] == NODE_PREFIX | SUBNET_BIT
    }

    /// Render Go's text form into `out`.
    ///
    /// A free function rather than only a `Display` impl so a `no_std` caller
    /// with a `[u8; N]` has a way in: `Display` needs a `fmt::Formatter`, which
    /// only `std`'s `format!` and `write!` construct. `core::fmt::Write` is the
    /// trait that *can* be implemented by anything, so this is the one entry
    /// point a core caller has.
    pub fn write_to<W: core::fmt::Write>(&self, out: &mut W) -> core::fmt::Result {
        // Go prints an address through `net.IP.String()`: lowercase groups with
        // no leading zeros, and the longest run of zero groups collapsed to `::`
        // (leftmost wins a tie). `Ipv6Addr`'s `Display` is the same rule, and a
        // yggdrasil address never hits its IPv4-in-IPv6 special case because the
        // first byte is `NODE_PREFIX`.
        write!(out, "{}", Ipv6Addr::from(self.0))
    }
}

impl Subnet {
    /// Is this a routed subnet, `03…`?
    pub fn is_valid(&self) -> bool {
        self.0[0] == NODE_PREFIX | SUBNET_BIT
    }

    /// Render Go's text form, prefix and all, into `out`.
    ///
    /// Go's `-subnet` prints a `net.IPNet`: the prefix in the same compressed
    /// form as an address, then the mask length. The `/64` is not a constant
    /// formatted from [`SUBNET_LEN`] because Go prints the mask length as a
    /// decimal and a reader comparing our output against `yggdrasilctl`'s
    /// compares the *string*.
    pub fn write_to<W: core::fmt::Write>(&self, out: &mut W) -> core::fmt::Result {
        let mut octets = [0u8; ADDR_LEN];
        octets[..SUBNET_LEN].copy_from_slice(&self.0);
        write!(out, "{}/64", Ipv6Addr::from(octets))
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.write_to(f)
    }
}

impl core::fmt::Display for Subnet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.write_to(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render into a fixed buffer with no allocator anywhere in sight.
    ///
    /// This is the test that justifies `write_to` existing: it renders the same
    /// text `Display` would, through the only interface a `no_std` caller has,
    /// and it does so without a `String`. If `write_to` and `Display` ever
    /// diverged — the classic way, one gains a prefix — this is what notices.
    struct Fixed {
        buf: [u8; 64],
        len: usize,
    }

    impl Fixed {
        fn new() -> Self {
            Fixed {
                buf: [0u8; 64],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for Fixed {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            assert!(
                self.len + s.len() <= self.buf.len(),
                "the buffer is too small"
            );
            self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
            self.len += s.len();
            Ok(())
        }
    }

    /// Go's own test vector, transcribed from `address_test.go`: one public key
    /// and the address and subnet it derives. These are the oracle for the
    /// *bytes*; the text form is checked against Go's printed strings below.
    const PUB: [u8; KEY_LEN] = [
        189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 82, 86, 251, 141, 171, 8,
        170, 152, 227, 5, 82, 138, 184, 79, 65, 158, 110, 251,
    ];
    /// The address Go derives from [`PUB`].
    const ADDR: [u8; ADDR_LEN] = [
        2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149,
    ];
    /// The subnet Go derives from [`PUB`]: the address's low bit set.
    const SNET: [u8; SUBNET_LEN] = [3, 0, 132, 138, 96, 79, 187, 126];
    /// What `yggdrasilctl -json getSelf` printed for that node, from the
    /// installed Go 0.5.14. **Captured output, not our own `Display`** — a
    /// round trip through our formatter could not tell a correct compression
    /// rule from a self-consistent wrong one, which is the entire failure mode
    /// this module has.
    const ADDR_TEXT: &str = "200:848a:604f:bb7e:4384:65db:8db6:6895";
    const SNET_TEXT: &str = "300:848a:604f:bb7e::/64";

    #[test]
    fn addr_vector_matches_go() {
        assert_eq!(addr_for_key(&PUB).0, ADDR);
    }

    #[test]
    fn subnet_vector_matches_go() {
        assert_eq!(subnet_for_key(&PUB).0, SNET);
    }

    /// `Display` needs no test of its own here: it is a three-line delegation
    /// to `write_to` (below), and a test that drove it would have to go through
    /// `to_string` or `format!`, neither of which exists without an allocator.
    /// That absence is the reason `write_to` is the primary entry point rather
    /// than an afterthought.
    /// The text form, rendered through `core::fmt::Write` into a fixed buffer —
    /// no `String`, no `format!`, nothing that needs an allocator.
    ///
    /// This is the assertion that justifies keeping address text in the core. If
    /// `core::net::Ipv6Addr`'s `Display` ever stopped matching Go's
    /// `net.IP.String()`, this fails, and it fails *here* where a `no_std` caller
    /// can see it, rather than in the wrapper where an operator would.
    #[test]
    fn text_matches_what_go_prints_through_display_too() {
        let mut f = Fixed::new();
        addr_for_key(&PUB).write_to(&mut f).unwrap();
        assert_eq!(f.as_str(), ADDR_TEXT);
        let mut g = Fixed::new();
        subnet_for_key(&PUB).write_to(&mut g).unwrap();
        assert_eq!(g.as_str(), SNET_TEXT);
    }

    /// The two predicates are **complementary only on real mesh addresses**,
    /// which is the trap worth pinning: `!is_valid()` is not `is_subnet()`,
    /// because an address whose first byte is neither `02` nor `03` is neither.
    /// `key_for_addr` and `lookup_key_for_addr` both branch on that difference,
    /// and `is_subnet` is the other half of Go's `writePC` node-or-subnet
    /// question (`ipv6rwc.go:306-311`).
    #[test]
    fn validity() {
        assert!(addr_for_key(&PUB).is_valid());
        assert!(subnet_for_key(&PUB).is_valid());
        assert!(!Address([NODE_PREFIX | SUBNET_BIT; ADDR_LEN]).is_valid());
        assert!(!Subnet([NODE_PREFIX; SUBNET_LEN]).is_valid());

        let node = addr_for_key(&PUB);
        let mut padded = [0u8; ADDR_LEN];
        padded[..SUBNET_LEN].copy_from_slice(&SNET);
        let subnet = Address(padded);
        assert!(subnet.is_subnet());
        assert!(!subnet.is_valid(), "a subnet address is not a node address");
        assert!(!node.is_subnet(), "and a node address is not a subnet");

        // Neither: a documentation prefix, which is the case the two predicates
        // would get wrong if either were written as the other's negation.
        // Parsed with `core::net::Ipv6Addr::from_str` rather than `std`'s parse,
        // which is available under `no_std` — the text-parsing half of this
        // module is the part that genuinely can be here.
        use core::str::FromStr;
        for neither in ["2001:db8::1", "fe80::1", "ff02::1", "::1"] {
            let a = Address(Ipv6Addr::from_str(neither).unwrap().octets());
            assert!(!a.is_valid() && !a.is_subnet(), "{neither} is neither");
        }
    }

    /// Go's own `getkey` vectors, transcribed from `address_test.go`.
    ///
    /// The trailing `1`s are the *lossiness*, stated as data: the address does
    /// not carry those key bits, so the reverse lookup cannot recover them and
    /// returns `1` (the pre-inversion value). A test that asserted a full
    /// round trip would pass with a wrong implementation that happened to be
    /// self-inverse.
    #[test]
    fn getkey_lossy_vectors_match_go() {
        assert_eq!(
            key_for_addr(&Address(ADDR)),
            [
                189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 127, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ]
        );
        assert_eq!(
            key_for_subnet(&Subnet(SNET)),
            [
                189, 186, 207, 216, 34, 64, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ],
            "a subnet carries 8 bytes of address, two of which are prefix and\n             ones-count, so only six key bytes survive — and the rest come back\n             as 1s, which is the lossiness Go documents"
        );
    }

    /// The lossy key round-trips to the **same address**.
    ///
    /// `key_for_addr` is not invertible — Go's `getkey` throws bits away — but
    /// the bits it throws away are the ones the address does not encode, so
    /// re-deriving must land on the same 16 bytes. This is a real invariant
    /// rather than a tautology: a bug in where `key_offset` starts would produce
    /// a key that is still *a* key but derives a different address, which would
    /// break every DHT lookup into that node.
    #[test]
    fn the_lossy_key_round_trips_to_the_same_address() {
        assert_eq!(addr_for_key(&key_for_addr(&Address(ADDR))), Address(ADDR));
        // The subnet form round-trips to the **node** address, not to the subnet,
        // and that asymmetry is the interesting part.
        //
        // `SUBNET_BIT` lives in byte 0, which is *before* `PAYLOAD_BIT_OFFSET`
        // — the point at which address payload starts feeding key bits back. So
        // the bit is never encoded in the key, cannot be recovered from one, and
        // `addr_for_key` unconditionally writes `NODE_PREFIX`. A subnet is a
        // *routing* statement about a node, not a different node.
        //
        // Only the first `SUBNET_LEN` bytes match, for the ordinary reason: a
        // subnet carries 8 of the address's 16 bytes, so the other 8 are the
        // lossiness again, arriving as zeroes in the derived address because the
        // key bits behind them came back as `1`s and therefore invert to `0`.
        let from_subnet = addr_for_key(&key_for_subnet(&Subnet(SNET)));
        assert_eq!(&from_subnet.0[..SUBNET_LEN], &ADDR[..SUBNET_LEN]);
        assert!(
            from_subnet.0[SUBNET_LEN..].iter().all(|b| *b == 0),
            "and the bytes a subnet does not carry come back zero"
        );
    }

    /// `lookup_key_for_addr` must pick the **different** lossy key for a subnet,
    /// because the two address kinds are looked up differently in the DHT. If
    /// this collapsed, a routed subnet would be queried as if it were a node,
    /// which fails silently as "no route to that host".
    #[test]
    fn a_subnet_is_looked_up_by_its_own_key() {
        let node = Address(ADDR);
        let mut padded = [0u8; ADDR_LEN];
        padded[..SUBNET_LEN].copy_from_slice(&SNET);
        let snet = Address(padded);
        assert_ne!(
            lookup_key_for_addr(&node),
            lookup_key_for_addr(&snet),
            "a node address and its subnet must not share a DHT key"
        );
        assert_eq!(lookup_key_for_addr(&node), key_for_addr(&node));
        assert_eq!(lookup_key_for_addr(&snet), key_for_subnet(&Subnet(SNET)));
    }
}
