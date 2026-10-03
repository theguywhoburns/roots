//! IPv6 address / subnet derivation from ed25519 node keys.
//! Port of Go `src/address/address.go`. No hashing: the address embeds the
//! bitwise inverse of the public key (minus leading 1s + first 0), prefixed
//! with [`NODE_PREFIX`] (`ones` count in byte 1). Subnets set the low bit.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; ADDR_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Subnet(pub [u8; SUBNET_LEN]);

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

pub fn subnet_for_key(public_key: &[u8; KEY_LEN]) -> Subnet {
    let addr = addr_for_key(public_key);
    let mut snet = [0u8; SUBNET_LEN];
    snet.copy_from_slice(&addr.0[..SUBNET_LEN]);
    snet[0] |= SUBNET_BIT;
    Subnet(snet)
}

/// Lossy reverse lookup: only the bits visible in the address are recovered,
/// unknown trailing key bits come back as `1` (zero pre-inversion).
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
    /// The other half of `is_valid`, and the one with three production callers:
    /// `lookup_key_for_addr` picks the lossy key differently for each, and the
    /// two address-to-key lookups in `driver.rs` have to match a subnet against a
    /// node's `/64` rather than its whole address. All four were writing the byte
    /// test out by hand, which is four places to forget the `SUBNET_BIT`.
    ///
    /// Note this is *not* `!is_valid()`: an address whose first byte is neither
    /// `02` nor `03` — a documentation prefix, say — is neither a node address
    /// nor a subnet, and only this says so correctly.
    pub fn is_subnet(&self) -> bool {
        self.0[0] == NODE_PREFIX | SUBNET_BIT
    }
}

impl Subnet {
    pub fn is_valid(&self) -> bool {
        self.0[0] == NODE_PREFIX | SUBNET_BIT
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Go prints an address through `net.IP.String()`: lowercase groups with
        // no leading zeros, and the longest run of zero groups collapsed to `::`
        // (leftmost wins a tie). `Ipv6Addr`'s `Display` is the same rule, and an
        // yggdrasil address never hits its IPv4-in-IPv6 special case because the
        // first byte is `NODE_PREFIX`.
        write!(f, "{}", std::net::Ipv6Addr::from(self.0))
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Go's `-subnet` prints a `net.IPNet`: the prefix in the same
        // compressed form as an address, then the mask length.
        let mut octets = [0u8; ADDR_LEN];
        octets[..SUBNET_LEN].copy_from_slice(&self.0);
        write!(f, "{}/64", std::net::Ipv6Addr::from(octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: [u8; KEY_LEN] = [
        189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 82, 86, 251, 141, 171, 8,
        170, 152, 227, 5, 82, 138, 184, 79, 65, 158, 110, 251,
    ];

    #[test]
    fn addr_vector_matches_go() {
        let expect = [
            2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149,
        ];
        assert_eq!(addr_for_key(&PUB).0, expect);
    }

    #[test]
    fn subnet_vector_matches_go() {
        assert_eq!(subnet_for_key(&PUB).0, [3, 0, 132, 138, 96, 79, 187, 126]);
    }

    /// The two predicates are **complementary only on real mesh addresses**,
    /// which is the trap worth pinning: `!Address::is_valid()` is not
    /// `Address::is_subnet()`, because an address whose first byte is neither
    /// `02` nor `03` is neither. `key_for_addr` and `lookup_key_for_addr` both
    /// branch on that difference, and `is_subnet` is the other half of Go's
    /// `writePC` node-or-subnet question (`ipv6rwc.go:306-311`).
    #[test]
    fn validity() {
        assert!(addr_for_key(&PUB).is_valid());
        assert!(subnet_for_key(&PUB).is_valid());
        assert!(!Address([NODE_PREFIX | SUBNET_BIT; ADDR_LEN]).is_valid());
        assert!(!Subnet([NODE_PREFIX; SUBNET_LEN]).is_valid());

        let node = addr_for_key(&PUB);
        let mut padded = [0u8; ADDR_LEN];
        padded[..SUBNET_LEN].copy_from_slice(&subnet_for_key(&PUB).0);
        let subnet = Address(padded);
        assert!(subnet.is_subnet());
        assert!(!subnet.is_valid(), "a subnet address is not a node address");
        assert!(!node.is_subnet(), "and a node address is not a subnet");
        // Neither: a documentation prefix, which is the case the two predicates
        // would get wrong if either were written as the other's negation.
        for neither in ["2001:db8::1", "fe80::1", "ff02::1", "::1"] {
            let a = Address(neither.parse::<std::net::Ipv6Addr>().unwrap().octets());
            assert!(!a.is_valid() && !a.is_subnet(), "{neither} is neither");
        }
    }

    #[test]
    fn getkey_lossy_vectors_match_go() {
        let addr = Address([
            2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149,
        ]);
        let expect: [u8; KEY_LEN] = [
            189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 127, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];
        assert_eq!(key_for_addr(&addr), expect);
        let snet = Subnet([3, 0, 132, 138, 96, 79, 187, 126]);
        let expect_s: [u8; KEY_LEN] = [
            189, 186, 207, 216, 34, 64, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];
        assert_eq!(key_for_subnet(&snet), expect_s);
    }
}
