//! Multicast peer discovery: the beacon codec and the announce state machine.
//! Port of Go `src/multicast/advertisement.go` and `src/multicast/multicast.go`.
//!
//! The library owns no socket. It takes the interface list the client scanned,
//! the listener ports the client bound, and the datagrams the client read, and
//! it answers with [`Command`]s: bind a listener, send a beacon, dial a peer,
//! stop a listener. The UDP socket, `SO_REUSEADDR`, `JoinGroup`, the interface
//! scan and the regex match are the client's job (`multicast_unix.go` is the
//! syscall half Go keeps on this side of the line).

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2b512, Blake2bMac512, Digest};

use crate::address::KEY_LEN;
use crate::error::Error;

/// Group the beacons go to. Go hardcodes it in `New` and never reads it from
/// config, so it is a constant here too (`multicast.go:71`).
pub const GROUP: &str = "[ff02::114]:9001";

/// Major version a beacon must carry (`core/version.go:27`).
pub const PROTO_MAJOR: u16 = 0;
/// Minor version a beacon must carry (`core/version.go:28`). The gate is exact
/// on this field, so a 0.6 node drops a 0.5 beacon and the other way round
/// (`multicast.go:416-417`).
pub const PROTO_MINOR: u16 = 5;

/// Longest gap between two beacons on one interface (`multicast.go:366-368`).
pub const MAX_INTERVAL: Duration = Duration::from_secs(15);

/// Fixed part of a beacon: two u16 version fields, the 32B key, the u16 port
/// and the u16 hash length (`advertisement.go:29`, `headerLen`).
pub const HEADER_LEN: usize = KEY_LEN + 8;
/// Length of the membership hash (Go's `blake2b.Size`).
pub const HASH_LEN: usize = 64;

/// A beacon. All fields are big endian on the wire, in this order:
/// `u16 major | u16 minor | 32B key | u16 port | u16 hash length | hash`
/// (`advertisement.go:9-26`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub major: u16,
    pub minor: u16,
    pub pubkey: [u8; KEY_LEN],
    /// Port the advertiser's listener is bound to, so it is the real port and
    /// not the one it asked for (`multicast.go:355`).
    pub port: u16,
    pub hash: Vec<u8>,
}

impl Advertisement {
    /// Go's `MarshalBinary`, which cannot fail. The length field is Go's
    /// `uint16(len(m.Hash))`, so a hash over 65535 bytes truncates rather than
    /// being refused (`advertisement.go:23`). Keep the truncation: the length
    /// is what the peer compares, not a guard.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.hash.len());
        out.extend_from_slice(&self.major.to_be_bytes());
        out.extend_from_slice(&self.minor.to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hash);
        out
    }

    /// Go's `UnmarshalBinary` (`advertisement.go:28-43`), quirks kept:
    ///
    /// * a buffer shorter than [`HEADER_LEN`], and a hash that reaches past the
    ///   end of the buffer, are [`Error::InvalidLength`]. Go's text for both is
    ///   "invalid multicast beacon"; the crate has one length error and it
    ///   reads "invalid handshake length", which no multicast caller ever sees.
    /// * bytes after the hash are ignored, not an error.
    /// * a hash shorter than 64 bytes decodes fine and only fails the
    ///   comparison in [`Multicast::receive`].
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() < HEADER_LEN {
            return Err(Error::InvalidLength);
        }
        let mut pubkey = [0u8; KEY_LEN];
        pubkey.copy_from_slice(&b[4..4 + KEY_LEN]);
        let hash_len = u16::from_be_bytes([b[6 + KEY_LEN], b[7 + KEY_LEN]]) as usize;
        if b.len() < HEADER_LEN + hash_len {
            return Err(Error::InvalidLength);
        }
        Ok(Self {
            major: u16::from_be_bytes([b[0], b[1]]),
            minor: u16::from_be_bytes([b[2], b[3]]),
            pubkey,
            port: u16::from_be_bytes([b[4 + KEY_LEN], b[5 + KEY_LEN]]),
            hash: b[HEADER_LEN..HEADER_LEN + hash_len].to_vec(),
        })
    }
}

/// The beacon's membership hash: `blake2b-512(key = this interface's password,
/// data = the advertised public key)`.
///
/// The advertiser computes it over its own key once per interface scan
/// (`multicast.go:213-223`). The receiver recomputes it over the *advertised*
/// key with its own password for that interface and compares byte for byte
/// (`multicast.go:429-441`), so one function covers both halves.
///
/// The construction is the one in `handshake.rs`: an empty password is an
/// unkeyed hash, which is what Go's `blake2b.New512(nil)` computes.
pub fn membership_hash(password: &[u8], pubkey: &[u8; KEY_LEN]) -> [u8; HASH_LEN] {
    if password.is_empty() {
        let mut h = Blake2b512::new();
        h.update(pubkey);
        return h.finalize().into();
    }
    match <Blake2bMac512 as KeyInit>::new_from_slice(password) {
        Ok(mut h) => {
            h.update(pubkey);
            h.finalize().into_bytes().into()
        }
        // Over BLAKE2b's 64-byte key limit there is no keyed hash to compute:
        // Go's `blake2b.New512` returns `KeySizeError` and the interface is
        // skipped (`multicast.go:214-217`, and again at `:432-434` on the
        // receive side). `Multicast::set_interfaces` skips such an interface,
        // so a direct call is the only way here. Hash unkeyed, the same value
        // an empty password gives: no Go node can match it, which is the point.
        Err(_) => membership_hash(&[], pubkey),
    }
}

/// One interface the client matched against the config. Go's `interfaceInfo`
/// (`multicast.go:42-51`) without the OS handles, because the client did the
/// scan and the library never learns an interface name it was not given.
///
/// The client must not list a name twice: the second entry wins and the
/// listener state of the first is dropped without an [`Command::Unbind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    /// The link-local address to bind and beacon on. Go walks every link-local
    /// address on the adapter and beacons from the first one that works
    /// (`multicast.go:306-371`); here the client picks the one.
    pub link_local: Ipv6Addr,
    /// Send beacons and accept inbound connections.
    pub beacon: bool,
    /// Join the group and dial peers that beacon.
    pub listen: bool,
    /// Port asked for in the [`Command::Bind`] URI. Zero means any port, and is
    /// what Go's generated config uses (`config/defaults_linux.go:17`): the
    /// beacon then carries the port the client actually bound.
    pub port: u16,
    pub priority: u8,
    /// Group password, at most 64 bytes. Empty means no password.
    pub password: Vec<u8>,
}

/// One thing the client must do, in the order a beacon needs: bind the
/// listener first, then beacon, because the beacon carries the bound port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Start a `tls://` listener on `link_local`, scoped to `iface`, and report
    /// the port it got with [`Multicast::listener_up`].
    Bind {
        iface: String,
        link_local: Ipv6Addr,
        port: u16,
        uri: String,
    },
    /// Send `bytes` to [`GROUP`] with the zone set to `iface`.
    Beacon { iface: String, bytes: Vec<u8> },
    /// Dial a peer once. Go uses `CallPeer`, which does not add a persistent
    /// peer (`core/api.go:221-223`).
    Dial {
        uri: String,
        sintf: String,
        peer: [u8; KEY_LEN],
    },
    /// Stop the listener for `iface`.
    Unbind { iface: String },
}

/// Per-interface state. Go spreads this over two maps: `_interfaces` holds the
/// scan result and `_listeners` holds one entry per bound listener, keyed by
/// interface name. A scan never resets the second one
/// (`multicast.go:262-341`), so a single entry holds both, and `cfg` being
/// `None` means the name is absent from the newest scan.
struct IfaceState {
    cfg: Option<InterfaceConfig>,
    hash: [u8; HASH_LEN],
    /// Port the client bound, from [`Multicast::listener_up`].
    listener_port: Option<u16>,
    /// Address we asked the client to bind, or are bound to. Go compares the
    /// listener's own address against the adapter's addresses
    /// (`multicast.go:278-300`).
    bind_addr: Option<Ipv6Addr>,
    /// Go's `listenerInfo.time`: when the last beacon went out.
    last_beacon: Option<Instant>,
    /// Go's `listenerInfo.interval`, zero until the first beacon.
    interval: Duration,
    /// The client has joined the group on this interface.
    joined: bool,
}

impl IfaceState {
    /// True when the listener this interface holds, or has asked for, is no
    /// longer wanted.
    fn listener_stale(&self) -> bool {
        // Nothing asked for, so there is nothing to stop.
        let Some(addr) = self.bind_addr else {
            return false;
        };
        match &self.cfg {
            // The interface left the newest scan (`multicast.go:271-274`).
            None => true,
            // The link-local address moved, so Go stops the listener and lets
            // the pass below start a new one (`multicast.go:295-300`).
            Some(cfg) => cfg.link_local != addr,
        }
    }
}

/// The announce state machine. One instance per node, driven from the client's
/// tick: [`Multicast::set_interfaces`], then [`Multicast::announce`], plus
/// [`Multicast::listener_up`] when a bind lands and [`Multicast::receive`] for
/// every datagram off the group.
pub struct Multicast {
    local_pubkey: [u8; KEY_LEN],
    /// Keyed by interface name, so an interface's listener and ramp state
    /// survive a scan that still reports it. Ordered so a tick emits its
    /// commands in a fixed order; Go ranges a map and does not.
    ifaces: BTreeMap<String, IfaceState>,
}

impl Multicast {
    pub fn new(local_pubkey: [u8; KEY_LEN]) -> Self {
        Self {
            local_pubkey,
            ifaces: BTreeMap::new(),
        }
    }

    /// Replace the interface set with a fresh scan. Go rebuilds
    /// `_interfaces` on every tick (`multicast.go:148-169`) and keys
    /// `_listeners` by interface name, so listener and ramp state survive a
    /// refresh of an interface that is still there.
    ///
    /// An interface that left the set keeps its entry with no config, so the
    /// next [`Multicast::announce`] can stop its listener. An entry with
    /// nothing bound is dropped here.
    pub fn set_interfaces(&mut self, ifaces: Vec<InterfaceConfig>) {
        let mut next = BTreeMap::new();
        for cfg in ifaces {
            // Go skips a config entry with neither flag set, so the interface
            // never enters the map at all (`multicast.go:208-210`).
            if !cfg.beacon && !cfg.listen {
                continue;
            }
            // A password over BLAKE2b's key limit has no hash, so Go skips the
            // interface (`multicast.go:214-217`).
            if cfg.password.len() > crate::handshake::MAX_PASSWORD_LEN {
                continue;
            }
            let name = cfg.name.clone();
            let hash = membership_hash(&cfg.password, &self.local_pubkey);
            let mut st = self.ifaces.remove(&name).unwrap_or(IfaceState {
                cfg: None,
                hash,
                listener_port: None,
                bind_addr: None,
                last_beacon: None,
                interval: Duration::ZERO,
                joined: false,
            });
            st.cfg = Some(cfg);
            st.hash = hash;
            next.insert(name, st);
        }
        for (name, mut st) in std::mem::take(&mut self.ifaces) {
            st.cfg = None;
            // Nothing bound and nothing asked for, so no listener to stop.
            if st.bind_addr.is_none() {
                continue;
            }
            next.insert(name, st);
        }
        self.ifaces = next;
    }

    /// One announce tick: Go's `_announce` (`multicast.go:247-377`) with the
    /// syscalls turned into commands. Go's own tick is one second plus up to
    /// one second of jitter (`multicast.go:373`).
    pub fn announce(&mut self, now: Instant) -> Vec<Command> {
        let mut out = Vec::new();
        let names: Vec<String> = self.ifaces.keys().cloned().collect();

        // Go's first pass: stop listeners whose interface went away or whose
        // address moved. A re-bind happens in the pass below, in the same tick
        // and after the Unbind, which is Go's order (`multicast.go:262-301`).
        for name in &names {
            if !self
                .ifaces
                .get(name)
                .is_some_and(IfaceState::listener_stale)
            {
                continue;
            }
            out.push(Command::Unbind {
                iface: name.clone(),
            });
            if let Some(st) = self.ifaces.get_mut(name) {
                // Go deletes the entry, so a new listener starts the ramp over.
                st.listener_port = None;
                st.bind_addr = None;
                st.last_beacon = None;
                st.interval = Duration::ZERO;
            }
        }

        for name in &names {
            let Some(st) = self.ifaces.get_mut(name) else {
                continue;
            };
            let Some(cfg) = st.cfg.clone() else {
                continue;
            };
            if cfg.listen {
                // Go calls `JoinGroup` here and drops the error
                // (`multicast.go:312-315`). The syscall is the client's, and
                // Go never leaves the group, so the flag only goes true.
                st.joined = true;
            }
            if !cfg.beacon {
                // Go's break: no beacon, and no inbound link either
                // (`multicast.go:316-318`).
                continue;
            }
            if st.bind_addr.is_none() {
                // No listener yet. Go calls `ListenLocal` and beacons in the
                // same tick, because it holds the listener and reads its port
                // back. This module cannot: the beacon advertises the bound
                // port (`multicast.go:355`), so the first beacon waits for
                // `listener_up`.
                st.bind_addr = Some(cfg.link_local);
                out.push(Command::Bind {
                    iface: name.clone(),
                    link_local: cfg.link_local,
                    port: cfg.port,
                    uri: listen_uri(&cfg),
                });
                continue;
            }
            let Some(port) = st.listener_port else {
                continue;
            };
            if st
                .last_beacon
                .is_some_and(|last| now.duration_since(last) < st.interval)
            {
                continue;
            }
            let adv = Advertisement {
                major: PROTO_MAJOR,
                minor: PROTO_MINOR,
                pubkey: self.local_pubkey,
                port,
                hash: st.hash.to_vec(),
            };
            out.push(Command::Beacon {
                iface: name.clone(),
                bytes: adv.encode(),
            });
            st.last_beacon = Some(now);
            // Go tests `interval.Seconds() < 15` against a float
            // (`multicast.go:366-368`). The interval only ever holds whole
            // seconds, so the two forms agree.
            if st.interval < MAX_INTERVAL {
                st.interval += Duration::from_secs(1);
            }
        }
        out
    }

    /// The client bound `iface` and got `bound_port`. That port is what the
    /// beacon advertises, so no beacon goes out before this call. The ramp is
    /// not reset here: a re-bind after [`Command::Unbind`] already reset it.
    pub fn listener_up(&mut self, iface: &str, bound_port: u16) {
        if let Some(st) = self.ifaces.get_mut(iface) {
            st.listener_port = Some(bound_port);
        }
    }

    /// The gap the next beacon on `iface` is gated on, or `None` for an
    /// interface the client has not given us. Zero means the next announce
    /// beacons.
    pub fn tick_interval(&self, iface: &str) -> Option<Duration> {
        self.ifaces.get(iface).map(|st| st.interval)
    }

    /// True once an announce has told the client to join the group on `iface`.
    pub fn is_joined(&self, iface: &str) -> bool {
        self.ifaces.get(iface).is_some_and(|st| st.joined)
    }

    /// One datagram off the group: Go's `listen` loop body
    /// (`multicast.go:379-455`). `zone` is the interface the packet arrived on
    /// and `from` its source, so `from.port()` is the source port, which Go
    /// throws away. Returns the dial to make, or nothing.
    ///
    /// Go reads the clock nowhere on this path, so `now` is here only to keep
    /// the call site the same shape as [`Multicast::announce`].
    pub fn receive(
        &mut self,
        zone: &str,
        from: SocketAddrV6,
        buf: &[u8],
        _now: Instant,
    ) -> Option<Command> {
        let Ok(adv) = Advertisement::decode(buf) else {
            return None;
        };
        // Both version fields, exactly (`multicast.go:413-417`).
        if adv.major != PROTO_MAJOR || adv.minor != PROTO_MINOR {
            return None;
        }
        if adv.pubkey == self.local_pubkey {
            return None;
        }
        let cfg = self.ifaces.get(zone)?.cfg.as_ref()?;
        if !cfg.listen {
            return None;
        }
        // Our own password for this interface over the advertised key, then a
        // byte compare. A hash that is too short fails here, not in the decoder.
        if membership_hash(&cfg.password, &adv.pubkey).as_slice() != adv.hash.as_slice() {
            return None;
        }
        // Go does not deduplicate: it calls `CallPeer` for every beacon that
        // gets this far and the link manager refuses the ones it already holds
        // (`core/link.go:236-243`). The client owns that refusal.
        Some(Command::Dial {
            uri: dial_uri(cfg, &adv, *from.ip(), zone),
            sintf: zone.to_string(),
            peer: adv.pubkey,
        })
    }
}

/// The [`Command::Bind`] URI: `tls://[link-local]:port?password=..&priority=..`
/// (`multicast.go:322-330`). No zone, because Go hands the interface to
/// `ListenLocal` as a separate argument. `password` comes before `priority`
/// because Go encodes through `url.Values.Encode`, which sorts keys, and Go
/// adds `priority` first.
fn listen_uri(cfg: &InterfaceConfig) -> String {
    format!(
        "tls://[{}]:{}?password={}&priority={}",
        cfg.link_local,
        cfg.port,
        query_escape(&cfg.password),
        cfg.priority,
    )
}

/// The [`Command::Dial`] URI: `tls://[source%zone]:advertised-port?key=..&password=..&priority=..`
/// (`multicast.go:425`, `:443-451`). The port is the one the beacon
/// advertised, because Go overwrites the source port with it before printing
/// the address. The query is in `url.Values.Encode` order: `key`, `password`,
/// `priority`.
fn dial_uri(cfg: &InterfaceConfig, adv: &Advertisement, from: Ipv6Addr, zone: &str) -> String {
    format!(
        "tls://[{}%{}]:{}?key={}&password={}&priority={}",
        from,
        zone,
        adv.port,
        // `hex.EncodeToString` is lower case, and hex digits never need
        // escaping.
        hex::encode(adv.pubkey),
        query_escape(&cfg.password),
        cfg.priority,
    )
}

/// Go's `url.QueryEscape` (`net/url`), which `url.Values.Encode` applies to
/// every value: the unreserved set `A-Za-z0-9-_.~` passes, a space becomes
/// `+`, and everything else becomes `%XX` in upper-case hex.
///
/// Go percent-decodes on the way back in with `u.Query().Get`, while
/// `link::parse_link_uri` takes the value raw, so a password that needs
/// escaping does not survive a round trip through that parser. The escape
/// stays anyway: the URI is the wire form and Go is the reader to match.
fn query_escape(v: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(v.len());
    for &b in v {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer key of 0x00..=0x1f, the key the known-answer hashes are over.
    const PEER: [u8; KEY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    /// A second peer key, 0x20..=0x3f.
    const PEER2: [u8; KEY_LEN] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    /// Our own key, distinct from both peers.
    const OURS: [u8; KEY_LEN] = [0xc3; KEY_LEN];
    const PW: &[u8] = b"roots multicast test";

    /// `fe80::` plus one segment, so a moved link-local is easy to name.
    fn ll(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)
    }

    fn cfg(name: &str, beacon: bool, listen: bool) -> InterfaceConfig {
        InterfaceConfig {
            name: name.to_string(),
            link_local: ll(1),
            beacon,
            listen,
            port: 9001,
            priority: 3,
            password: PW.to_vec(),
        }
    }

    /// A beacon from a peer that holds our password, built the way Go builds
    /// one (`multicast.go:351-357`).
    fn peer_beacon(pubkey: &[u8; KEY_LEN], port: u16, major: u16, minor: u16) -> Vec<u8> {
        Advertisement {
            major,
            minor,
            pubkey: *pubkey,
            port,
            hash: membership_hash(PW, pubkey).to_vec(),
        }
        .encode()
    }

    /// The source of a received beacon: the peer's link-local address on some
    /// source port.
    fn src(port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(ll(2), port, 0, 0)
    }

    fn expect_hash(hex_digest: &str) -> Vec<u8> {
        hex::decode(hex_digest).unwrap()
    }

    #[test]
    fn advertisement_roundtrips_and_rejects() {
        // Go's round trip, over hash lengths from empty to over-long.
        for hash_len in [0usize, 1, 32, 64, 200] {
            let orig = Advertisement {
                major: 1,
                minor: 2,
                pubkey: PEER,
                port: 3,
                hash: vec![0xab; hash_len],
            };
            let bytes = orig.encode();
            assert_eq!(bytes.len(), HEADER_LEN + hash_len);
            assert_eq!(Advertisement::decode(&bytes).unwrap(), orig);
        }

        // Field order and offsets, line by line through MarshalBinary.
        let adv = Advertisement {
            major: 0,
            minor: 5,
            pubkey: PEER,
            port: 9001,
            hash: vec![0xab; 64],
        };
        let b = adv.encode();
        assert_eq!(b.len(), 104);
        assert_eq!(&b[0..2], &[0x00, 0x00]);
        assert_eq!(&b[2..4], &[0x00, 0x05]);
        assert_eq!(&b[4..36], &PEER);
        assert_eq!(&b[36..38], &[0x23, 0x29]);
        assert_eq!(&b[38..40], &[0x00, 0x40]);
        assert!(b[40..].iter().all(|&x| x == 0xab));

        // Go's first length check: `headerLen` is 40, so 39 bytes is short.
        assert!(Advertisement::decode(&[]).is_err());
        assert!(Advertisement::decode(&b[..HEADER_LEN - 1]).is_err());

        // Go's TestMulticastAdvertisementRejectsTruncatedHash: a 40-byte buffer
        // that claims a 32-byte hash.
        let mut claimed = b[..HEADER_LEN].to_vec();
        claimed[6 + KEY_LEN..8 + KEY_LEN].copy_from_slice(&32u16.to_be_bytes());
        assert!(Advertisement::decode(&claimed).is_err());
        // A 32-byte hash that is really there decodes; receive is where it dies.
        claimed.extend_from_slice(&[0x5a; 32]);
        let short = Advertisement::decode(&claimed).unwrap();
        assert_eq!(short.hash.len(), 32);
        assert_eq!(short.port, 9001);

        // Quirk: a zero-length hash is fine, and so is a buffer longer than the
        // hash needs.
        claimed[6 + KEY_LEN..8 + KEY_LEN].copy_from_slice(&0u16.to_be_bytes());
        assert!(Advertisement::decode(&claimed).unwrap().hash.is_empty());
        let mut trailing = adv.clone();
        trailing.hash = vec![0x11; 8];
        let mut padded = trailing.encode();
        padded.extend_from_slice(&[0xff; 5]);
        assert_eq!(Advertisement::decode(&padded).unwrap(), trailing);

        // Quirk: `uint16(len(m.Hash))` truncates rather than refusing.
        let huge = Advertisement {
            major: 0,
            minor: 5,
            pubkey: PEER,
            port: 1,
            hash: vec![0x41; 65536 + 4],
        }
        .encode();
        assert_eq!(&huge[38..40], &4u16.to_be_bytes());
        assert_eq!(Advertisement::decode(&huge).unwrap().hash, vec![0x41; 4]);
    }

    #[test]
    fn multicast_hash_over_peer_key() {
        // Known answer: blake2b-512 keyed with b"roots multicast test" over
        // 0x00..=0x1f. Checked outside this crate with CPython's
        // `hashlib.blake2b`, which agrees with the BLAKE2 reference vectors in
        // BLAKE2/BLAKE2 `testvectors/blake2-kat.json`.
        let expect = expect_hash(
            "7d97b7fe987237592d1812f8869f00c17eb3ffba434725c9deb153dd1c94cb30\
             d765b6be6eb7cf59bf98d19c0457fe975ceee11085b2090e017030aff5952826",
        );
        assert_eq!(membership_hash(PW, &PEER).as_slice(), expect.as_slice());

        // The message is the peer's key, so a different key gives a different
        // hash. Both of these are known answers too.
        assert_eq!(
            hex::encode(membership_hash(PW, &PEER2)),
            "637a2affa2906e36486d635dd3e514072c4d3f3ed4b4bda23495f23ac7f566c\
             08c94a8f3eb7f15628c46f49183c4fd25d7c01442803a4ae5fdf99d1f35b0858f"
        );
        // A different password gives a different hash.
        assert_eq!(
            hex::encode(membership_hash(b"other password", &PEER)),
            "c1c07b2ac50184711b14169d4bba7c7d2aac52e030a936b43ec2592e24ffb93d\
             1b51eebb9a98143215a2a3c07747fafe7728a0e1824e50d86606c905353bd489"
        );
        // An empty password is the unkeyed hash, like Go's blake2b.New512(nil).
        assert_eq!(
            hex::encode(membership_hash(b"", &PEER)),
            "5c52920a7263e39d57920ca0cb752ac6d79a04fef8a7a216a1ecb7115ce06d8\
             9fd7d735bd6f4272555dba22c2d1c96e6352322c62c5630fde0f4777a76c3de2c"
        );
        // Not our own key, not a re-hash of the password.
        assert_ne!(membership_hash(PW, &PEER), membership_hash(PW, &OURS));
        assert_ne!(membership_hash(PW, &PEER), *blake2::Blake2b512::digest(PW));

        // 64 bytes is the last password BLAKE2b takes as a key, and it hashes
        // like any other.
        assert_eq!(
            hex::encode(membership_hash(&[0x5a; 64], &PEER)),
            "ee37aa5ea6fca21e045c40a5098489658bd990e16c9528d8964a20d529852a54b\
             b6367672a0ac091fba3c4dbdd8ee4f293a6afe896047ea1d5f3c7ab3aaa0dad"
        );
        // 65 bytes has no keyed form. Go skips the interface outright
        // (`multicast.go:214-217`) and `set_interfaces` does the same, so the
        // unkeyed fallback here is only reachable from a direct call.
        assert_eq!(
            membership_hash(&[0x5a; 65], &PEER),
            membership_hash(b"", &PEER)
        );
        let mut m = Multicast::new(OURS);
        let over = InterfaceConfig {
            password: vec![0x5a; 65],
            ..cfg("eth0", true, true)
        };
        m.set_interfaces(vec![over]);
        assert!(!m.is_joined("eth0"));
        assert_eq!(m.tick_interval("eth0"), None);
        assert!(m.announce(Instant::now()).is_empty());
    }

    #[test]
    fn multicast_ignores_minor_version_mismatch() {
        let now = Instant::now();
        let mut m = Multicast::new(OURS);
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        let from = src(5000);

        // The gate is exact on both fields (`multicast.go:413-419`), so 0.4,
        // 0.6 and 0.65535 are all refused even though the hash is right.
        for (major, minor) in [(0, 0), (0, 4), (0, 6), (0, 0xffff), (1, 5), (1, 0)] {
            assert!(
                m.receive("eth0", from, &peer_beacon(&PEER, 4242, major, minor), now)
                    .is_none(),
                "{major}.{minor} should be refused"
            );
        }
        assert!(matches!(
            m.receive(
                "eth0",
                from,
                &peer_beacon(&PEER, 4242, PROTO_MAJOR, PROTO_MINOR),
                now
            ),
            Some(Command::Dial { .. })
        ));
        // Garbage is refused before any of that.
        assert!(m.receive("eth0", from, &[], now).is_none());
        assert!(m.receive("eth0", from, &[0u8; 8], now).is_none());
    }

    #[test]
    fn multicast_beacon_ramps_to_cap() {
        let t0 = Instant::now();
        let mut m = Multicast::new(OURS);
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        assert_eq!(m.announce(t0).len(), 1);
        m.listener_up("eth0", 9001);

        // The first beacon is due at once, then the gap grows by a second per
        // beacon up to 15s and stays there (`multicast.go:347`, `:366-369`).
        let mut gaps: Vec<Duration> = Vec::new();
        let mut now = t0;
        let mut last = t0;
        for _ in 0..20 {
            let cmds = m.announce(now);
            assert_eq!(cmds.len(), 1, "one command at {now:?}: {cmds:?}");
            assert!(matches!(cmds[0], Command::Beacon { .. }), "{cmds:?}");
            gaps.push(now.duration_since(last));
            last = now;
            now += m.tick_interval("eth0").unwrap();
        }
        let expect: Vec<Duration> = (0..=15)
            .map(Duration::from_secs)
            .chain(std::iter::repeat_n(Duration::from_secs(15), 4))
            .collect();
        assert_eq!(gaps, expect);
        assert_eq!(m.tick_interval("eth0"), Some(MAX_INTERVAL));

        // `beacon: false` joins the group and does nothing else: Go breaks out
        // of the address loop before it looks for a listener
        // (`multicast.go:316-318`).
        let mut m2 = Multicast::new(OURS);
        m2.set_interfaces(vec![cfg("eth1", false, true)]);
        assert!(m2.announce(t0 + Duration::from_secs(60)).is_empty());
        assert!(m2.is_joined("eth1"));
        assert_eq!(m2.tick_interval("eth1"), Some(Duration::ZERO));
        // A refresh does not un-join: Go calls JoinGroup again and never
        // leaves the group (`multicast.go:312-315`).
        m2.set_interfaces(vec![cfg("eth1", false, true)]);
        assert!(m2.is_joined("eth1"));

        // Both flags off means the interface never enters the set
        // (`multicast.go:208-210`).
        m2.set_interfaces(vec![cfg("eth2", false, false)]);
        assert!(!m2.is_joined("eth2"));
        assert_eq!(m2.tick_interval("eth2"), None);
        assert!(
            m2.receive("eth2", src(1), &peer_beacon(&PEER, 1, 0, 5), t0)
                .is_none()
        );
    }

    #[test]
    fn multicast_dial_uri_params() {
        let now = Instant::now();
        let mut m = Multicast::new(OURS);
        let mut c = cfg("eth0", true, true);
        c.port = 9001;
        c.priority = 3;
        m.set_interfaces(vec![c]);

        // The Bind URI, with password before priority because Go's
        // `url.Values.Encode` sorts the keys (`multicast.go:322-330`).
        assert_eq!(
            m.announce(now),
            vec![Command::Bind {
                iface: "eth0".to_string(),
                link_local: ll(1),
                port: 9001,
                uri: "tls://[fe80::1]:9001?password=roots+multicast+test&priority=3".to_string(),
            }]
        );
        // A password Go would escape: a space is `+`, `&` and `=` are percent
        // escapes, `-_.~` pass through.
        let mut weird = cfg("eth1", true, true);
        weird.password = b"a b&c=d~e_f.g-h".to_vec();
        m.set_interfaces(vec![weird]);
        let cmds = m.announce(now);
        let Command::Bind { uri, .. } = &cmds[1] else {
            panic!("no bind: {cmds:?}");
        };
        assert_eq!(
            uri,
            "tls://[fe80::1]:9001?password=a+b%26c%3Dd~e_f.g-h&priority=3"
        );

        // The Dial URI: the advertised port wins over the source port, the zone
        // rides in the host, and the query is key, password, priority
        // (`multicast.go:425`, `:443-451`).
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        let cmd = m
            .receive("eth0", src(5555), &peer_beacon(&PEER, 4242, 0, 5), now)
            .unwrap();
        assert_eq!(
            cmd,
            Command::Dial {
                uri: format!(
                    "tls://[fe80::2%eth0]:4242?key={}&password=roots+multicast+test&priority=3",
                    hex::encode(PEER)
                ),
                sintf: "eth0".to_string(),
                peer: PEER,
            }
        );
        // An empty password is still present, as Go writes it
        // (`url.Values.Encode` emits `password=`).
        let mut nopw = cfg("eth0", true, true);
        nopw.password = Vec::new();
        m.set_interfaces(vec![nopw]);
        let mut ours = peer_beacon(&PEER, 1, 0, 5);
        // Recompute the hash for the empty password so the beacon passes the
        // check and reaches the URI.
        let mut adv = Advertisement::decode(&ours).unwrap();
        adv.hash = membership_hash(b"", &PEER).to_vec();
        ours = adv.encode();
        let cmd = m.receive("eth0", src(1), &ours, now).unwrap();
        let Command::Dial { uri, .. } = cmd else {
            panic!("no dial: {cmd:?}");
        };
        assert_eq!(
            uri,
            format!(
                "tls://[fe80::2%eth0]:1?key={}&password=&priority=3",
                hex::encode(PEER)
            )
        );
    }

    #[test]
    fn multicast_skips_a_beacon_when_its_listener_is_not_up() {
        let t0 = Instant::now();
        let mut m = Multicast::new(OURS);

        // The bind asks for port 0, so the beacon can only carry the port the
        // client really got, which is why the first tick has no beacon.
        let mut c = cfg("eth0", true, true);
        c.port = 0;
        m.set_interfaces(vec![c]);

        assert_eq!(
            m.announce(t0),
            vec![Command::Bind {
                iface: "eth0".to_string(),
                link_local: ll(1),
                port: 0,
                uri: "tls://[fe80::1]:0?password=roots+multicast+test&priority=3".to_string(),
            }]
        );
        // Every later tick waits for the bind: no second bind, still no beacon.
        for step in 1..5 {
            assert!(
                m.announce(t0 + Duration::from_secs(step)).is_empty(),
                "step {step}"
            );
        }
        assert_eq!(m.tick_interval("eth0"), Some(Duration::ZERO));

        // Once the port is known the beacon carries it, not the asked-for one,
        // and it carries our key and our own membership hash.
        m.listener_up("eth0", 31337);
        let cmds = m.announce(t0 + Duration::from_secs(5));
        let Command::Beacon { iface, bytes } = &cmds[0] else {
            panic!("no beacon: {cmds:?}");
        };
        assert_eq!(iface, "eth0");
        let adv = Advertisement::decode(bytes).unwrap();
        assert_eq!(adv.port, 31337);
        assert_eq!(adv.major, PROTO_MAJOR);
        assert_eq!(adv.minor, PROTO_MINOR);
        assert_eq!(adv.pubkey, OURS);
        assert_eq!(adv.hash, membership_hash(PW, &OURS).to_vec());
        // And the gap starts growing from there.
        assert_eq!(m.tick_interval("eth0"), Some(Duration::from_secs(1)));
        // A listener on an interface we were never given is ignored.
        m.listener_up("eth9", 1);
        assert_eq!(m.tick_interval("eth9"), None);
    }

    #[test]
    fn multicast_stops_a_vanished_interfaces_listener() {
        let t0 = Instant::now();
        let mut m = Multicast::new(OURS);
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        m.listener_up("eth0", 9001);
        m.announce(t0);
        m.announce(t0 + Duration::from_secs(1));
        m.announce(t0 + Duration::from_secs(2));
        assert_eq!(m.tick_interval("eth0"), Some(Duration::from_secs(2)));

        // The interface left the scan: stop its listener, once.
        m.set_interfaces(Vec::new());
        assert_eq!(
            m.announce(t0 + Duration::from_secs(3)),
            vec![Command::Unbind {
                iface: "eth0".to_string()
            }]
        );
        assert!(m.announce(t0 + Duration::from_secs(4)).is_empty());
        assert!(m.announce(t0 + Duration::from_secs(5)).is_empty());

        // It comes back with a new address: bind again in the same tick, and
        // the ramp starts over because Go deleted the listener entry
        // (`multicast.go:264-267`).
        let mut back = cfg("eth0", true, true);
        back.link_local = ll(9);
        m.set_interfaces(vec![back]);
        assert_eq!(
            m.announce(t0 + Duration::from_secs(6)),
            vec![Command::Bind {
                iface: "eth0".to_string(),
                link_local: ll(9),
                port: 9001,
                uri: "tls://[fe80::9]:9001?password=roots+multicast+test&priority=3".to_string(),
            }]
        );
        m.listener_up("eth0", 9001);
        assert_eq!(m.tick_interval("eth0"), Some(Duration::ZERO));
        assert!(matches!(
            m.announce(t0 + Duration::from_secs(7))[0],
            Command::Beacon { .. }
        ));

        // Same interface, same address: no Unbind, no second Bind.
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        m.announce(t0 + Duration::from_secs(8));
        let cmds = m.announce(t0 + Duration::from_secs(9));
        assert!(!cmds.iter().any(|c| matches!(c, Command::Unbind { .. })));
        assert!(!cmds.iter().any(|c| matches!(c, Command::Bind { .. })));

        // A link-local that moved is the other half of Go's stop pass
        // (`multicast.go:277-300`): Unbind first, then Bind on the new one.
        let mut moved = cfg("eth0", true, true);
        moved.link_local = ll(8);
        m.set_interfaces(vec![moved]);
        assert_eq!(
            m.announce(t0 + Duration::from_secs(10)),
            vec![
                Command::Unbind {
                    iface: "eth0".to_string()
                },
                Command::Bind {
                    iface: "eth0".to_string(),
                    link_local: ll(8),
                    port: 9001,
                    uri: "tls://[fe80::8]:9001?password=roots+multicast+test&priority=3"
                        .to_string(),
                },
            ]
        );
    }

    #[test]
    fn multicast_never_dials_itself() {
        let now = Instant::now();
        let mut m = Multicast::new(OURS);
        m.set_interfaces(vec![cfg("eth0", true, true)]);
        let from = src(5000);

        // Our own key, with the hash that matches it, is refused
        // (`multicast.go:418-419`).
        assert!(
            m.receive("eth0", from, &peer_beacon(&OURS, 4242, 0, 5), now)
                .is_none()
        );
        // A zone we do not have is refused (`multicast.go:430`).
        assert!(
            m.receive("eth1", from, &peer_beacon(&PEER, 4242, 0, 5), now)
                .is_none()
        );
        // An interface that does not listen is refused.
        m.set_interfaces(vec![cfg("eth0", false, true), cfg("eth2", true, false)]);
        assert!(
            m.receive("eth2", from, &peer_beacon(&PEER, 4242, 0, 5), now)
                .is_none()
        );
        // Our own key again, now that eth0 is listen-only: still refused.
        assert!(
            m.receive("eth0", from, &peer_beacon(&OURS, 4242, 0, 5), now)
                .is_none()
        );
        m.set_interfaces(vec![cfg("eth0", true, true)]);

        // A beacon whose hash was made with another password is refused at the
        // comparison, not the decoder (`multicast.go:440-442`).
        let wrong_pw = Advertisement {
            major: 0,
            minor: 5,
            pubkey: PEER,
            port: 4242,
            hash: membership_hash(b"other password", &PEER).to_vec(),
        }
        .encode();
        assert!(Advertisement::decode(&wrong_pw).is_ok());
        assert!(m.receive("eth0", from, &wrong_pw, now).is_none());

        // A 32-byte hash decodes and then fails the same compare.
        let mut short = Advertisement::decode(&peer_beacon(&PEER, 4242, 0, 5)).unwrap();
        short.hash.truncate(32);
        let short = short.encode();
        assert!(Advertisement::decode(&short).is_ok());
        assert!(m.receive("eth0", from, &short, now).is_none());

        // So does the right 64 bytes with extra after them: Go's `bytes.Equal`
        // wants equal lengths, not a prefix (`multicast.go:440`).
        let mut long = Advertisement::decode(&peer_beacon(&PEER, 4242, 0, 5)).unwrap();
        long.hash.extend_from_slice(&[0u8; 4]);
        let long = long.encode();
        assert!(Advertisement::decode(&long).is_ok());
        assert!(m.receive("eth0", from, &long, now).is_none());

        // Two copies of one beacon give two dials: Go does not deduplicate and
        // the link manager refuses the second (`core/link.go:236-243`).
        let good = peer_beacon(&PEER, 4242, 0, 5);
        for _ in 0..2 {
            assert!(matches!(
                m.receive("eth0", from, &good, now),
                Some(Command::Dial { .. })
            ));
        }
    }
}
